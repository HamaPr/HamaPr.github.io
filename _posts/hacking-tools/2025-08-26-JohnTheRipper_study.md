---
layout: post
title: "John the Ripper 공부: 패스워드 크래킹 도구"
date: 2025-08-26 17:00:00 +0900
categories: [hacking-tools]
tags: [John the Ripper, Password Cracking, Hash, Linux, Hacking Tool]
description: "John the Ripper를 이용한 리눅스 Shadow 파일, Zip 파일 암호 크래킹 및 방어 대책"
---

## 1. 개요

**John the Ripper (JtR)**는 세계적으로 가장 유명한 패스워드 크래킹 도구 중 하나입니다.
유닉스/리눅스 계열의 패스워드 해시뿐만 아니라 Windows LM/NTLM, Kerberos, PDF, ZIP, Office 문서 등 수백 가지 포맷의 암호를 크랙할 수 있습니다. 주로 오프라인 상태에서 탈취한 해시 파일을 대상으로 사전 공격(Dictionary Attack)이나 무차별 대입 공격을 수행합니다.

---

## 2. 기본 사용법

```bash
john [옵션] [해시 파일]
```

### 주요 옵션
*   **--wordlist=[file]**: 사용할 사전 파일을 지정합니다. (필수적으로 사용됨)
*   **--format=[format]**: 해시 알고리즘을 수동으로 지정합니다. (보통 자동 탐지됨)
*   **--show**: 이미 크랙된 비밀번호를 보여줍니다. (`john.pot` 파일 참조)
*   **--rules**: 사전 파일의 단어들을 변형(대소문자 변경, 숫자 추가 등)하여 대입하는 규칙을 적용합니다.

---

## 3. 실습 1: 리눅스 Shadow 파일 크래킹

리눅스 시스템의 계정 정보는 `/etc/passwd`에, 실제 비밀번호 해시는 `/etc/shadow`에 저장됩니다. 이 두 파일을 결합하여 크래킹할 수 있습니다.

### 3.1. Unshadow
먼저 `unshadow` 유틸리티를 사용하여 두 파일을 하나의 포맷으로 합칩니다.
```bash
unshadow /etc/passwd /etc/shadow > passwords.txt
```

### 3.2. 크래킹 실행
합쳐진 파일을 대상으로 `rockyou.txt` 사전을 이용해 공격합니다.
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
```

![JohnShadow](/assets/images/hacking-tools/John_Shadow.png)

---

## 4. 실습 2: Zip 파일 암호 크래킹

암호가 걸린 Zip 파일도 JtR을 이용해 풀 수 있습니다. 먼저 Zip 파일을 JtR이 이해할 수 있는 해시 포맷으로 변환해야 합니다.

### 4.1. zip2john 변환
```bash
zip2john protected.zip > zip.hash
```

### 4.2. 크래킹 실행
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

이와 유사하게 `pdf2john`, `ssh2john` 등 다양한 변환 도구(`*2john`)가 제공되어 여러 파일 형식을 지원합니다.

---

## 5. 실습 3: MD5 해시 크래킹

`sqlmap` 등을 통해 획득한 단일 MD5 해시를 크래킹하는 예시입니다.

```bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![JohnMd5](/assets/images/hacking-tools/John_1.png)

---

## 6. 방어 대책

1.  **강력한 비밀번호 정책**: 사전 공격에 당하지 않도록 충분히 길고 복잡한(특수문자, 숫자, 대소문자 혼용) 비밀번호를 강제합니다.
2.  **솔트(Salt) 사용**: 비밀번호 해시 생성 시 랜덤한 솔트 값을 추가하여 레인보우 테이블 공격을 무력화합니다. (현대 리눅스는 기본적으로 적용됨)
3.  **느린 해시 알고리즘 사용**: bcrypt, Argon2, PBKDF2 등 연산 비용이 높은 알고리즘을 사용하여 크래킹 속도를 늦춥니다.
4.  **Shadow 파일 권한 관리**: `/etc/shadow` 파일은 `root` 사용자만 읽을 수 있도록 권한(`600` 또는 `640`)을 엄격히 관리해야 합니다.

<hr class="short-rule">
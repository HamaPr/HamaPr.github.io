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

## 2. 주요 기능 및 원리

Mimikatz는 윈도우의 **LSASS(Local Security Authority Subsystem Service)** 프로세스 메모리에 접근하여 인증 정보를 탈취합니다.

### 2.1. sekurlsa::logonpasswords
가장 대표적인 명령어로, 현재 로그인된 사용자들의 비밀번호(설정에 따라 평문 또는 해시)를 추출합니다. 윈도우는 사용자 편의(SSO 등)를 위해 메모리에 인증 정보를 일정 기간 보관하는데, Mimikatz는 이를 읽어냅니다.

### 2.2. Pass-the-Hash (PtH)
추출한 NTLM 해시를 이용하여 비밀번호를 몰라도 인증을 우회하고 다른 시스템에 접근할 수 있는 기법입니다.
```bash
sekurlsa::pth /user:Administrator /domain:target.local /ntlm:<NTLM_Hash>
```

### 2.3. Golden Ticket & Silver Ticket
케르베로스(Kerberos) 인증 시스템의 취약점을 이용하여, 도메인 컨트롤러의 모든 권한을 가진 티켓(Golden Ticket)을 위조할 수 있습니다. 이를 통해 도메인 내의 모든 자원에 접근할 수 있는 영구적인 권한을 획득하게 됩니다.

## 3. 실습 및 증거

아래는 침투에 성공한 시스템에서 Mimikatz를 실행하여 메모리에 저장된 자격 증명 정보를 덤프한 결과입니다.

![Mimikatz Credential Dump](/assets/images/att-ck/8.1.2.cre.png)

## 4. 보안 대책

1.  **LSASS 보호**: 윈도우 8.1/Server 2012 R2 이상에서는 'LSA 보호 모드'를 활성화하여 신뢰할 수 없는 프로세스가 LSASS 메모리에 접근하는 것을 차단할 수 있습니다.
2.  **Debug 권한 제거**: Mimikatz가 메모리에 접근하기 위해 필요한 `SeDebugPrivilege` 권한을 일반 사용자 및 관리자에게서 제거합니다(가능한 경우).
3.  **WDigest 비활성화**: 레지스트리 설정을 통해 평문 비밀번호가 메모리에 저장되지 않도록 WDigest 인증을 비활성화합니다.
4.  **EDR 솔루션 도입**: 엔드포인트 탐지 및 대응(EDR) 솔루션을 사용하여 메모리 해킹 시도를 실시간으로 탐지하고 차단합니다.

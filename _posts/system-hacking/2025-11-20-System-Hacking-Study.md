---
layout: post
title: "ATT&CK 기반 시스템 해킹 및 권한 상승 기술 분석"
date: 2025-11-20 11:00:00 +0900
categories: [system-hacking]
---

## 개요
본 포스트는 시스템 내부 침투 후 권한 상승(Privilege Escalation) 및 지속성 확보(Persistence)를 위해 사용된 주요 시스템 해킹 기술을 정리합니다.

## 권한 상승 기술 (Privilege Escalation)

### 1. Sudo Misconfiguration
*   **설명:** `sudo` 설정(`/etc/sudoers`)의 미흡함을 악용하여 root 권한을 획득하는 기법입니다.
*   **예시:** `NOPASSWD` 옵션이 설정된 `find`, `vim`, `less` 등의 명령어를 통해 셸을 실행할 수 있습니다. (예: `sudo find . -exec /bin/sh \; -quit`)
*   **도구:** `GTFOBins` (바이너리 악용 방법 참조)

### 2. SUID Binary Exploitation
*   **설명:** SUID(Set User ID) 비트가 설정된 바이너리의 취약점(버퍼 오버플로우 등)을 공격하여 해당 파일 소유자(주로 root)의 권한을 획득합니다.
*   **분석:** `gdb` 등을 이용해 바이너리를 분석하고 오프셋을 계산하여 익스플로잇을 수행합니다.

### 3. Kernel Exploitation (OverlayFS)
*   **설명:** 운영체제 커널의 취약점(예: CVE-2021-3493)을 이용하여 일반 사용자 권한에서 root 권한으로 상승합니다.
*   **도구:** `searchsploit` (취약점 검색), `gcc` (익스플로잇 컴파일)

### 4. Docker Container Escape
*   **설명:** Docker 컨테이너 내부에서 호스트 시스템으로 탈출하여 권한을 획득하는 기법입니다.
*   **원인:** 사용자가 `docker` 그룹에 포함되어 있거나, 컨테이너가 특권 모드(`--privileged`)로 실행될 때 발생하기 쉽습니다.
*   **기법:** Docker 소켓을 마운트하여 호스트의 파일시스템에 접근하거나 새로운 컨테이너를 생성하여 호스트를 제어합니다.

## 지속성 확보 (Persistence)

### 1. Cron Job
*   **설명:** 리눅스의 작업 스케줄러인 `cron`에 악성 스크립트 실행 명령을 등록하여, 시스템 재부팅 후에도 백도어가 실행되도록 설정합니다.

### 2. SSH Key Injection
*   **설명:** 공격자의 SSH 공개 키를 피해자 계정의 `~/.ssh/authorized_keys` 파일에 추가하여, 언제든지 비밀번호 없이 SSH로 접속할 수 있도록 합니다.

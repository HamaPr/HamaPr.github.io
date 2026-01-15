---
layout: post
title: "DIRB & Gobuster"
date: 2025-08-25 17:00:00 +0900
categories: [hacking-tools]
tags: [Dirb, Gobuster, Web Scanning, Directory Brute Force, Hacking Tool]
description: "웹 서버의 숨겨진 디렉터리와 파일을 찾아내는 Dirb와 Gobuster 사용법 및 비교"
---

## 1. 개요

**DIRB**와 **Gobuster**는 웹 서버에 숨겨진 디렉터리와 파일을 찾기 위해 사전(Wordlist)을 기반으로 무차별 대입 공격(Brute-Force)을 수행하는 도구이다.
웹 사이트에는 관리자 페이지(`/admin`), 백업 파일(`/backup.zip`), 설정 파일(`/config.php`) 등 링크로 연결되지 않은 중요한 리소스가 숨겨져 있을 수 있으며, 이를 찾아내는 것은 공격 표면을 확장하는 핵심 정찰 활동이다.
본 글에서는 두 도구의 차이점을 비교하고, 현재 더 널리 사용되는 Gobuster를 중심으로 디렉터리 스캐닝 실습을 진행한다.

---

## 2. 도구 비교

| 특징 | DIRB | Gobuster |
| :--- | :--- | :--- |
| **언어** | C | Go |
| **속도** | 상대적으로 느림 (싱글 스레드 기반) | **매우 빠름** (멀티스레드 최적화) |
| **기능** | 디렉터리 스캔 특화 | 디렉터리, DNS, VHost 등 다양한 모드 지원 |
| **재귀 스캔** | 기본 지원 | 별도 옵션 필요 |

DIRB는 설치가 간편하고 사용법이 직관적이지만, 대규모 스캔 시 속도 문제로 인해 최근에는 압도적으로 빠른 **Gobuster**가 더 많이 사용되는 추세이다.

---

## 3. Gobuster 사용법

Gobuster는 여러 모드를 지원하지만, 웹 디렉터리 스캔에는 `dir` 모드를 사용한다.

```bash
gobuster dir -u [대상 URL] -w [사전 파일] [옵션]
```

### 주요 옵션
*   **-u (url)**: 대상 웹 사이트 주소
*   **-w (wordlist)**: 사용할 사전 파일 (예: `/usr/share/wordlists/dirb/common.txt`)
*   **-x (extensions)**: 찾을 파일 확장자 지정 (예: `php,txt,zip`)
*   **-t (threads)**: 스레드 수 (기본값: 10, 속도를 높이려면 50~100 권장)
*   **-k**: SSL 인증서 검증 무시 (사설 인증서 사용 시 유용)
*   **-s (status codes)**: 정상으로 간주할 상태 코드 지정

---

## 4. 공격 실습: Directory Brute-Force

DVWA 서버를 대상으로 숨겨진 `php`, `txt` 파일을 탐색한다.

```bash
gobuster dir -u http://192.9.200.11/dvwa/ -w /usr/share/wordlists/dirb/common.txt -x php,txt
```

![GobusterScan](/assets/images/hacking-tools/Gobuster_1.png)

### 결과 분석
*   **Status 200 (OK)**: 정상적으로 접근 가능한 페이지 (`/login.php`, `/index.php` 등)
*   **Status 301 (Redirect)**: 다른 경로로 리다이렉트되는 디렉터리 (`/config`, `/docs`)
*   **Status 403 (Forbidden)**: 접근이 거부된 경로. 중요한 파일이 존재할 가능성이 높으므로 우회 방법을 고민해야 한다.

![GobusterScan2](/assets/images/hacking-tools/Gobuster_Ext.png)

---

## 5. DIRB 사용법

참고로 DIRB는 별도의 모드 지정 없이 바로 URL과 사전 파일을 입력하여 사용한다. 기본적으로 재귀 스캔(하위 디렉터리까지 탐색)을 수행한다.

```bash
dirb http://192.9.200.11/ /usr/share/wordlists/dirb/common.txt
```

---

## 6. 보안 대책

*   **불필요한 파일 삭제**: 개발용 테스트 파일, 백업 파일(`.bak`, `.old`), 임시 파일 등을 운영 서버 배포 전에 반드시 제거한다.
*   **디렉터리 리스팅 비활성화**: 웹 서버 설정에서 `Options -Indexes` (Apache) 등을 적용하여 파일 목록이 노출되지 않도록 한다.
*   **WAF 적용**: 반복적인 404 오류를 발생시키는 비정상적인 스캔 패턴을 탐지하고 해당 IP를 차단한다.
*   **접근 제어**: 관리자 페이지와 같은 중요 경로는 IP 기반 접근 제어(ACL)를 설정하여 외부 접근을 원천 차단한다.

<hr class="short-rule">
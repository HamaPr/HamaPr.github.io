---
layout: post
title: "Dirb, Gobuster 공부: 웹 디렉터리 스캐닝 도구"
date: 2025-08-25 17:00:00 +0900
categories: [hacking-tools]
tags: [Dirb, Gobuster, Web Scanning, Directory Brute Force, Hacking Tool]
description: "웹 서버의 숨겨진 디렉터리와 파일을 찾아내는 Dirb와 Gobuster 사용법 및 비교"
---

## 1. 개요

**Dirb**와 **Gobuster**는 웹 서버에 숨겨진 디렉터리와 파일을 찾기 위해 사전(Wordlist)을 기반으로 무차별 대입 공격(Brute-force)을 수행하는 도구입니다.
웹 사이트에는 링크로 연결되지 않은 관리자 페이지(`/admin`), 백업 파일(`/backup.zip`), 설정 파일(`/config.php`) 등이 존재할 수 있으며, 이를 찾아내는 것은 공격 표면을 넓히는 중요한 정찰 단계입니다.

---

## 2. 도구 비교

| 특징 | Dirb | Gobuster |
| :--- | :--- | :--- |
| **언어** | C | Go |
| **속도** | 상대적으로 느림 | **매우 빠름** (멀티스레드 최적화) |
| **기능** | 디렉터리 스캔 위주 | 디렉터리, DNS, VHost 등 다양한 모드 지원 |
| **재귀 스캔** | 기본 지원 | 별도 옵션 필요 |

최근에는 압도적인 속도 차이로 인해 **Gobuster**가 더 많이 사용되는 추세입니다.

---

## 3. Gobuster 사용법

Gobuster는 여러 모드를 지원하지만, 가장 많이 쓰이는 것은 디렉터리 스캔(`dir`) 모드입니다.

```bash
gobuster dir -u [대상 URL] -w [사전 파일] [옵션]
```

### 주요 옵션
*   **-u (url)**: 대상 웹 사이트 주소
*   **-w (wordlist)**: 사용할 사전 파일 경로 (예: `/usr/share/wordlists/dirb/common.txt`)
*   **-x (extensions)**: 찾을 파일 확장자 지정 (예: `php,txt,zip`)
*   **-s (status codes)**: 성공으로 간주할 HTTP 상태 코드 (예: `200,301,403`)
*   **-t (threads)**: 스레드 수 (기본값: 10, 속도 조절용)
*   **-k**: SSL 인증서 검증 무시

---

## 4. 실습: 숨겨진 파일 찾기

DVWA 서버를 대상으로 `php` 파일과 `txt` 파일을 포함하여 스캔을 수행합니다.

```bash
gobuster dir -u http://192.9.200.11/dvwa/ -w /usr/share/wordlists/dirb/common.txt -x php,txt
```

![GobusterScan](/assets/images/hacking-tools/Gobuster_1.png)

### 결과 분석
*   **Status 200 (OK)**: 정상적으로 접근 가능한 페이지입니다. (`/login.php`, `/index.php`)
*   **Status 301 (Redirect)**: 다른 경로로 리다이렉트되는 디렉터리입니다. (`/config`, `/docs`)
*   **Status 403 (Forbidden)**: 접근이 거부된 경로입니다. 때로는 중요한 파일이 있어 접근을 막아둔 것일 수 있으므로 우회 방법을 고민해봐야 합니다.

![GobusterScan2](/assets/images/hacking-tools/Gobuster_Ext.png)

---

## 5. Dirb 사용법 (참고)

Dirb는 사용법이 매우 간단하며, 기본적으로 재귀 스캔(하위 디렉터리까지 탐색)을 수행합니다.

```bash
dirb http://192.9.200.11/ /usr/share/wordlists/dirb/common.txt
```

---

## 6. 방어 대책

1.  **불필요한 파일 삭제**: 개발 과정에서 생성된 테스트 파일, 백업 파일(`.bak`, `.old`), 임시 파일 등을 운영 서버에서 반드시 삭제합니다.
2.  **디렉터리 리스팅 비활성화**: 웹 서버 설정에서 `Options -Indexes` (Apache) 등을 설정하여 파일 목록이 노출되지 않도록 합니다.
3.  **접근 제어**: 관리자 페이지나 중요 디렉터리는 IP 기반의 접근 제어(ACL)를 설정하여 외부 접근을 차단합니다.
4.  **WAF 사용**: 반복적인 404 오류를 발생시키는 스캔 도구의 패턴을 탐지하고 차단합니다.

<hr class="short-rule">
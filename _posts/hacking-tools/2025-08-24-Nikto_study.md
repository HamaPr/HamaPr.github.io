---
layout: post
title: "Nikto 공부: 웹 서버 취약점 스캐너"
date: 2025-08-24 17:00:00 +0900
categories: [hacking-tools]
tags: [Nikto, Web Scanning, Vulnerability Scanner, Hacking Tool]
description: "Nikto를 이용한 웹 서버 설정 오류 진단, SSL 스캔, WAF 우회 방법"
---

## 1. Nikto 개요

**Nikto**는 웹 서버의 다양한 보안 취약점을 자동으로 점검해주는 오픈소스 스캐너입니다.
6,700개 이상의 잠재적인 위험 파일/CGI, 1,250개 이상의 구버전 서버 소프트웨어, 270개 이상의 특정 버전 문제를 검사합니다. 또한 서버 설정 오류(Misconfiguration)나 기본 파일 방치 등을 찾아내는 데 탁월합니다.

---

## 2. 기본 사용법

```bash
nikto -h [Target IP or Domain] [옵션]
```

### 주요 옵션
*   **-h (host)**: 대상 호스트를 지정합니다.
*   **-p (port)**: 포트를 지정합니다. (기본: 80)
*   **-ssl**: HTTPS(SSL) 프로토콜을 강제로 사용하여 스캔합니다.
*   **-T (Tuning)**: 스캔할 취약점 유형을 선택합니다. (예: `x`=전체, `2`=설정오류, `9`=SQL Injection 등)
*   **-o (output)**: 결과를 파일로 저장합니다. (`-o result.html` 처럼 확장자에 따라 포맷 자동 결정)

---

## 3. 실습 1: 기본 스캔 및 결과 분석

대상 서버(`192.9.200.11`)의 80번 포트를 스캔합니다.

```bash
nikto -h 192.9.200.11 -p 80
```

![Nikto](/assets/images/hacking-tools/Nikto_1.png)

### 결과 해석
*   **Server**: `Apache/2.4.58` - 웹 서버의 종류와 버전을 식별했습니다. 구버전이라면 CVE를 검색해볼 수 있습니다.
*   **X-Frame-Options**: 이 헤더가 없으면 클릭재킹(Clickjacking) 공격에 취약할 수 있습니다.
*   **X-Content-Type-Options**: 이 헤더가 없으면 MIME Sniffing 공격에 노출될 수 있습니다.
*   **Allowed HTTP Methods**: `PUT`, `DELETE` 등의 메소드가 허용되어 있다면 파일 업로드나 삭제가 가능할 수 있습니다.
*   **/icons/README**: 기본 설치 파일이 남아있어 서버 정보를 유추하는 데 사용될 수 있습니다.

---

## 4. 실습 2: SSL/TLS 스캔

HTTPS를 사용하는 사이트는 `-ssl` 옵션을 추가하여 인증서 정보와 암호화 설정 취약점(Heartbleed 등)을 점검할 수 있습니다.

```bash
nikto -h 192.9.200.11 -p 443 -ssl
```

![Nikto](/assets/images/hacking-tools/Nikto_SSL.png)

---

## 5. 심화: IDS/WAF 우회 (Evasion)

방화벽이나 IDS(침입 탐지 시스템)가 Nikto의 스캔 패턴을 차단할 경우, `-evasion` 옵션을 사용하여 패킷을 변조할 수 있습니다.

```bash
nikto -h 192.9.200.11 -evasion 1
```

*   **1 (Random URI encoding)**: URI를 랜덤하게 인코딩하여 전송 (예: `/test` -> `/%74est`)
*   **2 (Self-reference /./)**: 경로에 `/./`를 삽입 (예: `/./test`)
*   **A (Fake parameter)**: 의미 없는 파라미터 추가
*   **B (Fake headers)**: 의미 없는 헤더 추가

이 옵션들을 조합하여 보안 장비의 탐지를 우회하고 스캔을 시도할 수 있습니다.

---

## 6. 방어 대책

1.  **불필요한 파일 제거**: 웹 서버 설치 시 기본으로 생성되는 매뉴얼, 예제 파일, 기본 스크립트 등을 모두 삭제합니다.
2.  **보안 헤더 적용**: `X-Frame-Options`, `X-XSS-Protection`, `Content-Security-Policy` 등 보안 헤더를 설정하여 브라우저 보안 기능을 활성화합니다.
3.  **배너 그래빙 방지**: `ServerTokens Prod` (Apache) 등의 설정으로 서버 버전 정보가 응답 헤더에 노출되지 않도록 합니다.
4.  **HTTP 메소드 제한**: `GET`, `POST` 외에 불필요한 `PUT`, `DELETE`, `TRACE` 등의 메소드를 비활성화합니다.

<hr class="short-rule">
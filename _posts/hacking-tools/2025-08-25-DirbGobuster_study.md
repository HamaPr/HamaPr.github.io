---
layout: post
title: "Dirb, Gobuster 공부"
date: 2025-08-25 17:00:00 +0900
categories: [해킹 툴]
---

### 1. 개요

Dirb와 Gobuster는 웹 서버에 숨겨진 디렉터리와 파일을 찾기 위해 사전(wordlist)을 기반으로 무차별 대입 공격을 수행하는 도구이다.

웹 사이트의 모든 페이지가 링크로 연결되어 있는 것은 아니다. 개발 과정에서 남겨진 테스트 페이지 · 관리자 로그인 페이지 · 설정 파일 백업 등은 외부에 노출되지 않지만 서버에는 존재하는 경우가 많다. 이런 숨겨진 경로를 찾아내는 것은 공격 표면을 넓히는 중요한 정찰 단계이다.

---

### 2. 기본 사용법

두 도구 모두 CLI(명령줄 인터페이스) 기반으로 동작하며 기본적인 사용법은 유사하다. 최근에는 Go 언어로 작성되어 더 빠른 성능을 보이는 Gobuster가 더 많이 사용되는 추세이다.

*   **Dirb:**
    ```bash
    # dirb <대상 URL> [사용할 사전 파일 경로]
    dirb http://192.9.200.11/
    ```
*   **Gobuster:**
    ```bash
    # gobuster dir -u <대상 URL> -w <사전 파일 경로>
    gobuster dir -u http://192.9.200.11/ -w /usr/share/wordlists/dirb/common.txt
    ```

---

### 3. 사용 예시 (Gobuster)

DVWA 서버를 대상으로 `common.txt` 사전을 이용하여 디렉터리 및 파일 스캔을 수행했다.

```bash
gobuster dir -u http://192.9.200.11/dvwa/ -w /usr/share/wordlists/dirb/common.txt
```
   ![GobusterScan](/assets/images/Gobuster_1.png)

***결과 분석***

스캔 결과 `Status: 200` (OK), `Status: 301` (Redirect) 등 정상적으로 접근 가능한 여러 경로를 발견했다.
*   `/login.php` (Status: 200): 로그인 페이지
*   `/phpinfo.php` (Status: 200): 서버의 상세 정보가 담긴 페이지
*   `/config` (Status: 301): 설정 관련 디렉터리
*   `/docs` (Status: 301): 문서 디렉터리

이처럼 링크만으로는 알 수 없었던 `phpinfo.php`나 `config` 디렉터리 같은 민감할 수 있는 경로를 찾아내어 다음 공격 단계를 계획하는 데 활용할 수 있다.

---

### 4. 주요 옵션 (Gobuster)

*   **`-x [extensions]`**: 특정 확장자를 가진 파일만 검색한다. (예: `-x php,txt,html`)
*   **`-s [status codes]`**: 성공으로 간주할 HTTP 상태 코드를 지정한다. (예: `-s 200,204,301`)
*   **`-t [threads]`**: 스캔에 사용할 스레드 수를 지정하여 속도를 조절한다.

<hr class="short-rule">
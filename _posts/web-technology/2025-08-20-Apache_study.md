---
layout: post
title: "Apache 공부"
date: 2025-08-20 17:00:00 +0900
categories: [web-technology]
---

## 1. 개요

Apache HTTP Server는 세계적으로 가장 널리 쓰이는 웹 서버 소프트웨어 중 하나이다. APM 스택에서 'A'를 담당하며 사용자의 HTTP 요청을 받아 HTML · CSS · 이미지 같은 정적 파일을 제공하거나 PHP 스크립트를 실행하여 동적 콘텐츠를 생성하는 역할을 한다.

---

## 2. 주요 디렉터리 및 파일 (Ubuntu 기준)

*   **/etc/apache2/**: Apache의 주 설정 파일들이 위치하는 디렉터리이다.
*   **/etc/apache2/apache2.conf**: 메인 설정 파일. 전역 설정을 포함한다.
*   **/etc/apache2/sites-available/**: 사용 가능한 가상 호스트(웹사이트) 설정 파일들이 저장된다.
*   **/var/www/html/**: 웹 콘텐츠가 위치하는 기본 경로(Document Root)이다. DVWA 같은 웹 애플리케이션 파일은 이곳에 위치한다.
*   **/var/log/apache2/**: 로그 파일이 저장되는 곳. `access.log`는 접속 기록 `error.log`는 오류 기록을 담는다.

---

## 3. 주요 설정 지시어

Apache의 동작은 설정 파일 `.conf` 안의 지시어(Directives)를 통해 제어된다.

#### ***DocumentRoot***
웹사이트의 최상위 디렉터리를 지정한다. Apache는 이 경로를 기준으로 사용자가 요청한 파일을 찾는다.
```apache
# /etc/apache2/sites-available/000-default.conf
DocumentRoot /var/www/html
```

#### ***Options Indexes***
특정 디렉터리에 `index.html`이나 `index.php` 같은 인덱스 파일이 없을 때 해당 디렉터리의 파일 목록을 보여줄지 여부를 결정한다. 이 기능이 활성화되어 있으면 의도치 않은 파일이 노출될 수 있다.

*   **`Options +Indexes` · `Options Indexes`**: 디렉터리 리스팅 허용
*   **`Options -Indexes`**: 디렉터리 리스팅 차단 (보안 권장 설정)

   ![ApacheList](/assets/images/web-technology/Apache_1.png)

#### ***ServerTokens / ServerSignature***
서버 오류 페이지나 HTTP 응답 헤더에 Apache 버전과 같은 상세 정보를 얼마나 노출할지 결정한다. 보안을 위해 최소한의 정보만 보여주는 것이 좋다.

*   **`ServerTokens Prod`**: 서버 정보를 `Apache`로만 표시한다.
*   **`ServerSignature Off`**: 오류 페이지 하단에 서버 정보 표시를 끈다.

---

## 4. 보안 관점의 로그 분석

Apache 로그 파일, 특히 접근 로그 **`access.log`** 는 정상적인 서비스 통계뿐만 아니라 외부의 공격 시도를 탐지하고 분석하는 데 매우 중요한 정보를 담고 있다. 공격자가 시스템을 공격할 때 남기는 흔적을 로그에서 식별하는 것은 보안 분석의 기본이다.

#### ***1. 로그 파일의 위치 및 기본 형식***
*   ***위치:*** `/var/log/apache2/` (Ubuntu 기준)
*   ***파일:***
    *   **`access.log`**: 모든 웹 요청 기록 (누가 · 언제 · 무엇을 요청했는지)
    *   **`error.log`**: 서버 오류 및 경고 기록
*   ***기본 형식 (Common Log Format):***

    `[Client IP] - - [Request Time] "GET /path HTTP/1.1" [Status Code] [Response Size]`

#### **2. 사용 예시: 공격 흔적 탐지**
다른 스터디에서 수행했던 공격들이 `access.log`에 어떻게 기록되는지 `grep` 명령어를 통해 확인할 수 있다.

*   ***SQL Injection (Sqlmap) 공격 탐지:***
    **`sqlmap`**과 같은 자동화 도구는 다수의 비정상적인 URL 파라미터를 생성한다. **`UNION`**, **`SELECT`**와 같은 SQL 키워드를 로그 파일에서 검색하여 공격 시도를 식별할 수 있다.
    ```bash
    # /var/log/apache2 디렉터리에서 access.log 파일을 대상으로 'UNION' 문자열 검색
    grep "UNION" /var/log/apache2/access.log
    ```
    ```log
    192.9.200.12 - - [20/Aug/2025:21:15:30 +0900] "GET /dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x...%29--%20-&Submit=Submit HTTP/1.1" 200 1961 "-" "sqlmap/1.9.8"
    ```
    로그에는 URL 인코딩된 형태(`%20UNION%20SELECT...`)로 공격 페이로드가 기록되어 공격이 발생했다는 명백한 증거가 된다.

*   ***Command Injection 공격 탐지:***
    명령어 인젝션 공격에 사용되는 쉘 메타 문자 **`;`** · **`|`** · **`&&`** · **`ls`** · **`whoami`** 같은 명령어 흔적을 검색하여 공격을 탐지할 수 있다.
    ```bash
    # URL 인코딩된 세미콜론(%3B)과 ls 명령어를 함께 검색
    grep "%3B%20ls" /var/log/apache2/access.log
    ```
    ```log
    192.9.200.12 - - [20/Aug/2025:21:40:11 +0900] "GET /dvwa/vulnerabilities/exec/?ip=127.0.0.1%3B%20ls+-l HTTP/1.1" 200 1950 "http://192.9.200.11/dvwa/vulnerabilities/exec/" "Mozilla/5.0..."
    ```

    로그를 통해 공격자가 어떤 IP에서 어떤 명령어를 주입하려고 시도했는지 파악할 수 있다. 이러한 로그는 침해 사고 분석 시 공격자의 행위를 재구성하는 데 결정적인 역할을 한다.

---

## 5. 가상 호스트 (Virtual Host) 설정

하나의 서버에서 여러 도메인/웹사이트를 운영하는 기능.

### 가상 호스트 유형
| 유형 | 기준 | 예시 |
|------|------|------|
| Name-based | 도메인 이름 | www.site1.com, www.site2.com |
| IP-based | IP 주소 | 10.0.0.11, 10.0.0.12 |
| Port-based | 포트 번호 | :80, :8080 |

### Name-based 가상 호스트 설정

#### Ubuntu (/etc/apache2/sites-available/)
```apache
# /etc/apache2/sites-available/site1.conf
<VirtualHost *:80>
    ServerName www.site1.com
    ServerAlias site1.com
    DocumentRoot /var/www/site1
    ErrorLog ${APACHE_LOG_DIR}/site1-error.log
    CustomLog ${APACHE_LOG_DIR}/site1-access.log combined
    
    <Directory /var/www/site1>
        Options -Indexes
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

#### CentOS/Rocky (/etc/httpd/conf.d/)
```apache
# /etc/httpd/conf.d/site1.conf
<VirtualHost *:80>
    ServerName www.site1.com
    DocumentRoot /var/www/site1
    ErrorLog logs/site1-error_log
    CustomLog logs/site1-access_log combined
</VirtualHost>
```

### 가상 호스트 활성화 (Ubuntu)
```bash
# 사이트 활성화
a2ensite site1.conf

# 설정 테스트
apachectl configtest

# Apache 재시작
systemctl reload apache2
```

### 테스트 (hosts 파일 수정)
```
# /etc/hosts (Linux) 또는 C:\Windows\System32\drivers\etc\hosts (Windows)
10.0.0.11  www.site1.com
10.0.0.11  www.site2.com
```

### HTTPS 가상 호스트
```apache
<VirtualHost *:443>
    ServerName www.site1.com
    DocumentRoot /var/www/site1
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/site1.crt
    SSLCertificateKeyFile /etc/ssl/private/site1.key
</VirtualHost>
```

---

## 6. 접근 제어 설정

Apache는 특정 디렉터리나 파일에 대한 접근을 IP 주소나 사용자 인증을 통해 제한할 수 있습니다.

### IP 기반 접근 제어

특정 IP만 허용하거나 차단하는 설정입니다.

#### Apache 2.2 방식 (Order 지시어)
```apache
# /etc/httpd/conf.d/vir.conf (CentOS/Rocky)
<Directory "/var/www/blog">
    Order deny,allow
    Deny from all
    Allow from 10.0.0.101
    Allow from 192.168.1.0/24
</Directory>
```

#### Apache 2.4 방식 (Require 지시어)
```apache
<Directory "/var/www/blog">
    <RequireAll>
        Require all denied
        Require ip 10.0.0.101
        Require ip 192.168.1.0/24
    </RequireAll>
</Directory>
```

### 사용자 인증 기반 접근 제어 (.htaccess)

사용자 ID/PW를 통해 접근을 제한하는 방법입니다.

#### 1. 패스워드 파일 생성
```bash
# 인증 파일 디렉터리 생성
mkdir /auth

# 첫 번째 사용자 생성 (-c: 파일 생성)
htpasswd -c /auth/.user admin

# 추가 사용자 등록 (-c 옵션 없이)
htpasswd /auth/.user user1
```

#### 2. httpd.conf 또는 가상호스트 설정
```apache
<Directory "/var/www/intra">
    AllowOverride AuthConfig
</Directory>
```

#### 3. .htaccess 파일 생성
```apache
# /var/www/intra/.htaccess
AuthName "Restricted Area"
AuthType Basic
AuthUserFile /auth/.user
Require user admin user1
```

#### 4. 접속 테스트
브라우저에서 해당 URL 접속 시 인증 팝업이 표시됩니다.

### 실습 예시: 다중 가상호스트 + 접근제어

```apache
# /etc/httpd/conf.d/vir.conf
NameVirtualHost *:80

# 메인 사이트 (공개)
<VirtualHost *:80>
    ServerName www.hamap.local
    ServerAlias hamap.local
    DocumentRoot /var/www/html
</VirtualHost>

# 블로그 (IP 제한)
<Directory "/var/www/blog">
    Order deny,allow
    Deny from all
    Allow from 10.0.0.101
</Directory>
<VirtualHost *:80>
    ServerName blog.hamap.local
    DocumentRoot /var/www/blog
</VirtualHost>

# 인트라넷 (사용자 인증)
<Directory "/var/www/intra">
    AllowOverride AuthConfig
</Directory>
<VirtualHost *:80>
    ServerName intra.hamap.local
    DocumentRoot /var/www/intra
</VirtualHost>
```

<hr class="short-rule">
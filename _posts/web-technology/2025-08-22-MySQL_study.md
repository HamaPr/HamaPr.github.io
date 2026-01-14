---
layout: post
title: "MySQL 공부: 데이터베이스 관리와 보안"
date: 2025-08-22 17:00:00 +0900
categories: [web-technology]
tags: [MySQL, Database, SQL Injection, Security, RDBMS]
description: "MySQL 기본 명령어, 사용자 권한 관리, 그리고 SQL Injection 방어를 위한 Prepared Statement"
---

## 1. 개요

**MySQL**은 전 세계적으로 가장 널리 사용되는 오픈소스 관계형 데이터베이스 관리 시스템(RDBMS)입니다.
웹 애플리케이션의 핵심 데이터를 저장하므로, MySQL의 보안 설정과 올바른 쿼리 작성은 정보 유출을 막는 최후의 보루와 같습니다.

---

## 2. 기본 명령어 및 구조

### 2.1. 접속 및 확인
```bash
# root 계정으로 접속
sudo mysql -u root -p
```

*   `SHOW DATABASES;`: 데이터베이스 목록 확인
*   `USE [db_name];`: 사용할 DB 선택
*   `SHOW TABLES;`: 테이블 목록 확인
*   `DESC [table_name];`: 테이블 구조(스키마) 확인

### 2.2. 데이터 조회 (DVWA 예시)
DVWA의 `users` 테이블 구조를 파악하고 데이터를 조회해 봅니다.

```sql
USE dvwa;
SELECT user, password FROM users;
```
결과로 사용자명과 해시된 비밀번호가 출력됩니다. 공격자가 SQL Injection을 통해 노리는 것이 바로 이러한 데이터입니다.

![MysqlDatabase](/assets/images/web-technology/Mysql_1.png)
![MysqlDatabase](/assets/images/web-technology/Mysql_Select.png)

---

## 3. 사용자 및 권한 관리 (Security)

보안을 위해 애플리케이션은 `root` 계정을 사용해서는 안 되며, 최소한의 권한만 가진 전용 계정을 사용해야 합니다.

### 3.1. 사용자 생성
```sql
-- 로컬에서만 접속 가능한 사용자 생성
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
```

### 3.2. 권한 부여 (Least Privilege)
`dvwa` 데이터베이스에 대해서만 `SELECT`, `INSERT`, `UPDATE` 권한을 부여합니다. (`DROP`이나 `GRANT` 권한은 제외)
```sql
GRANT SELECT, INSERT, UPDATE ON dvwa.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
```

---

## 4. SQL Injection 방어: Prepared Statement

SQL Injection은 사용자 입력값이 쿼리의 일부분으로 해석되어 발생합니다. 이를 막기 위해 **Prepared Statement(준비된 구문)**를 사용해야 합니다.

### 취약한 코드 (PHP)
```php
$id = $_GET['id'];
// 입력값이 쿼리에 그대로 연결됨 -> 위험!
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);
```

### 안전한 코드 (PHP)
```php
$id = $_GET['id'];
// 1. 쿼리 구조를 미리 정의 (?는 플레이스홀더)
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
// 2. 입력값을 별도로 바인딩 (i는 integer 타입)
$stmt->bind_param("i", $id);
// 3. 쿼리 실행
$stmt->execute();
$result = $stmt->get_result();
```
이렇게 하면 입력값은 오직 '데이터'로만 처리되어 SQL 문법에 영향을 줄 수 없습니다.

---

## 5. 보안 설정 (Hardening)

1.  **원격 접속 제한**: `/etc/mysql/mysql.conf.d/mysqld.cnf` 파일에서 `bind-address = 127.0.0.1`로 설정하여 외부 접속을 차단합니다.
2.  **익명 사용자 제거**: `mysql_secure_installation` 스크립트를 실행하여 익명 사용자, 테스트 DB 등을 삭제합니다.
3.  **파일 권한**: DB 데이터 파일이 저장된 디렉터리(`/var/lib/mysql`)의 권한을 엄격하게 관리합니다.

<hr class="short-rule">
---
layout: post
title: "MySQL 공부"
date: 2025-08-22 17:00:00 +0900
categories: [웹 기술]
---

### 1. MySQL 개요

MySQL은 세계에서 가장 많이 사용되는 오픈소스 관계형 데이터베이스 관리 시스템(RDBMS)이다. APM 스택의 'M'을 담당하며 웹 애플리케이션의 사용자 정보 · 게시글 · 설정 등 대부분의 데이터를 저장하고 관리하는 역할을 한다.

DVWA를 설치한 Ubuntu 환경에서는 MySQL과 호환되는 MariaDB가 기본적으로 설치된다. 사용법과 명령어는 대부분 동일하다.

---

### 2. 기본 접속 및 명령어

#### ***터미널 접속***
MySQL 서버에 관리자(root) 권한으로 접속한다. `-u`는 사용자 `-p`는 비밀번호 입력을 의미한다.
```bash
sudo mysql -u root -p
```

#### ***주요 명령어***
*   **`SHOW DATABASES;`**: 현재 서버의 모든 데이터베이스 목록을 보여준다.
*   **`USE [database_name];`**: 사용할 데이터베이스를 선택한다.
*   **`SHOW TABLES;`**: 현재 선택된 데이터베이스의 모든 테이블 목록을 보여준다.
*   **`DESC [table_name];`**: 특정 테이블의 구조(컬럼, 데이터 타입 등)를 보여준다.
*   **`SELECT * FROM [table_name];`**: 특정 테이블의 모든 데이터를 조회한다.

---

### 3. DVWA 데이터베이스 구조 확인

DVWA의 데이터베이스 구조를 직접 확인하는 과정은 SQL Injection과 같은 공격을 이해하는 데 도움이 된다.

   ![MysqlDatabase](/assets/images/Mysql_1.png)

1.  ***데이터베이스 선택:***
    `USE dvwa;`

2.  ***테이블 목록 확인:***
    `SHOW TABLES;`
    (결과로 `guestbook`, `users` 테이블 등이 나타난다.)

3.  ***`users` 테이블 구조 확인:***
    `DESC users;`
    (결과로 `user_id` · `user` · `password` 등 컬럼 정보가 나타난다.)

4.  ***`users` 테이블 데이터 조회:***
    `SELECT user, password FROM users;`
    (DVWA에 저장된 모든 사용자의 이름과 MD5로 해시된 비밀번호가 출력된다.)

---

### 4. 보안 관점의 MySQL

SQL Injection 공격은 결국 공격자가 `SELECT` · `UNION` · `INSERT` 같은 SQL 구문을 웹 애플리케이션을 통해 데이터베이스에 주입하는 행위이다.

따라서 웹 애플리케이션을 개발할 때는 사용자 입력값을 그대로 SQL 쿼리에 결합하지 않고 **Prepared Statement 매개변수화된 쿼리**를 사용하여 데이터와 명령어를 명확히 분리해야 한다. 이는 MySQL 자체의 기능이라기보다는 PHP와 같은 애플리케이션 언어 레벨에서 구현해야 하는 핵심 보안 대책이다.

<hr class="short-rule">
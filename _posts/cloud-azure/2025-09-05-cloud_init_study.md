---
layout: post
title: "Cloud-init"
date: 2025-09-05 17:00:00 +0900
categories: [cloud-azure]
---

## 1. 개요

**cloud-init**은 클라우드 인스턴스(가상 머신)의 **초기 설정을 자동화**하는 업계 표준 멀티 디스트리뷰션 도구이다.
VM이 처음 부팅될 때 실행되어 호스트 이름 설정, SSH 키 등록, 패키지 설치, 사용자 생성, 파일 배포 등을 자동으로 수행한다.

### 핵심 기능
1.  **부팅 시 자동 구성**: OS 이미지를 굽지 않고도 부팅 시점에 원하는 설정을 주입하여 인프라를 유연하게 관리한다.
2.  **멀티 플랫폼 지원**: Azure, AWS, GCP, OpenStack 등 대부분의 퍼블릭/프라이빗 클라우드 환경에서 동일한 문법(YAML)으로 사용 가능하다.
3.  **IaC (Infrastructure as Code)**: 서버 설정을 코드로 정의하므로 버전 관리가 가능하고 재사용성이 높다.

### 활용 사례
*   **패키지 설치**: `nginx`, `git`, `docker` 등 필수 소프트웨어 자동 설치
*   **사용자 관리**: 기본 계정 외 추가 사용자 생성 및 그룹 할당
*   **보안 설정**: SSH 공개키(Authorized Keys) 자동 배포
*   **파일 배포**: 설정 파일(`/etc/nginx/nginx.conf` 등) 생성 및 권한 부여

---

## 2. cloud-init 형식

cloud-init 설정 파일은 주로 YAML 형식을 사용하며, 파일 최상단에 `#cloud-config` 주석이 반드시 있어야 한다.

### 기본 구조
```yaml
#cloud-config

# 1. 패키지 업데이트 및 업그레이드
package_update: true
package_upgrade: true

# 2. 패키지 설치
packages:
  - nginx
  - git
  - htop
  - curl

# 3. 명령어 실행 (쉘 스크립트처럼 동작)
runcmd:
  - systemctl enable nginx
  - systemctl start nginx
  - echo "System Ready" > /tmp/ready

# 4. 파일 작성
write_files:
  - path: /var/www/html/index.html
    permissions: '0644'
    owner: root:root
    content: |
      <h1>Hello from cloud-init!</h1>
      <p>This file was created automatically.</p>
```

---

## 3. Azure에서 사용 방법

### Azure CLI로 VM 생성 시 적용
`--custom-data` 파라미터에 cloud-init 파일 경로를 지정한다.
```bash
az vm create \
  -g MyRG -n WebServer \
  --image Ubuntu2204 \
  --custom-data cloud-init.yaml \
  --admin-username azureuser \
  --generate-ssh-keys
```

### ARM 템플릿에서 사용
Base64로 인코딩된 문자열을 `customData` 속성에 넣는다.
```json
{
  "osProfile": {
    "customData": "[base64(parameters('cloudInitScript'))]"
  }
}
```

### Terraform에서 사용
`base64encode()` 함수와 `file()` 함수를 함께 사용한다.
```hcl
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  # ... (생략)
  custom_data = base64encode(file("cloud-init.yaml"))
}
```

---

## 4. 실습 예시

### 시나리오 1: 웹 서버(Nginx + PHP) 자동 구축

`web-server.yaml`:
```yaml
#cloud-config

package_update: true

packages:
  - nginx
  - php-fpm

# Nginx의 기본 index.html 교체
write_files:
  - path: /var/www/html/index.html
    permissions: '0644'
    owner: www-data:www-data
    content: |
      <!DOCTYPE html>
      <html>
      <head><title>Welcome</title></head>
      <body>
        <h1>Server deployed by cloud-init</h1>
        <p>Hostname: $(hostname)</p>
        <p>Deploy Time: $(date)</p>
      </body>
      </html>

runcmd:
  - systemctl enable nginx
  - systemctl start nginx
  - echo "Deployment completed at $(date)" >> /var/log/cloud-init-custom.log
```

### 시나리오 2: WordPress 자동 설치 (LAMP 스택)

```yaml
#cloud-config

packages:
  - apache2
  - mysql-server
  - php
  - php-mysql
  - libapache2-mod-php
  - wget

runcmd:
  # 서비스 시작
  - systemctl enable apache2 mysql
  - systemctl start apache2 mysql
  
  # WordPress 다운로드 및 설치
  - cd /var/www/html
  - wget https://wordpress.org/latest.tar.gz
  - tar -xzf latest.tar.gz
  - mv wordpress/* .
  - rm -rf wordpress latest.tar.gz
  - chown -R www-data:www-data /var/www/html
  - rm index.html
```

---

## 5. 주요 모듈 설명

| 모듈 | 설명 | 예시 |
|---|---|---|
| **package_update** | `apt update` 또는 `yum check-update` 실행 | `true` |
| **packages** | 설치할 패키지 목록 정의 | `[nginx, git]` |
| **users** | 사용자 및 그룹 생성, 권한 부여 | `groups: sudo` |
| **write_files** | 파일 생성 (경로, 권한, 소유자, 내용) | `path: /etc/config` |
| **runcmd** | 쉘 명령어 리스트 순차 실행 | `[ls -al, systemctl start]` |
| **ssh_keys** | SSH 공개키 배포 | `ssh-rsa AAAA...` |
| **disk_setup** | 디스크 파티셔닝 및 포맷 | `filesystem: ext4` |
| **mounts** | 디스크 마운트 설정 (`/etc/fstab`) | `[/dev/sdc, /data]` |

### 사용자 생성 고급 예시
```yaml
users:
  - name: developer
    groups: sudo, docker
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-rsa AAAA... (Public Key)
```

---

## 6. 보안 주의사항

cloud-init은 강력한 자동화 도구이지만, **민감한 정보를 평문으로 노출할 위험**이 있다. 공격자가 VM 내부에 침입하거나 클라우드 API 권한을 탈취하면 User Data에 저장된 비밀번호, API 키 등을 쉽게 획득할 수 있다.

### 위험: User Data / Custom Data 노출

*   **IMDS (Instance Metadata Service)**: Azure VM 내부에서 `http://169.254.169.254/metadata/instance`에 접근하면 VM의 Custom Data(cloud-init 스크립트)를 조회할 수 있다.
*   **Azure Portal/CLI**: `Contributor` 이상의 권한을 가진 사용자는 VM의 User Data를 API로 조회할 수 있다.
*   **잔류 로그**: cloud-init 로그 파일(`/var/log/cloud-init.log`)에 민감 정보가 남아있을 수 있다.

```bash
# VM 내부에서 Custom Data 조회 (공격자 관점)
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-02-01" | base64 -d
```

### 보안 권장 사항

1.  **비밀번호 하드코딩 금지**: cloud-init에 평문 비밀번호나 API 키를 넣지 않는다.
2.  **Azure Key Vault 사용**: Managed Identity를 통해 런타임에 Key Vault에서 비밀 정보를 가져오도록 스크립트를 작성한다.
3.  **로그 정리**: cloud-init 실행 후 민감 정보가 포함될 수 있는 로그 파일을 삭제하거나 권한을 제한한다.
4.  **IMDS 접근 제한**: 필요 시 iptables로 메타데이터 서비스 접근을 특정 사용자로 제한한다.

```yaml
#cloud-config
# Bad Example (❌)
runcmd:
  - echo "DB_PASSWORD=P@ssw0rd123" >> /etc/environment

# Good Example (✅) - Key Vault 사용
runcmd:
  - az login --identity
  - DB_PWD=$(az keyvault secret show --vault-name MyVault -n db-password --query value -o tsv)
  - echo "DB_PASSWORD=$DB_PWD" >> /etc/environment
```

---

## 7. 트러블슈팅

cloud-init이 실패했을 때 확인해야 할 로그 파일들이다.

### 로그 확인
```bash
# cloud-init 실행 전체 로그
tail -f /var/log/cloud-init.log

# runcmd 등 명령어 실행 결과 (STDOUT/STDERR)
tail -f /var/log/cloud-init-output.log
```

### 상태 확인 및 재실행
```bash
# 현재 상태 확인
cloud-init status

# 특정 모듈만 재실행 (디버깅용)
# 1. 클린업
sudo cloud-init clean
# 2. 초기화 단계 실행
sudo cloud-init init
# 3. 모듈 단계 실행
sudo cloud-init modules --mode=config
sudo cloud-init modules --mode=final
```

![cloud-init 로그 확인](/assets/images/cloud-azure/cloud-init.png)

<hr class="short-rule">

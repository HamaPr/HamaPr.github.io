---
layout: post
title: 리눅스 마스터 2급 취득
date: 2025-09-13 15:00:00 +0900
categories: [자격증]
tags: [linux]
---

리눅스 마스터 2급 자격증을 취득했습니다. 한국정보통신기술협회(KAIT)에서 주관하는 이 자격증 과정을 통해 파일 시스템부터 네트워크 설정까지, 리눅스 운영, 관리 기술을 학습했습니다.

---

### 1. 리눅스 일반

- ***리눅스의 이해***:
  - **커널**: 하드웨어를 제어하는 운영체제의 핵심. 리누스 토발즈가 개발.
  - **셸**: 사용자와 커널을 연결하는 인터페이스. 명령어 해석기. (bash, sh, csh 등)
  - **GNU 프로젝트**: 자유 소프트웨어 재단(FSF)의 리처드 스톨만이 시작한 'GNU is Not Unix' 프로젝트. 리눅스는 GNU 프로젝트의 도구들과 결합하여 완성됨.

- ***FHS (Filesystem Hierarchy Standard)***: 리눅스 디렉터리 구조 표준.
  - `/bin`: 기본 명령어.
  - `/sbin`: 시스템 관리자용 명령어.
  - `/etc`: 시스템 설정 파일.
  - `/var`: 로그, 스풀 등 가변 데이터.
  - `/usr`: 사용자용 프로그램 및 데이터.
  - `/boot`: 부팅 관련 파일 (커널 이미지 등).

- ***파일 권한과 소유권***:
  - **권한**: `r`(read=4), `w`(write=2), `x`(execute=1)의 조합으로 표현. 소유자/그룹/기타 사용자로 구분.
  - **`chmod`**: 파일이나 디렉터리의 권한을 변경. (`chmod 755 file.sh`)
  - **`chown`**: 파일이나 디렉터리의 소유자 및 그룹을 변경. (`chown user:group file.txt`)

- ***링크 파일***:
  - **하드 링크**: 원본 파일과 동일한 inode를 공유. 원본이 삭제되어도 데이터 유지.
  - **심볼릭 링크 (소프트 링크)**: 원본 파일을 가리키는 바로 가기. 원본 삭제 시 링크 무효화. (`ln -s [원본] [링크]`)

---

### 2. 리눅스 운영 및 관리

- ***프로세스 관리***:
  - **`ps`**: 현재 실행 중인 프로세스 상태 확인.
    - `ps aux`: BSD 계열 옵션. 시스템의 모든 프로세스를 상세하게 출력.
    - `ps -ef`: System V 계열 옵션. 전체 프로세스를 PID, PPID와 함께 출력.
  - **`kill`**: 특정 PID의 프로세스에 시그널을 전송. (`kill -9 [PID]`는 강제 종료)
  - **`top`**: 시스템 프로세스 상태를 실시간으로 모니터링.

- ***디스크 및 파일시스템 관리***:
  - **파티션 생성**: `fdisk /dev/sdb` (n -> p -> 1 -> w)
  - **파일시스템 포맷**: `mkfs.ext4 /dev/sdb1`
  - **마운트**:
    - 임시 마운트: `mount /dev/sdb1 /data`
    - 영구 마운트: `/etc/fstab` 파일에 등록.
      ```
      /dev/sdb1   /data   ext4   defaults   0   0
      ```
  - **디스크 사용량 확인**: `df -h` (파일시스템 기준), `du -sh [dir]` (디렉터리 기준).

- ***사용자 및 그룹 관리***:
  - **관련 파일**:
    - `/etc/passwd`: 사용자 계정 정보.
    - `/etc/shadow`: 암호화된 패스워드.
    - `/etc/group`: 그룹 정보.
  - **명령어**:
    - `useradd [user]`: 사용자 생성. (`-d` 홈 디렉터리, `-s` 셸, `-g` 그룹 지정)
    - `passwd [user]`: 사용자 비밀번호 설정.
    - `usermod`, `userdel`, `groupadd` 등.

- ***패키지 관리***:
  - **RPM (RedHat Package Manager)**: CentOS, Fedora 계열.
    - `rpm -ivh [package.rpm]`: 설치.
    - `rpm -qa | grep [name]`: 설치된 패키지 검색.
    - `yum install [name]`: 의존성을 해결하며 온라인으로 설치.
  - **DPKG (Debian Package)**: Debian, Ubuntu 계열.
    - `dpkg -i [package.deb]`: 설치.
    - `apt-get install [name]`: 의존성을 해결하며 온라인으로 설치.

---

### 3. 리눅스 활용

- ***셸 스크립트 기초***:
  - `#!/bin/bash`: 스크립트를 실행할 셸을 지정 (Shebang).
  - 변수: `VAR="value"`, 참조 시 `$VAR`.
  - 조건문: `if [ 조건 ]; then ... fi`.
  - 반복문: `for i in {1..5}; do ... done`.

- ***서비스 관리 (systemd)***:
  - **`systemctl`**: `systemd`를 사용하는 최신 리눅스 배포판의 서비스 관리 명령어.
    - `systemctl start [service]`: 서비스 시작.
    - `systemctl stop [service]`: 서비스 중지.
    - `systemctl enable [service]`: 부팅 시 자동 실행 등록.
    - `systemctl status [service]`: 서비스 상태 확인.

- ***네트워크 설정 및 확인***:
  - **`ip` 명령어**: 최신 네트워크 설정 명령어.
    - `ip addr show`: IP 주소 확인.
    - `ip route show`: 라우팅 테이블 확인.
  - **`netstat -anp`**: 모든 네트워크 연결 및 포트 상태를 PID와 함께 확인.
  - **방화벽 (firewalld)**:
    ```bash
    firewall-cmd --permanent --add-service=http # 서비스 허용
    firewall-cmd --reload                       # 설정 다시 로드
    ```

- ***텍스트 편집기***:
  - **vi/vim**: 리눅스의 표준 텍스트 편집기. 명령 모드, 입력 모드, 실행 모드로 구성.
    - `:w`: 저장.
    - `:q`: 종료.
    - `:wq`: 저장 후 종료.
    - `:q!`: 강제 종료.

<hr class="short-rule">
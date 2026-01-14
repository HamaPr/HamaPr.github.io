---
layout: post
title: "systemd 서비스 관리 심화"
date: 2025-06-12 17:00:00 +0900
categories: [linux]
---

## 1. 개념

**systemd**는 리눅스 시스템의 부팅 프로세스를 초기화하고(PID 1) 시스템 서비스 및 리소스를 관리하는 표준 Init 시스템입니다.
서비스 간의 의존성을 처리하고 병렬 실행을 지원하여 부팅 속도와 시스템 관리 효율성을 향상시킵니다.

### 기본 정보

| 항목 | 설명 |
|------|------|
| 역할 | PID 1 프로세스, 모든 서비스의 부모 |
| 설정 경로 | `/etc/systemd/system/`, `/lib/systemd/system/` |
| 관리 명령어 | `systemctl` |

### systemd vs SysVinit

| 항목 | SysVinit | systemd |
|------|----------|---------|
| 시작 방식 | 순차적 | 병렬 (빠른 부팅) |
| 서비스 스크립트 | 쉘 스크립트 | Unit 파일 |
| 의존성 관리 | 수동 | 자동 (Wants, Requires) |

### Unit 유형

| 타입 | 확장자 | 용도 |
|------|--------|------|
| Service | `.service` | 데몬 프로세스 |
| Socket | `.socket` | 소켓 활성화 |
| Target | `.target` | Unit 그룹 (런레벨 대체) |
| Timer | `.timer` | 예약 작업 (cron 대체) |
| Mount | `.mount` | 마운트 포인트 |

---

## 2. 설치 방법

systemd는 대부분의 배포판에 기본 설치됨.

### 설정 파일 경로
```bash
# 시스템 기본 Unit 파일
/lib/systemd/system/

# 관리자 커스텀 Unit 파일 (우선순위 높음)
/etc/systemd/system/

# 런타임 생성 Unit
/run/systemd/system/
```

---

## 3. 사용법

### 기본 서비스 관리
```bash
# 서비스 시작/중지/재시작
systemctl start nginx
systemctl stop nginx
systemctl restart nginx

# 설정 리로드 (재시작 없이)
systemctl reload nginx

# 서비스 상태 확인
systemctl status nginx

# 부팅 시 자동 시작 설정
systemctl enable nginx
systemctl disable nginx

# 서비스 시작 + 자동 시작 동시 설정
systemctl enable --now nginx
```

### 서비스 분석
```bash
# 모든 서비스 목록
systemctl list-units --type=service

# 실패한 서비스 확인
systemctl --failed

# 서비스 의존성 확인
systemctl list-dependencies nginx

# 부팅 시간 분석
systemd-analyze
systemd-analyze blame
```

### 커스텀 서비스 생성

`/etc/systemd/system/myapp.service`:
```ini
[Unit]
Description=My Custom Application
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/myapp
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=myuser
Group=mygroup

[Install]
WantedBy=multi-user.target
```

### Unit 파일 섹션 설명

| 섹션 | 설명 |
|------|------|
| `[Unit]` | 메타데이터, 의존성 정의 |
| `[Service]` | 실행 방법, 재시작 정책 |
| `[Install]` | enable 시 설정 |

### Type 옵션

| Type | 설명 |
|------|------|
| `simple` | 기본값, ExecStart가 메인 프로세스 |
| `forking` | 데몬화하는 프로세스 |
| `oneshot` | 일회성 작업 |
| `notify` | 준비 완료 신호 전송 |

---

## 4. 실습 예시

### Apache 소스 설치 후 systemd 등록

```bash
# 1. 서비스 파일 생성
cat > /etc/systemd/system/httpd-custom.service << 'EOF'
[Unit]
Description=Apache HTTP Server (Custom Build)
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/apache2/bin/apachectl start
ExecStop=/usr/local/apache2/bin/apachectl stop
ExecReload=/usr/local/apache2/bin/apachectl restart
PIDFile=/usr/local/apache2/logs/httpd.pid

[Install]
WantedBy=multi-user.target
EOF

# 2. systemd 리로드
systemctl daemon-reload

# 3. 서비스 시작 및 활성화
systemctl enable --now httpd-custom
```

### 타이머로 예약 작업 설정

```bash
# backup.service
cat > /etc/systemd/system/backup.service << 'EOF'
[Unit]
Description=Daily Backup

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup.sh
EOF

# backup.timer
cat > /etc/systemd/system/backup.timer << 'EOF'
[Unit]
Description=Run backup daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 타이머 활성화
systemctl enable --now backup.timer
systemctl list-timers
```

![systemctl status 출력](/assets/images/linux/systemd.png)

---

## 5. 트러블슈팅

### 서비스 시작 실패 시
```bash
# 상세 로그 확인
journalctl -u nginx -f
journalctl -xe
```

### Unit 파일 수정 후
```bash
# 반드시 daemon-reload 실행
systemctl daemon-reload
```

### preset 설정 확인
```bash
# 기본 활성화 여부 확인
systemctl preset nginx
cat /etc/systemd/system-preset/*.preset
```

<hr class="short-rule">

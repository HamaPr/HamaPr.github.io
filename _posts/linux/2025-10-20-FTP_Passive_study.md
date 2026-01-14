---
layout: post
title: "FTP Passive 모드 설정"
date: 2025-10-20 17:00:00 +0900
categories: [linux]
---

## 1. 개념

**Passive Mode**는 FTP 데이터 연결 시 클라이언트가 서버로 연결하는 방식입니다.

### Active vs Passive

| 구분 | Active | Passive |
|------|--------|---------|
| 데이터 연결 | 서버 → 클라이언트 | 클라이언트 → 서버 |
| 방화벽 | 클라이언트 방화벽 문제 | ✅ 문제 없음 |
| 포트 | 20번 고정 | 랜덤 포트 |

### 왜 Passive를 쓰는가?
- **NAT 환경**: 클라이언트가 공유기 뒤에 있으면 Active 불가
- **방화벽**: 외부→내부 연결 차단 시 Active 불가
- **현대 환경**: 대부분 Passive 사용

---

## 2. 설정 방법

### /etc/vsftpd/vsftpd.conf
```conf
# Passive 모드 활성화
pasv_enable=YES

# Passive 포트 범위 지정
pasv_min_port=30000
pasv_max_port=30100

# 서버 외부 IP (NAT 환경)
pasv_address=10.0.0.11
```

### 방화벽 설정
```bash
# Passive 포트 범위 허용
firewall-cmd --permanent --add-port=30000-30100/tcp
firewall-cmd --reload
```

### 서비스 재시작
```bash
systemctl restart vsftpd
```

---

## 3. 사용법

### 클라이언트 테스트
```bash
# lftp (Passive 기본)
lftp -u ftpuser 10.0.0.11

# ftp 명령어 (Passive 전환)
ftp 10.0.0.11
ftp> passive
Passive mode on.
```

### FileZilla 설정
1. 편집 → 설정 → FTP
2. 전송 모드: **Passive**

---

## 4. 실습

### 요구사항

| 항목 | 설정값 |
|------|--------|
| Passive 포트 범위 | 60000 ~ 60010 |
| 사용자 | a, b |
| chroot | 활성화 |
| idle_session_timeout | 120초 |
| data_connection_timeout | 60초 |

### vsftpd.conf 설정

```conf
pasv_enable=YES
pasv_min_port=60000
pasv_max_port=60010
pasv_address=10.0.0.11

chroot_local_user=YES
allow_writeable_chroot=YES
idle_session_timeout=120
data_connection_timeout=60
```

### 설정 검증 - 타임아웃 및 디렉토리 확인

`/hamap` 디렉토리 구성과 타임아웃 설정 적용 여부를 확인합니다.

![FTP Passive 설정 검증](/assets/images/linux/ftp-passive-config.png)

```bash
ls -al /hamap
# banner, chroot, xferlog 파일 확인

cat /etc/vsftpd/vsftpd.conf | grep 'time'
# idle_session_timeout=120
# data_connection_timeout=60
```

### 포트 리스닝 확인

`ss -nat` 명령으로 Passive 포트 범위(60000-60010)가 사용 중인지 확인합니다.

![FTP Passive 포트 확인](/assets/images/linux/ftp-passive-port-check.png)

### Wireshark 분석 - PASV 포트 계산

FTP Passive 모드에서 서버가 응답하는 포트 번호를 분석합니다.

![FTP Passive Wireshark 분석](/assets/images/linux/ftp-passive-wireshark.png)

서버 응답: `227 Entering Passive Mode (10,0,0,11,234,97)`

**포트 계산 공식**:
```
포트 = (첫 번째 숫자 × 256) + 두 번째 숫자
     = (234 × 256) + 97
     = 60001
```

동일한 방식으로 사용자 b의 연결도 확인:

![FTP Passive 사용자 b](/assets/images/linux/ftp-passive-user2.png)

---

## 5. 트러블슈팅

| 문제 | 원인 | 해결 |
|------|------|------|
| 연결은 되지만 목록 안 보임 | Passive 포트 차단 | 방화벽에 포트 범위 추가 |
| 외부에서 접속 안됨 | pasv_address 미설정 | 외부 IP 설정 |
| 타임아웃 | 포트 범위 너무 좁음 | 범위 확대 |

<hr class="short-rule">

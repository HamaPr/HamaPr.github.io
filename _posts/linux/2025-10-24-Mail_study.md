---
layout: post
title: "Mail Server"
date: 2025-10-24 17:00:00 +0900
categories: [linux]
---

## 1. 개요

**메일 서버**는 인터넷을 통해 전자우편을 송수신하고 저장하는 시스템이다.
메일을 발송하고 중계하는 **MTA (Mail Transfer Agent)**와 수신된 메일을 사용자의 편지함에 저장하고 전달하는 **MDA (Mail Delivery Agent)**가 협력하여 작동한다.

### 핵심 구성 요소
1.  **SMTP (Simple Mail Transfer Protocol)**: 메일을 발송하거나 서버 간에 전송할 때 사용하는 프로토콜이다. (TCP 25)
2.  **MTA (전송 에이전트)**: SMTP를 이용하여 실제로 메일을 배달하는 소프트웨어이다. (예: Sendmail, Postfix)
3.  **MDA (수신 에이전트)**: 도착한 메일을 분류하여 저장소에 넣고, POP3/IMAP을 통해 사용자에게 제공한다. (예: Dovecot, Procmail)

### 동작 흐름 다이어그램
```mermaid
flowchart LR
    Sender((발신자)) -->|SMTP| MTA1[Sendmail 서버]
    MTA1 -->|SMTP| MTA2[수신측 서버]
    MTA2 -->|저장| MDA[Dovecot]
    MDA -->|POP3/IMAP| Receiver((수신자))
```

### 프로토콜 비교
| 역할 | 프로토콜 | 포트 | 소프트웨어 (Linux) | 설명 |
|------|----------|------|--------------------|------|
| **전송** | SMTP | 25 | `Sendmail`, `Postfix` | 메일 발송 및 중계 |
| **수신** | POP3 | 110 | `Dovecot` | 메일을 로컬로 다운로드 후 서버에서 삭제 (옵션) |
| **수신** | IMAP | 143 | `Dovecot` | 메일을 서버에 저장하고 동기화 (멀티 디바이스 권장) |

---

## 2. 서버 구축 (Sendmail & Dovecot)

Rocky Linux 환경에서 전통적인 **Sendmail**과 **Dovecot**을 이용하여 메일 서버를 구축하는 과정이다.

### 설치 및 서비스 시작
```bash
# 패키지 설치
dnf install -y sendmail sendmail-cf dovecot

# 서비스 활성화 및 시작
systemctl enable --now sendmail dovecot

# 방화벽 허용 (SMTP, POP3, IMAP)
firewall-cmd --permanent --add-service={smtp,pop3,imap}
firewall-cmd --reload
```

---

## 3. 설정 방법

### Sendmail 설정 (/etc/mail/sendmail.mc)
기본적으로 Sendmail은 로컬 루프백(`127.0.0.1`)에서만 연결을 허용하므로, 외부 통신을 위해 이를 해제해야 한다.

1.  **설정 파일 수정**: `vi /etc/mail/sendmail.mc`
2.  `DAEMON_OPTIONS` 라인 수정:
    ```bash
    # (변경 전) DAEMON_OPTIONS(`Port=smtp,Addr=127.0.0.1, Name=MTA')dnl
    # (변경 후) DAEMON_OPTIONS(`Port=smtp, Name=MTA')dnl
    ```
3.  **컴파일 및 적용**: `.mc` 파일을 `.cf` 설정 파일로 변환한다.
    ```bash
    m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf
    systemctl restart sendmail
    ```

### Dovecot 설정 (/etc/dovecot/dovecot.conf)
POP3와 IMAP 프로토콜을 활성화하고 메일 박스 형식을 지정한다.

1.  **메인 설정**: `/etc/dovecot/dovecot.conf`
    ```conf
    protocols = imap pop3
    listen = *
    ```
2.  **메일 박스 위치**: `/etc/dovecot/conf.d/10-mail.conf`
    ```conf
    # mbox 형식 사용 (사용자 홈 디렉터리에 메일 저장)
    mail_location = mbox:~/mail:INBOX=/var/mail/%u
    ```

---

## 4. 실습: 메일 송수신 테스트

### 환경 구성
*   **도메인**: `hamap.local`
*   **메일 서버 IP**: `10.0.0.13`
*   **DNS MX 레코드**: `mail.hamap.local` -> `10.0.0.13`

### 사용자 생성
이메일 계정으로 사용할 리눅스 사용자를 생성한다.
```bash
useradd a
useradd b
passwd a
passwd b
```

### 릴레이 허용 (/etc/mail/access)
신뢰할 수 있는 네트워크나 도메인에서 보낸 메일만 중계(Relay)하도록 설정한다. 스팸 메일 서버로 악용되는 것을 막기 위해 필수적이다.
```bash
Connect:10.0.0        RELAY
Connect:hamap.local   RELAY
```
적용: `makemap hash /etc/mail/access < /etc/mail/access`

### 클라이언트 연동 (Thunderbird)
PC에서 메일 클라이언트(Thunderbird 등)를 설치하고 테스트 계정을 연결한다.
1.  **계정 설정**: 이름(사용자 A), 이메일(`a@hamap.local`), 비밀번호 입력.
2.  **수동 설정**:
    *   수신 서버 (IMAP): `10.0.0.13`, 포트 143, SSL 없음.
    *   발신 서버 (SMTP): `10.0.0.13`, 포트 25, SSL 없음.
3.  **송수신 테스트**: A 사용자에서 B 사용자로 메일을 보내고, B 사용자에서 정상 수신되는지 확인한다.

### 트러블슈팅
*   **"Relaying Denied" 오류**: `/etc/mail/access` 파일에 클라이언트 IP나 도메인이 `RELAY`로 등록되어 있는지 확인하고 `makemap` 명령을 다시 실행한다.
*   **접속 실패**: 방화벽(firewalld)에서 해당 포트(25, 110, 143)가 열려 있는지 확인한다.

<hr class="short-rule">

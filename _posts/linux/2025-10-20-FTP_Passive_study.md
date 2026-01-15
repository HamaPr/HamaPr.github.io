---
layout: post
title: "FTP Passive Mode"
date: 2025-10-20 17:00:00 +0900
categories: [linux]
---

## 1. 개요

**Passive Mode**는 FTP의 고질적인 방화벽 연결 문제를 해결하기 위해 고안된 데이터 전송 방식이다.
Active Mode와 달리, **클라이언트가 서버의 랜덤 포트로 데이터 연결을 요청**하는 구조이므로 클라이언트 쪽에 방화벽이나 공유기(NAT)가 있어도 원활하게 통신할 수 있다.

### Active vs Passive 비교

| 특징 | Active Mode | Passive Mode |
|------|-------------|--------------|
| **데이터 연결 주체** | 서버 → 클라이언트 | 클라이언트 → 서버 |
| **명령어 포트** | 21 (TCP) | 21 (TCP) |
| **데이터 포트** | 20 (서버 고정) | 1024 이상의 랜덤 포트 (서버) |
| **방화벽 친화성** | 낮음 (클라이언트 방화벽이 차단함) | 높음 (요즘 표준) |

---

## 2. 서버 설정 (vsftpd.conf)

Passive Mode를 제대로 사용하려면 FTP 서버가 사용할 **데이터 포트 범위**를 명시적으로 지정하고 방화벽에서 열어주어야 한다.

```bash
vi /etc/vsftpd/vsftpd.conf
```

### 필수 설정 항목
```ini
# Passive 모드 활성화
pasv_enable=YES

# 데이터 전송에 사용할 포트 범위 지정 (예: 60000~60010)
pasv_min_port=60000
pasv_max_port=60010

# (중요) 서버가 NAT 뒤에 있는 경우 외부 공인 IP 지정
# 클라이언트가 이 IP로 접속을 시도하게 됨
pasv_address=10.0.0.11
```

### 방화벽 설정
지정한 포트 범위만큼 방화벽을 열어주어야 한다.
```bash
firewall-cmd --permanent --add-port=60000-60010/tcp
firewall-cmd --reload
```

---

## 3. 실습: 패시브 모드 검증

### FileZilla 설정
클라이언트(FileZilla 등)에서도 전송 모드를 설정할 수 있다. 대부분 '기본값'이나 'Passive'로 되어 있다.
*   **파일** > **사이트 관리자** > **전송 설정** 탭 > **전송 모드**: `수동형(Passive)` 선택

![FTP Passive 설정 검증](/assets/images/linux/ftp-passive-config.png)

### Wireshark 패킷 분석
서버가 클라이언트에게 어떤 포트로 접속하라고 알려주는지 패킷을 통해 직접 확인한다.

1.  **PASV 명령**: 클라이언트가 "Passive 모드로 통신하자"고 요청
2.  **227 Entering Passive Mode**: 서버가 수락하며 접속할 IP와 포트 정보를 알려줌

![FTP Passive Wireshark 분석](/assets/images/linux/ftp-passive-wireshark.png)

### 포트 번호 계산
서버의 응답 메시지: `(10,0,0,11,234,97)`
여기서 앞의 4개는 IP 주소(`10.0.0.11`)이고, 뒤의 2개(`234`, `97`)가 포트 번호이다.

$$ \text{Port} = (234 \times 256) + 97 = 59904 + 97 = 60001 $$

즉, 클라이언트는 서버의 **60001번 포트**로 데이터 연결을 시도하게 된다.

---

## 4. 트러블슈팅

### 접속은 되는데 파일 목록이 안 보임 (Listing Failed)
전형적인 Passive 포트 차단 증상이다. 21번 포트는 열려 있어서 로그인까지는 되지만, 데이터 채널인 60000번대 포트가 방화벽에 막혀 파일 목록을 받아오지 못하는 것이다.
*   **해결**: `firewall-cmd`로 `pasv_min_port` ~ `pasv_max_port` 범위가 열려 있는지 확인한다.

### 외부(공인 IP)에서 접속 불가
서버가 사설 IP를 쓰고 있고 외부에서 접속하는 경우, 서버는 자신의 사설 IP를 알려주기 때문에 클라이언트가 접속할 수 없다.
*   **해결**: `pasv_address=공인IP` 설정을 통해 서버가 클라이언트에게 공인 IP를 알려주도록 해야 한다.

<hr class="short-rule">

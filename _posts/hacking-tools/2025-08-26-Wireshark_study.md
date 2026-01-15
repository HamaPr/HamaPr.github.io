---
layout: post
title: "Wireshark (Network Protocol Analyzer)"
date: 2025-08-26 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

**Wireshark**는 세계에서 가장 널리 사용되는 오픈소스 네트워크 프로토콜 분석기이다.
네트워크 인터페이스를 통과하는 모든 패킷을 실시간으로 캡처하고 원시 데이터(Raw Data) 수준까지 정밀하게 분석할 수 있어, 네트워크 문제 해결부터 악성 트래픽 탐지까지 광범위하게 활용된다.
본 글에서는 Wireshark의 핵심 기능인 패킷 캡처와 디스플레이 필터를 익히고, 실제 HTTP 로그인 패킷과 HTTPS 암호화 패킷을 분석, 복호화하는 과정을 다룬다.

---

## 2. 주요 기능

### 패킷 캡처
네트워크 인터페이스(예: `eth0`, `Wi-Fi`)를 선택하여 오고 가는 모든 트래픽을 수집한다.

### 디스플레이 필터
수만 개의 패킷 중 원하는 정보만 빠르게 찾기 위해 필터링 규칙을 적용한다.
*   `ip.addr == 192.9.200.11`: 특정 IP 관련 패킷만 필터링
*   `tcp.port == 80`: 웹 트래픽(80번 포트)만 필터링
*   `http.request.method == "POST"`: HTTP POST 요청만 필터링

### TCP 스트림 추적
분할되어 전송된 여러 TCP 패킷을 재조립하여 사람이 읽을 수 있는 하나의 데이터 스트림(대화 내용)으로 보여준다.

---

## 3. 실습: Ping 패킷 분석

가장 기본적인 `ping` 통신 과정을 분석하며 Wireshark 사용법을 익힌다.

1.  캡처를 시작하고 터미널에서 `ping -c 1 192.9.200.11`을 실행한다.
2.  필터 입력창에 `icmp`를 입력한다.

![WiresharkIcmp](/assets/images/hacking-tools/Wire_1.png)

내 PC가 보낸 `Echo (ping) request` 패킷과 서버가 응답한 `Echo (ping) reply` 패킷을 확인할 수 있다.

---

## 4. 실습: Credential Sniffing

암호화되지 않은 HTTP 통신에서 계정 정보가 평문으로 노출되는 취약점을 확인한다.

1.  캡처를 시작하고 DVWA 로그인 페이지(HTTP)에서 로그인을 시도한다.
2.  필터에 `http.request.method == "POST"`를 입력하여 로그인 요청 패킷을 찾는다.
3.  패킷 상세 창(Packet Details)에서 `HTML Form URL Encoded` 항목을 확인하거나, 우클릭 후 `Follow TCP Stream`을 실행한다.

![WiresharkHttppost](/assets/images/hacking-tools/Wire_2.png)
![WiresharkFollowtcpstream](/assets/images/hacking-tools/Wire_3.png)

`username`과 `password`가 평문으로 전송되는 것을 명확히 확인할 수 있다.

---

## 5. 심화: HTTPS 트래픽 복호화

TLS로 암호화된 트래픽을 Wireshark에서 설정하여 복호화하는 방법이다.

### 복호화 원리
브라우저가 TLS 통신 시 생성하는 임시 비밀키(Session Key)를 파일(`SSLKEYLOGFILE`)로 저장하게 하고, Wireshark가 이 파일을 참조하여 패킷을 실시간으로 복호화하는 방식이다.

### 설정 절차

**1. 키 로그 파일 경로 지정**
터미널에서 환경 변수를 설정하고 브라우저를 실행한다.
```bash
export SSLKEYLOGFILE=~/ssl_key.log
firefox  # 또는 chrome
```

**2. Wireshark 설정**
메뉴에서 `Edit > Preferences > Protocols > TLS`로 이동하여 `(Pre)-Master-Secret log filename` 항목에 위에서 설정한 로그 파일 경로(`~/ssl_key.log`)를 등록한다.

**3. 결과 확인**
HTTPS 사이트에 접속하면 암호화되어 `Application Data`로만 보이던 패킷이 `HTTP` 프로토콜로 식별되며, 하단 `Decrypted TLS` 탭에서 평문 데이터를 확인할 수 있게 된다.

---

## 6. 필터 및 통계

대량의 패킷 속에서 원하는 정보만 정밀하게 추출하기 위한 고급 필터와 통계 기능이다.

### 디스플레이 필터 심화
```bash
# 논리 연산자 조합
ip.addr == 10.0.0.11 && tcp.port == 80

# 특정 문자열 포함 (HTTP Body 내)
http contains "password"

# 패킷 크기 필터링
frame.len > 1000

# 특정 TCP 플래그 (SYN만)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# 특정 시간 범위 (상대 시간)
frame.time_relative >= 10 && frame.time_relative <= 60
```

### Capture Filter (캡처 시 필터링)
캡처 전 미리 필터를 걸어 불필요한 트래픽을 제외하여 파일 크기를 줄인다.
```bash
# 특정 호스트만 캡처
host 192.168.1.100

# 특정 포트만 캡처
port 443

# 특정 대역 제외
not net 10.0.0.0/8
```

### Statistics 메뉴 활용
*   **Conversations**: 통신한 호스트 쌍과 데이터량 통계 (대용량 전송 호스트 식별)
*   **Protocol Hierarchy**: 캡처된 프로토콜 비율 (이상 프로토콜 탐지)
*   **IO Graph**: 시간대별 트래픽 그래프 (공격 발생 시점 시각화)
*   **Endpoints**: 통신 참여자별 패킷/바이트량 정렬

### 색상 규칙 (Colouring Rules)
`View > Coloring Rules`에서 특정 조건의 패킷에 색상을 지정하여 시각적으로 빠르게 식별한다. (예: HTTP 오류=빨강, DNS=파랑)

<hr class="short-rule">
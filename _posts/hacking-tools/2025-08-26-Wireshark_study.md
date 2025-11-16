---
layout: post
title: "Wireshark 공부"
date: 2025-08-26 17:00:00 +0900
categories: [해킹 툴]
---

### 1. Wireshark 개요

Wireshark는 네트워크 패킷 분석 도구이다. 네트워크 인터페이스를 오가는 모든 트래픽을 실시간으로 캡처하여 각 패킷의 내용을 상세하게 보여주는 기능을 한다.

Burp Suite가 웹 트래픽(HTTP)이라는 특정 애플리케이션 계층에 집중한다면 Wireshark는 그보다 낮은 계층인 TCP/IP · UDP · ICMP 등 모든 종류의 패킷을 원시(Raw) 형태로 들여다볼 수 있다. 네트워크 통신의 근본 원리를 이해하는 데 필수적인 도구이다.

---

### 2. 기본 인터페이스

Wireshark의 화면은 크게 세 부분으로 나뉜다.
1.  **패킷 목록 (Packet List Pane)**: 캡처된 패킷들의 요약 정보(번호 · 시간 · 출발지/목적지 IP · 프로토콜 등)를 시간 순서대로 보여준다.
2.  **패킷 상세 (Packet Details Pane)**: 목록에서 선택한 패킷의 구조를 프로토콜 계층별로 나누어 상세하게 보여준다. (Ethernet · IP · TCP 등)
3.  **패킷 바이트 (Packet Bytes Pane)**: 선택한 패킷의 실제 데이터 값을 16진수와 ASCII 형태로 보여준다.

---

### 3. 주요 기능

#### ***패킷 캡처 (Packet Capture)***
Wireshark를 실행하고 캡처할 네트워크 인터페이스(예: `eth0` 또는 `VMnet8`)를 선택하면 실시간으로 패킷 수집이 시작된다. 빨간색 사각형 아이콘을 누르면 캡처가 중지된다.

#### ***디스플레이 필터 (Display Filters)***
수많은 패킷 중에서 원하는 정보만 걸러보는 핵심 기능이다. 상단의 필터 입력창에 조건을 입력하면 해당 조건에 맞는 패킷만 목록에 표시된다.
*   `ip.addr == 192.9.200.11`: 출발지 또는 목적지 IP가 `192.9.200.11`인 패킷
*   `tcp.port == 80`: TCP 포트 80을 사용하는 패킷
*   `icmp`: `ping`과 관련된 ICMP 프로토콜 패킷
*   `http`: HTTP 프로토콜 패킷
*   `http.request.method == "POST"`: HTTP POST 요청만 필터링한다.

#### ***TCP 스트림 추적 (Follow TCP Stream)***
흩어져 있는 여러 개의 TCP 패킷을 하나의 대화(Stream)로 재조합하여 보여주는 기능이다. 복잡한 패킷 목록 없이 전체 HTTP 요청과 응답 내용을 한눈에 파악할 수 있다.

---

### 4. 사용 예시: Ping 패킷 분석

가장 기본적인 네트워크 통신인 `ping` 명령의 패킷을 분석해 본다.

1.  Wireshark에서 패킷 캡처를 시작한다.
2.  터미널을 열어 `ping -c 1 192.9.200.11` 명령을 실행한다. (`-c 1`은 한 번만 보내는 옵션)
3.  Wireshark에서 캡처를 중지한다.
4.  디스플레이 필터에 `icmp`를 입력한다.

   ![WiresharkIcmp](/assets/images/Wire_1.png)

결과적으로 두 개의 ICMP 패킷이 나타난다. 하나는 내 PC가 Target 서버로 보낸 `Request`(요청)이고 다른 하나는 Target 서버가 응답한 `Reply`(응답)이다. 이 과정을 통해 간단한 `ping` 명령이 실제 네트워크에서는 어떤 패킷 형태로 오고 가는지 직접 확인할 수 있다.

### 5. 사용 예시 2: HTTP 로그인 패킷 분석

암호화되지 않은 HTTP 로그인 요청을 캡처하여 아이디와 비밀번호가 평문으로 전송되는 것을 확인한다.

1.  Wireshark 캡처를 시작하고 DVWA 로그인 페이지에서 로그인한다.
2.  캡처를 중지하고 필터에 `http.request.method == "POST"` 를 입력한다.
3.  필터링된 POST 패킷의 상세 창에서 `HTML Form URL Encoded` 부분을 확장하면 `username`과 `password` 값을 평문으로 확인할 수 있다.

   ![WiresharkHttppost](/assets/images/Wire_2.png)

4.  해당 패킷에서 `Follow TCP Stream` 기능을 사용하면 `username=admin&password=password` 와 같은 전송 데이터를 더 명확하게 확인할 수 있다.

   ![WiresharkFollowtcpstream](/assets/images/Wire_3.png)

이 과정을 통해 암호화되지 않은 HTTP 통신은 중간에서 얼마든지 감청될 수 있다는 것을 명확히 확인할 수 있다.

#### ***복호화 원리***

TLS 핸드셰이크 과정에서 클라이언트와 서버는 공유 비밀(Pre-Master Secret)을 생성한다.  
이 값을 외부에 기록하면, Wireshark가 이를 이용해 암호화된 트래픽을 복호화할 수 있다.  
브라우저는 `SSLKEYLOGFILE` 환경 변수가 설정되어 있을 경우, 이 키를 지정된 파일에 기록한다.

#### ***설정 절차***

1. **키 로그 파일 경로 지정**  
   터미널에서 다음 환경 변수를 설정한다.  
   ```bash
   export SSLKEYLOGFILE=~/ssl_key.log
   ```  
   이후 동일한 터미널에서 브라우저를 실행해야 키 로그가 기록된다.  
   ```bash
   firefox
   ```

2. **Wireshark에 키 로그 경로 등록**  
   Wireshark 메뉴에서 `Edit > Preferences > Protocols > TLS`로 이동한다.  
   `(Pre)-Master-Secret log filename` 필드에 위에서 지정한 파일 경로(`~/ssl_key.log`)를 입력한다.

3. **캡처 및 분석**  
   - Wireshark에서 패킷 캡처를 시작한다.  
   - 키 로깅이 활성화된 브라우저로 HTTPS 사이트(DVWA 등)에 접속하고 로그인한다.  
   - 캡처를 중지한 후 디스플레이 필터에 `http`를 입력한다.  

   설정이 성공하면, 기존에 `TLSv1.3 Application Data`로만 표시되던 패킷이 `HTTP/1.1` 또는 `HTTP/2`로 식별되며,  
   패킷 상세 창 하단에 `Decrypted TLS` 탭이 추가된다.  
   이 탭을 선택하면 평문 형태의 HTTP 요청 본문(예: `username=admin&password=password`)을 확인할 수 있다.

> 최신 브라우저에서는 샌드박스 정책으로 인해 키 로그가 기대한 경로에 생성되지 않을 수 있다.  
> 이 경우 Firefox를 사용하거나, 터미널에서 직접 브라우저를 실행해 환경 변수가 정상적으로 상속되었는지 확인해야 한다.  
> 또한, TLS 1.3에서는 일부 세션 재사용 방식으로 인해 모든 패킷이 복호화되지 않을 수도 있다.

<hr class="short-rule">
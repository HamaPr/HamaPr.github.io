---
layout: post
title: 네트워크 관리사 2급 취득
date: 2025-07-12 15:00:00 +0900
categories: [자격증]
tags: [네트워크 관리사, ICQA, network]
---

한국정보통신자격협회(ICQA) 네트워크 관리사 2급 자격증을 취득했습니다. 이 과정에서 TCP/IP, OSI 모델, NOS, 네트워크 운용기기와 같은 핵심 이론은 물론 라우터 설정, 서버 구축, 케이블 제작과 같은 실제 설정 절차를 익히며 네트워크 관리 방법을 학습했습니다.

---

### ***1. 네트워크 일반***

- ***OSI 7계층 모델***: 네트워크 통신 과정을 7개의 논리적 계층으로 구분한 모델.
  - **7계층 (응용)**: 사용자 인터페이스 제공. (HTTP, FTP, SMTP, DNS)
  - **6계층 (표현)**: 데이터 형식 변환, 암호화, 압축. (JPEG, ASCII)
  - **5계층 (세션)**: 통신 세션 설정, 유지, 종료.
  - **4계층 (전송)**: 종단 간 신뢰성 있는 데이터 전송. (TCP, UDP)
  - **3계층 (네트워크)**: IP 주소를 사용한 경로 설정(Routing). (IP, ICMP)
  - **2계층 (데이터링크)**: MAC 주소를 사용한 프레임 전송. (이더넷)
  - **1계층 (물리)**: 전기적 신호(Bit) 전송. (케이블, 허브)

- ***데이터 단위 (PDU)***
  - **세그먼트 (Segment)**: 4계층 (전송 계층)
  - **패킷 (Packet)**: 3계층 (네트워크 계층)
  - **프레임 (Frame)**: 2계층 (데이터링크 계층)

- ***네트워크 토폴로지***:
  - **버스형 (Bus)**: 하나의 통신 회선에 여러 노드가 연결.
  - **스타형 (Star)**: 중앙 장비(허브, 스위치)에 모든 노드가 연결.
  - **링형 (Ring)**: 각 노드가 인접한 두 노드와 연결되어 링을 구성.
  - **메시형 (Mesh)**: 모든 노드가 서로 직접 연결. 안정성이 높음.

- ***전송 매체***:
  - **UTP (Unshielded Twisted Pair)**: 가장 널리 사용되는 구리선 케이블. 카테고리(CAT5, CAT6)에 따라 대역폭이 다름.
  - **광섬유 (Optical Fiber)**: 빛을 이용해 데이터를 전송. 장거리, 고속 전송에 유리.

---

### ***2. TCP/IP***

- ***TCP/IP 4계층 모델***: OSI 7계층을 4계층으로 단순화한 실용 모델.
  - **4계층 (응용)**: OSI 5, 6, 7계층에 해당.
  - **3계층 (전송)**: OSI 4계층에 해당.
  - **2계층 (인터넷)**: OSI 3계층에 해당.
  - **1계층 (네트워크 인터페이스)**: OSI 1, 2계층에 해당.

- ***TCP와 UDP***:
  - **TCP (Transmission Control Protocol)**: 연결형 프로토콜. 3-way-handshake로 연결을 수립하며, 신뢰성 있는 데이터 전송을 보장.
  - **UDP (User Datagram Protocol)**: 비연결형 프로토콜. 신뢰성보다 속도가 중요할 때 사용 (DNS, VoIP 등).

- ***IP 주소***:
  - **IPv4**: 32비트 주소 체계. A, B, C, D 클래스로 구분.
  - **IPv6**: 128비트 주소 체계. IPv4 주소 고갈 문제 해결 및 보안 기능(IPsec) 강화.
  - **사설 IP 대역**: 내부 네트워크에서 사용하는 주소.
    - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

- ***주요 프로토콜***:
  - **ARP (Address Resolution Protocol)**: 논리적 주소(IP)를 물리적 주소(MAC)로 변환.
  - **ICMP (Internet Control Message Protocol)**: 네트워크 통신 중 발생하는 오류 메시지를 보고. (`ping`이 사용)
  - **DHCP (Dynamic Host Configuration Protocol)**: 네트워크 내의 클라이언트에게 IP 주소를 자동으로 할당.

---

### ***3. NOS (Network Operating System)***

- ***Windows Server***:
  - **Active Directory**: 사용자, 컴퓨터 등 네트워크 리소스를 관리하는 디렉터리 서비스.
  - **DNS 서버**: 도메인 이름을 IP 주소로 변환. 주요 레코드 타입(A, CNAME, MX, NS).
  - **DHCP 서버**: 클라이언트에게 IP 주소, 서브넷 마스크, 게이트웨이, DNS 서버 주소를 자동으로 할당.
  - **주요 명령어**:
    ```cmd
    ipconfig /all     :: 네트워크 설정 상세 확인
    nslookup [domain] :: DNS 질의
    ping [ip/domain]  :: 연결성 테스트
    ```

- ***Linux***:
  - **네트워크 설정 파일**:
    - `/etc/sysconfig/network-scripts/ifcfg-eth0`: 네트워크 인터페이스 설정.
    - `/etc/resolv.conf`: DNS 서버 주소 설정.
    - `/etc/hosts`: IP 주소와 호스트 이름 수동 매핑.
  - **주요 명령어**:
    ```bash
    ip addr show         :: (ifconfig 대체) IP 주소 확인
    netstat -anp         :: 네트워크 연결 상태 및 포트 확인
    route -n             :: 라우팅 테이블 확인
    systemctl status sshd :: 서비스 상태 확인 (systemd 기반)
    ```

---

### ***4. 네트워크 운용기기***

- ***계층별 장비***:
  - **리피터, 허브 (L1)**: 신호 증폭 및 분배.
  - **브리지, 스위치 (L2)**: MAC 주소를 기반으로 프레임 전달.
  - **라우터 (L3)**: IP 주소를 기반으로 다른 네트워크 간 패킷 경로 설정.
  - **게이트웨이 (L7)**: 프로토콜이 다른 두 네트워크를 연결.

- ***라우팅 프로토콜***:
  - **정적 라우팅 (Static)**: 관리자가 수동으로 경로를 설정.
  - **동적 라우팅 (Dynamic)**: 라우터끼리 정보를 교환하여 최적 경로를 자동으로 계산.
    - **내부 라우팅 (IGP)**: RIP, OSPF
    - **외부 라우팅 (EGP)**: BGP

- ***기본 라우터 명령어***:
  ```bash
  # 인터페이스 IP 설정
  Router(config)# interface GigabitEthernet0/0
  Router(config-if)# ip address 192.168.1.1 255.255.255.0
  Router(config-if)# no shutdown

  # 정적 라우트 추가
  Router(config)# ip route 10.0.0.0 255.0.0.0 192.168.1.2

  # 설정 확인
  Router# show ip route
  Router# show running-config
  ```

<hr class="short-rule">
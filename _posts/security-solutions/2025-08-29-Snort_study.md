---
layout: post
title: "Snort"
date: 2025-08-29 17:00:00 +0900
categories: [security-solutions]
---

## 1. 개요

**Snort**는 실시간 트래픽 분석과 패킷 로깅을 수행하는 전 세계에서 가장 널리 사용되는 오픈소스 네트워크 침입 탐지/방지 시스템(IDS/IPS)이다.
사전에 정의된 **룰(Rule/Signature)**을 기반으로 네트워크 패킷을 정밀하게 검사하여 공격 시도를 탐지하거나 차단한다. Cisco Talos 팀에 의해 지속적으로 업데이트된다.

### 핵심 기능
*   **패킷 스니퍼 (Sniffer)**: tcpdump처럼 네트워크 트래픽을 실시간으로 도청한다.
*   **패킷 로거 (Logger)**: 트래픽을 디스크에 로그 파일로 저장한다.
*   **네트워크 NIDS/NIPS**: 트래픽을 분석하여 공격을 탐지(Alert)하거나 차단(Block)한다.

### IDS vs IPS 비교
| 구분 | IDS (침입 탐지) | IPS (침입 방지) |
|---|---|---|
| **동작** | 공격 탐지 및 관리자 알림 | 공격 탐지 및 즉시 차단 |
| **구성 위치** | 스위치의 미러링 포트 (SPAN) | 트래픽이 통과하는 인라인 (Inline) |
| **영향** | 네트워크 성능 영향 적음 | 장애 시 네트워크 단절 위험 (Fail-Open/Close 고려) |

### 동작 아키텍처
```mermaid
flowchart LR
    Packet[트래픽 수신] --> Decoder[패킷 디코더<br>Protocol 분석]
    Decoder --> Preproc[전처리기<br>재조합/정규화]
    Preproc --> Engine[탐지 엔진<br>룰 매칭]
    Engine --> Output[출력 플러그인<br>로그/알림]
```

---

## 2. 설치 방법 (CentOS/Rocky Linux 기준)

Snort 3 최신 버전을 소스 코드로 컴파일하여 설치하는 과정이다.

### 1) 필수 의존성 설치
```bash
# 기본 도구 및 컴파일러 설치
dnf install -y epel-release git flex bison gcc gcc-c++ make cmake automake autoconf libtool

# Snort 의존성 라이브러리 설치 (OpenSSL, PCRE, dnet 등)
dnf install -y pcre-devel libdnet-devel hwloc-devel libmnl-devel luajit-devel openssl-devel \
    zlib-devel libnghttp2-devel libpcap-devel xz-devel uuid-devel
```

### 2) LibDAQ 설치 (Data Acquisition Library)
Snort가 패킷을 수집하기 위한 라이브러리다.
```bash
cd /usr/local/src
wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.13.tar.gz
tar xzf v3.0.13.tar.gz
cd libdaq-3.0.13
./bootstrap
./configure
make && make install
```

### 3) Snort 3 설치
```bash
cd /usr/local/src
wget https://github.com/snort3/snort3/archive/refs/tags/3.1.74.0.tar.gz
tar xzf 3.1.74.0.tar.gz
cd snort3-3.1.74.0

# 빌드 및 설치
./configure_cmake.sh --prefix=/usr/local/snort
cd build
make -j$(nproc)
make install
```

### 4) 환경 변수 설정
```bash
echo 'export PATH=$PATH:/usr/local/snort/bin' >> ~/.bashrc
echo '/usr/local/lib' > /etc/ld.so.conf.d/snort.conf
ldconfig
source ~/.bashrc

# 버전 확인
snort -V
```

---

## 3. Snort 룰(Rule) 문법

Snort의 강력함은 유연한 룰에서 나온다. 룰은 헤더(Header)와 옵션(Option)으로 구성된다.

### 기본 구조
```
[Action] [Proto] [SrcIP] [SrcPort] [Direction] [DstIP] [DstPort] ( [Option] )
```

*   **Action**: `alert`(알림), `block`(차단), `log`(기록), `pass`(무시)
*   **Proto**: `tcp`, `udp`, `icmp`, `ip`
*   **Direction**: `->` (단방향), `<>` (양방향)
*   **Option**: 탐지 세부 조건을 괄호 `()` 안에 정의

### 예시: 웹 서버(80)로의 모든 접속 탐지
```snort
alert tcp any any -> $HOME_NET 80 (msg:"HTTP Connection Detected"; sid:1000001; rev:1;)
```

### 주요 옵션 설명
| 옵션 | 설명 | 예시 |
|---|---|---|
| **msg** | 로그에 남길 메시지 | `msg:"SQL Injection Attack";` |
| **content** | 패킷 페이로드에서 찾을 문자열/패턴 | `content:"SELECT";` |
| **nocase** | 대소문자 구분 안 함 | `content:"admin"; nocase;` |
| **sid** | 룰 식별 ID (개별 룰은 1,000,000 이상 권장) | `sid:1000005;` |
| **rev** | 룰 수정 버전 (수정 시 증가시킴) | `rev:3;` |
| **classtype** | 공격 유형 분류 | `classtype:web-application-attack;` |

---

## 4. 실습: 공격 탐지 룰 작성

### 시나리오 1: SQL Injection 탐지
URL이나 Body에 `SELECT`, `UNION` 같은 키워드가 포함된 경우 탐지한다.
```snort
alert tcp any any -> $HOME_NET 80 (
    msg:"SQL Injection Attempt Detected";
    content:"SELECT", nocase;
    content:"FROM", nocase; 
    sid:1000010; rev:1;
    classtype:web-application-attack;
)

alert tcp any any -> $HOME_NET 80 (
    msg:"SQL Injection - Generic Logic Test";
    content:"' or 1=1"; nocase;
    sid:1000011; rev:1;
)
```

### 시나리오 2: Nmap 스캔 탐지
Nmap은 스캔 시 특정 패킷 패턴을 보인다. (예: 핑 없이 하는 TCP 스캔 등)
```snort
alert tcp any any -> $HOME_NET any (
    msg:"Nmap TCP Scan Detected";
    flags:S; 
    threshold:type both, track by_src, count 10, seconds 5;
    sid:1000020; rev:1;
)
```

### Snort 실행 및 테스트
#### 1. 설정 파일 유효성 검사
```bash
snort -c /usr/local/snort/etc/snort/snort.lua -T
```

#### 2. IDS 모드로 실행
콘솔에 경고를 출력(`-A alert_fast`)하며 실행한다.
```bash
snort -c /usr/local/snort/etc/snort/snort.lua -i eth0 -A alert_fast -l /var/log/snort
```

---

## 5. 트러블슈팅

### 실행 시 라이브러리 오류 (libdaq.so not found)
설치된 라이브러리 경로를 시스템이 인식하지 못하는 경우다.
```bash
# ldconfig 재실행
ldconfig

# 또는 환경변수 임시 지정
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### 트래픽이 탐지되지 않을 때
1.  **네트워크 인터페이스 이름**: `-i eth0` 옵션의 인터페이스 이름이 실제 장비와 맞는지 확인 (`ip addr`).
2.  **Home Net 설정**: `snort.lua` 파일에서 `HOME_NET` 변수가 보호하려는 대역으로 설정되어 있는지 확인.
3.  **Checksum 오류**: 가상환경에서는 Checksum Offloading 때문에 패킷이 버려질 수 있다. `-k none` 옵션으로 체크섬 검사를 끌 수 있다.

<hr class="short-rule">

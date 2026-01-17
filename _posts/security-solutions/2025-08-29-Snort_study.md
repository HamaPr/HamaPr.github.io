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

## 4. 탐지 룰 예시

### 웹 공격 탐지

#### SQL Injection
```snort
alert tcp any any -> $HOME_NET 80 (
    msg:"SQL Injection - SELECT FROM";
    content:"SELECT"; nocase;
    content:"FROM"; nocase; distance:0;
    sid:1000010; rev:1;
    classtype:web-application-attack;
)

alert tcp any any -> $HOME_NET 80 (
    msg:"SQL Injection - Logic Bypass";
    content:"' or '1'='1"; nocase;
    sid:1000011; rev:1;
)
```

#### XSS (Cross-Site Scripting)
```snort
alert tcp any any -> $HOME_NET 80 (
    msg:"XSS - Script Tag Detected";
    content:"<script"; nocase;
    sid:1000012; rev:1;
    classtype:web-application-attack;
)
```

#### Command Injection
```snort
alert tcp any any -> $HOME_NET 80 (
    msg:"Command Injection - Pipe Operator";
    content:"|"; 
    content:"/bin/"; distance:0;
    sid:1000013; rev:1;
)
```

#### Web Shell 탐지
```snort
alert tcp any any -> $HOME_NET 80 (
    msg:"Web Shell - PHP System Call";
    content:"system("; nocase;
    content:".php"; nocase;
    sid:1000014; rev:1;
    classtype:trojan-activity;
)
```

---

### 네트워크 스캔 탐지

#### Port Scan (SYN Flood)
```snort
alert tcp any any -> $HOME_NET any (
    msg:"Port Scan - Multiple SYN";
    flags:S;
    threshold:type both, track by_src, count 20, seconds 5;
    sid:1000020; rev:1;
    classtype:attempted-recon;
)
```

#### ICMP Sweep
```snort
alert icmp any any -> $HOME_NET any (
    msg:"ICMP Sweep Detected";
    itype:8;
    threshold:type both, track by_src, count 10, seconds 3;
    sid:1000021; rev:1;
)
```

---

### 인증 공격 탐지

#### SSH Brute Force
```snort
alert tcp any any -> $HOME_NET 22 (
    msg:"SSH Brute Force Attempt";
    flow:to_server,established;
    threshold:type both, track by_src, count 5, seconds 60;
    sid:1000030; rev:1;
    classtype:attempted-admin;
)
```

#### FTP Brute Force
```snort
alert tcp any any -> $HOME_NET 21 (
    msg:"FTP Login Failed - Brute Force";
    content:"530 "; depth:4;
    threshold:type both, track by_src, count 5, seconds 60;
    sid:1000031; rev:1;
)
```

---

### C2 통신 및 데이터 유출 탐지

#### DNS Tunneling
```snort
alert udp any any -> any 53 (
    msg:"DNS Tunneling - Long Subdomain";
    content:"|00 01 00 00|"; offset:4; depth:4;
    pcre:"/[a-z0-9]{50,}\./i";
    sid:1000040; rev:1;
    classtype:trojan-activity;
)
```

#### Reverse Shell (Bash)
```snort
alert tcp $HOME_NET any -> any any (
    msg:"Reverse Shell - Bash /dev/tcp";
    content:"/dev/tcp/"; nocase;
    sid:1000041; rev:1;
    classtype:trojan-activity;
)
```

---

## 5. APT 시그니처 작성 가이드

APT(Advanced Persistent Threat) 공격은 정교하고 지속적이므로, 단일 룰보다 여러 지표를 조합해야 한다.

### 작성 원칙

| 원칙 | 설명 |
|------|------|
| **다중 조건** | content 옵션을 여러 개 사용하여 오탐 감소 |
| **정규식 활용** | pcre 옵션으로 패턴 변형 대응 |
| **메타데이터** | reference, classtype으로 위협 인텔리전스 연동 |
| **Threshold** | 임계값 설정으로 알림 폭주 방지 |

### 예시: Cobalt Strike Beacon 탐지
```snort
alert tcp $HOME_NET any -> any any (
    msg:"APT - Cobalt Strike Beacon C2";
    flow:to_server,established;
    content:"|00 00 be ef|"; offset:0; depth:4;
    content:"HTTP/1."; distance:0;
    reference:url,attack.mitre.org/techniques/T1071;
    classtype:trojan-activity;
    sid:1000050; rev:1;
)
```

### 예시: Mimikatz 실행 탐지 (SMB)
```snort
alert tcp any any -> $HOME_NET 445 (
    msg:"APT - Mimikatz Pattern over SMB";
    content:"sekurlsa"; nocase;
    content:"logonpasswords"; nocase; distance:0;
    sid:1000051; rev:1;
    classtype:trojan-activity;
)
```

---

## 6. Snort 실행 및 테스트

### 설정 파일 유효성 검사
```bash
snort -c /usr/local/snort/etc/snort/snort.lua -T
```

### IDS 모드로 실행
콘솔에 경고를 출력(`-A alert_fast`)하며 실행한다.
```bash
snort -c /usr/local/snort/etc/snort/snort.lua -i eth0 -A alert_fast -l /var/log/snort
```

---

## 7. 트러블슈팅

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

---

## 8. 보안 고려사항

*   **룰 업데이트**: Snort 룰(시그니처)을 최신 상태로 유지해야 신종 공격을 탐지할 수 있다. Talos 공식 룰셋을 주기적으로 다운로드한다.
*   **IPS 모드 주의**: 인라인(IPS) 모드에서는 잘못된 룰이 정상 트래픽을 차단할 수 있다. 충분한 테스트 후 운영 환경에 적용한다.
*   **성능 튜닝**: 대용량 트래픽 환경에서는 패킷 손실이 발생할 수 있다. 멀티스레딩과 하드웨어 오프로드를 검토한다.
*   **로그 보안**: Snort 로그에는 민감한 네트워크 정보가 포함되므로, 로그 파일 접근 권한을 제한하고 중앙 로그 서버로 전송한다.

<hr class="short-rule">

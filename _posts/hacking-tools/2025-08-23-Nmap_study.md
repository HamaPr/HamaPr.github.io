---
layout: post
title: "Nmap (Network Mapper)"
date: 2025-08-23 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

**Nmap (Network Mapper)**은 네트워크 탐색과 보안 감사를 위해 사용하는 가장 강력하고 대중적인 오픈소스 스캐너이다.
패킷을 전송하고 응답을 분석하여 열려 있는 포트, 실행 중인 서비스, 운영체제 정보 등을 식별할 수 있어 침투 테스트의 정찰 단계에서 필수적으로 사용된다.
본 글에서는 Nmap의 핵심적인 스캔 옵션과 NSE(Nmap Scripting Engine)를 활용하여 취약점을 점검하는 방법을 다룬다.

---

## 2. 스캔 워크플로우

```mermaid
flowchart LR
    A[대상 IP] --> B[포트 스캔]
    B --> C[서비스 버전 확인]
    C --> D[NSE 취약점 스캔]
    D --> E[CVE 확인]
    E --> F[익스플로잇 선택]
```

---

## 3. 실습 환경

### Metasploitable 2
```bash
# 취약한 VM 다운로드 후 VirtualBox로 실행
# https://sourceforge.net/projects/metasploitable/
nmap -sV -sC 192.168.56.101
```

### Docker 기반
```bash
docker run -d -p 80:80 -p 22:22 vulnerables/web-dvwa
nmap -sV localhost
```

---

## 4. 주요 스캔 유형

#### 기본 TCP 스캔
가장 기본적인 스캔 방식으로, 대상 호스트와 3-way Handshake 연결을 시도하여 포트 개방 여부를 확인한다.

```bash
nmap 192.9.200.11
```

**결과**
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

#### 버전 스캔 (-sV)
기본 스캔에 더해 서비스의 배너 정보를 분석하여 구체적인 애플리케이션 버전을 확인한다.

```bash
nmap -sV 192.9.200.11
```

**결과**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```
![NmapsV](/assets/images/hacking-tools/Nmap_1.png)

버전 정보는 해당 서비스에 알려진 취약점(CVE)이 있는지 확인하는 데 결정적인 단서가 된다.

---

## 4. 주요 옵션 분석

*   **-sC (Script Scan)**: 기본 스크립트(`default` 카테고리)를 실행하여 더 많은 정보를 수집한다. `-sV`와 함께 `-sC -sV` 조합으로 자주 사용된다.
*   **-p [Ports]**: 특정 포트만 지정하여 스캔한다. (예: `-p 80,443`) 시간 단축을 위해 필수적이다.
*   **-p-**: 1번부터 65535번까지 모든 포트를 스캔한다. 전체적인 공격 표면을 확인할 때 사용하지만 시간이 오래 걸린다.
*   **-O**: 운영체제(OS) 추정을 시도한다. (단, 정확도가 100%는 아니다)

---

## 5. NSE 활용

Nmap Scripting Engine (NSE)은 Lua 언어로 작성된 스크립트를 통해 Nmap의 기능을 확장한다. 단순한 포트 스캔을 넘어 취약점 진단까지 가능하다.

### 취약점 스캔
`vuln` 카테고리의 스크립트를 사용하여 대상 서비스에 알려진 취약점이 존재하는지 점검한다.

```bash
nmap -sV --script=vuln 192.9.200.11
```
![Nmap2vuln](/assets/images/hacking-tools/Nmap_3.png)

결과에 CVE 번호와 `VULNERABLE` 상태가 출력된다면, 이는 즉각적인 조치가 필요한 보안 위협임을 의미한다.

---

## 6. 스텔스 스캔

실제 침투 테스트 환경에서는 방화벽이나 IDS가 스캔을 차단하거나 탐지할 수 있다. 다양한 옵션을 활용해 탐지를 우회한다.

### UDP 스캔 (-sU)
TCP 스캔만으로는 확인할 수 없는 UDP 서비스(DNS, SNMP, DHCP 등)를 점검한다. TCP보다 응답이 느리므로 주요 포트만 지정하는 것이 효율적이다.
```bash
nmap -sU -p 53,161,123 192.9.200.11
```

### 방화벽 우회 옵션
*   **-Pn (No Ping)**: ICMP 핑을 보내지 않고 바로 포트 스캔을 수행한다. 방화벽이 ICMP를 차단해 호스트가 "down"으로 보일 때 필수.
*   **-sA (ACK Scan)**: ACK 패킷만 보내 방화벽 설정(Stateful/Stateless) 여부를 확인한다. 포트 개방 여부가 아닌 **필터링 상태**를 탐지하는 데 유용하다.
*   **-f (Fragment Packets)**: 패킷을 작은 조각으로 분할하여 IDS의 시그니처 탐지를 우회한다.

```bash
# 핑 없이 스캔 (방화벽 ICMP 차단 시)
nmap -Pn -sS 192.9.200.11

# 패킷 분할 (IDS 우회)
nmap -f --mtu 16 192.9.200.11
```

### 스텔스 스캔 (-sS)
기본적으로 Nmap은 SYN 스캔(`-sS`)을 수행하며, 이는 완전한 TCP 연결(3-way handshake)을 맺지 않아 로그에 남기 어렵다. 단, 최신 보안 장비는 SYN 스캔도 탐지할 수 있다.

### 스캔 속도 조절 (-T)
IDS 탐지를 피하기 위해 스캔 속도를 낮출 수 있다.
| 옵션 | 이름 | 설명 |
|------|------|------|
| `-T0` | Paranoid | 매우 느림 (IDS 우회, 실전용) |
| `-T1` | Sneaky | 느림 |
| `-T3` | Normal | 기본값 |
| `-T4` | Aggressive | 빠름 (CTF/랩 환경) |

---

## 7. 방어 대책

### 탐지 방법
*   **IDS/IPS 룰**: Snort, Suricata에서 SYN 스캔 패턴 탐지
*   **방화벽 로그**: 짧은 시간 내 다수 포트 연결 시도 모니터링
*   **Rate Limiting**: 동일 IP의 연속 연결 시도 제한

### 방어 방법
*   **불필요한 포트 닫기**: 사용하지 않는 서비스 비활성화
*   **방화벽 규칙**: 화이트리스트 기반 접근 제어
*   **배너 그랩 방지**: 서비스 버전 정보 숨기기
    ```bash
    # Apache 버전 숨기기 (httpd.conf)
    ServerTokens Prod
    ServerSignature Off
    ```

---

## MITRE ATT&CK 매핑

| Nmap 기능 | ATT&CK 기법 | ID | 단계 |
|-----------|------------|-----|------|
| 포트 스캔 (`-sS`, `-sT`) | Network Service Discovery | T1046 | Discovery |
| 서비스 버전 탐지 (`-sV`) | Network Service Discovery | T1046 | Discovery |
| OS 탐지 (`-O`) | System Information Discovery | T1082 | Discovery |
| NSE 취약점 스캔 (`--script vuln`) | Vulnerability Scanning | T1595.002 | Reconnaissance |
| 호스트 탐색 (`-sn`) | Remote System Discovery | T1018 | Discovery |

<hr class="short-rule">
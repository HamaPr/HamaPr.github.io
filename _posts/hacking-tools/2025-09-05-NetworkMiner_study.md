---
layout: post
title: "NetworkMiner"
date: 2025-09-05 18:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

**NetworkMiner**는 네트워크 트래픽(PCAP)을 수동적(Passive)으로 분석하여 OS 핑거프린팅, 파일 추출, 자격 증명 등을 수행하는 포렌식 도구이다.
패킷 스트림을 재조합하여 전송된 파일과 이미지를 원본 형태로 복원하는 데 특화되어 있다.

### 기본 정보

| 항목 | 설명 |
|------|------|
| 유형 | 네트워크 포렌식 도구 |
| 입력 | PCAP, PCAPNG |
| 출력 | 파일, 이미지, 세션 정보 |

### Wireshark와 비교

| 기능 | NetworkMiner | Wireshark |
|------|--------------|-----------|
| **파일 추출** | **자동 (매우 강력)** | 수동 (Export Objects) |
| **호스트 식별** | OS, 포트 등 자동 프로파일링 | IP 기반 패킷 나열 |
| **자격 증명** | 평문 (ID/PW) 자동 탐지 | 문자열 검색 필요 |
| **실시간 캡처** | 제한적 (무료 버전 불가) | 강력함 |

```mermaid
flowchart LR
    A[PCAP 파일] --> B[NetworkMiner 로드]
    B --> C[호스트 프로파일링]
    C --> D[파일 추출]
    D --> E[자격 증명 탐지]
```

---

## 2. 설치 방법

### Windows
공식 사이트에서 다운로드 후 실행만 하면 된다. 별도 설치 과정이 없다.

1.  [Netresec 공식 사이트](https://www.netresec.com/?page=NetworkMiner)에서 Free Edition 다운로드
2.  ZIP 압축 해제 후 `NetworkMiner.exe` 실행

### 리눅스 설치
Windows 프로그램이므로 리눅스에서는 `.NET` 호환 계층인 `Mono`가 필요하다.

```bash
# 1. Mono 설치
sudo apt install mono-complete

# 2. NetworkMiner 다운로드
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip

# 3. 압축 해제 및 실행 권한 부여
unzip NetworkMiner.zip
cd NetworkMiner_*
chmod +x NetworkMiner.exe

# 4. 실행
mono NetworkMiner.exe
```

---

## 3. 주요 기능 및 탭 구성

PCAP 파일을 로드(`File` -> `Open`)하면 자동으로 분석이 수행되며, 결과는 상단 탭에 분류된다.

| 탭 | 설명 | 활용 포인트 |
|----|------|-------------|
| **Hosts** | 통신한 호스트 목록 | OS, MAC 주소, 열린 포트 확인 |
| **Files** | 추출된 파일 목록 | 웹쉘, 악성코드, 문서 파일 확보 |
| **Images** | 추출된 이미지 | 음란물, 문서 캡처, 스테가노그래피 확인 |
| **Credentials** | 자격 증명 정보 | HTTP, FTP, IMAP 등의 평문 계정 정보 |
| **Sessions** | 세션 정보 | 통신 방향, 포트, 지속 시간 분석 |
| **DNS** | DNS 쿼리 | 악성 도메인(C2) 통신 확인 |

### 자동 추출 결과 구조
추출된 파일은 NetworkMiner 폴더 내 `AssembledFiles` 디렉터리에 IP 별로 자동 저장된다.
```
AssembledFiles/
├── 192.168.1.100/
│   ├── 80-index.html
│   └── 80-logo.png
└── 10.0.0.1/
    └── 21-malware.exe
```

---

## 4. 실습 환경

### 샘플 PCAP 다운로드
다양한 프로토콜 분석 실습을 위해 공개된 PCAP 파일을 다운로드한다.
*   **Netresec Public PCAP**: https://www.netresec.com/?page=PcapFiles
*   **Wireshark Sample Captures**: `http.cap`, `telnet.cap` 등
*   **Malware Traffic Analysis**: 실제 악성코드 통신 패킷 분석 ([링크](https://www.malware-traffic-analysis.net/))

### 로컬 트래픽 캡처
NetworkMiner 무료 버전은 실시간 캡처 기능에 제한이 있으므로, Wireshark나 Tcpdump로 캡처한 파일을 로드하는 것이 좋다.

---

## 5. 실습: 패킷 분석

웹 트래픽에 포함된 계정 정보와 파일을 추출하는 실습이다.

### 1. 실습 데이터 준비
테스트용 PCAP 파일을 다운로드한다.
```bash
wget https://raw.githubusercontent.com/packetrat/packethunting/master/HTTP-password.pcap -O web_traffic.pcap
```

### 2. 분석 수행
1.  **파일 로드**: NetworkMiner에서 `web_traffic.pcap` 파일을 연다.
2.  **Credentials 탭**: 평문으로 전송된 **로그인 정보(ID/Password)**가 자동으로 추출된 것을 확인한다.
3.  **Files 탭**: 전송된 HTML, 이미지, 압축 파일 등을 확인하고 우클릭해서 원본 파일을 저장한다.
4.  **Hosts 탭**: 통신 주체의 IP를 클릭하여 운영체제 정보와 열린 포트를 확인한다.

![NetworkMiner Files 탭](/assets/images/hacking-tools/NetworkMiner.png)

---

## 6. CTF 활용 팁

해킹 대회(CTF)의 포렌식 문제에서 NetworkMiner는 다음과 같이 활용된다.

*   **숨겨진 파일 찾기**: `Files` 탭을 이용해 전송된 모든 파일을 한눈에 확인하고, Hex Editor로 분석한다.
*   **Flag 추출**: HTTP POST 데이터, FTP 전송 파일, DNS TXT 레코드 등에 숨겨진 Flag를 찾는다.
*   **이미지 분석**: `Images` 탭에서 깨진 이미지나 스테가노그래피가 의심되는 이미지를 식별한다.

---

## 7. 트러블슈팅

### 파일이 추출되지 않는 경우
*   **HTTPS 트래픽**: 암호화된 트래픽(TLS)은 복호화 키가 없으면 내용을 볼 수 없으므로 파일 추출이 불가능하다.
*   **패킷 손실**: 캡처 도중 패킷이 유실되어 TCP 스트림이 깨진 경우 파일이 온전하게 복원되지 않을 수 있다.

### 대용량 PCAP 처리
*   무료 버전은 메모리 제한이 있어 대용량 파일 로드 시 멈출 수 있다. 이 경우 `editcap` 등으로 파일을 쪼개서 분석해야 한다.
    ```bash
    editcap -c 100000 large.pcap split.pcap
    ```

---

## 8. 방어 대책 (패킷 분석 대응)

### 패킷 보호
*   **전송 구간 암호화**: HTTPS(TLS 1.3) 사용 시 NetworkMiner가 내용을 복원하거나 파일을 추출할 수 없다.
*   **VPN 사용**: 터널링을 통해 패킷 헤더와 페이로드를 숨긴다.

### 데이터 유출 방지 (DLP)
*   **네트워크 DRM**: 중요 파일이 외부로 전송될 때 암호화되거나 차단되도록 한다.
*   **스테가노그래피 탐지**: 이미지 파일 등에 숨겨진 데이터가 있는지 주기적으로 점검한다.

<hr class="short-rule">

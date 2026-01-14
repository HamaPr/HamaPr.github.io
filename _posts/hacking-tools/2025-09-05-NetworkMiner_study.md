---
layout: post
title: "NetworkMiner 패킷 분석"
date: 2025-09-05 18:00:00 +0900
categories: [hacking-tools]
---

## 1. 개념

**NetworkMiner**는 네트워크 트래픽을 수동적(Passive)으로 분석하여 OS 핑거프린팅, 파일 추출, 자격 증명 등을 수행하는 포렌식 도구입니다.
패킷 스트림을 재조합하여 전송된 파일과 이미지를 원본 형태로 복원하는 데 특화되어 있습니다.

### 기본 정보

| 항목 | 설명 |
|------|------|
| 유형 | 네트워크 포렌식 |
| 입력 | PCAP, PCAPNG |
| 출력 | 파일, 이미지, 세션 |
| 버전 | Free / Professional |

### Wireshark와 비교

| 기능 | NetworkMiner | Wireshark |
|------|--------------|-----------|
| 파일 추출 | 자동 | 수동 (Export) |
| 호스트 프로파일 | ✅ | ❌ |
| 자격 증명 탐지 | ✅ | 수동 필터 |
| 실시간 캡처 | ❌ (Free) | ✅ |

---

## 2. 설치 방법

### Windows
1. https://www.netresec.com/?page=NetworkMiner 다운로드
2. ZIP 압축 해제
3. NetworkMiner.exe 실행

### Linux (Mono)
```bash
# Mono 설치
sudo apt install mono-complete

# NetworkMiner 다운로드 및 실행
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip
unzip NetworkMiner.zip
cd NetworkMiner_*
chmod +x NetworkMiner.exe
mono NetworkMiner.exe
```

---

## 3. 주요 기능

### 패킷 로드
```
File → Open → PCAP/PCAPNG 파일 선택
```

### 탭별 기능

| 탭 | 설명 |
|----|------|
| Hosts | 통신한 호스트 목록 |
| Files | 추출된 파일 (이미지, 문서 등) |
| Images | 추출된 이미지 미리보기 |
| Credentials | HTTP, FTP 자격 증명 |
| Sessions | TCP/UDP 세션 |
| DNS | DNS 쿼리/응답 |

### 자동 추출 결과
```
AssembledFiles/
├── 192.168.1.100/
│   ├── 80-index.html
│   └── 80-logo.png
└── 10.0.0.1/
    └── 21-file.zip
```

---

## 4. 실습 예시

### 실습용 PCAP 다운로드
웹 트래픽 분석 실습을 위해 계정 정보가 포함된 샘플 PCAP 파일을 다운로드합니다.
```bash
wget https://raw.githubusercontent.com/packetrat/packethunting/master/HTTP-password.pcap -O web_traffic.pcap
```

### 웹 트래픽 분석
1. PCAP 파일 로드
2. **Files** 탭에서 다운로드된 파일 확인
3. **Images** 탭에서 이미지 확인
4. **Credentials** 탭에서 평문 로그인 정보 탐지

### DNS 분석
1. **DNS** 탭 선택
2. 의심스러운 도메인 쿼리 확인
3. C2 서버 통신 패턴 파악

### 호스트 프로파일링
1. **Hosts** 탭 선택
2. IP 주소 클릭
3. OS 핑거프린팅, MAC 주소, 오픈 포트 확인

---

## 5. CTF 활용

### 숨겨진 파일 찾기
1. PCAP 로드
2. Files 탭에서 전송된 파일 확인
3. 파일 헤더 분석 (HxD 등)

### Flag 추출
```
자주 나오는 형식:
- HTTP POST 데이터
- FTP 전송 파일
- DNS TXT 레코드
- 이미지 내 스테가노그래피
```

![NetworkMiner Files 탭](/assets/images/hacking-tools/NetworkMiner.png)

---

## 6. 트러블슈팅

### 파일 추출 안됨
- 암호화된 트래픽 (HTTPS)은 추출 불가
- 불완전한 세션 (패킷 손실)

### 대용량 PCAP
- 메모리 부족 시 분할 처리
- `editcap -c 100000 large.pcap split.pcap`

<hr class="short-rule">

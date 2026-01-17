---
layout: post
title: "Bash Script"
date: 2025-06-20 17:00:00 +0900
categories: [linux]
---

## 1. 개요

**Bash 스크립트**를 활용하면 대량의 사용자 계정을 생성하거나 수정, 삭제하는 지루한 반복 작업을 자동화할 수 있다.
수십, 수백 명의 신입 사원 계정을 일일이 명령어로 생성하는 대신, 스크립트 하나로 CSV 파일이나 텍스트 파일의 명단을 읽어 빠르고 정확하게 처리한다.

### 주요 활용 시나리오
*   **일괄 생성**: 신규 프로젝트 팀원 50명의 계정 생성 및 초기 비밀번호 설정
*   **일괄 삭제**: 퇴사자 명단을 읽어 계정 비활성화 및 홈 디렉터리 백업
*   **보안 정책 적용**: 전체 사용자의 비밀번호 만료일 설정 및 강제 변경 요구 (`chage`)

---

## 2. 사용법 (핵심 명령어)

스크립트 작성 전, 개별 명령어를 이해해야 한다.

### 기초 명령어
```bash
# 사용자 생성 (홈 디렉터리 생성 및 쉘 지정)
useradd -m -s /bin/bash username

# 비밀번호 설정 (비대화형)
echo "username:password123" | chpasswd

# 계정 관리 (비밀번호 만료일 설정 등)
chage -M 90 -W 7 username  # 90일 만료, 7일 전 경고

# 사용자 삭제 (홈 디렉터리 포함)
userdel -r username
```

---

## 3. 실습: 스크립트 작성

### 시나리오: 텍스트 파일 기반 일괄 생성
`users.txt` 파일에 `아이디:비밀번호` 형식으로 저장된 목록을 읽어 계정을 생성한다.

**입력 파일 (users.txt)**:
```text
user01:Pass123!
user02:Pass123!
user03:Pass123!
```

**스크립트 (create_users.sh)**:
```bash
#!/bin/bash

USER_FILE="users.txt"

# 파일 존재 여부 확인
if [ ! -f "$USER_FILE" ]; then
    echo "Error: $USER_FILE not found."
    exit 1
fi

# 파일의 각 줄을 읽어 루프 실행
while IFS=':' read -r username password; do
    # 이미 존재하는 사용자인지 확인
    if id "$username" &>/dev/null; then
        echo "[SKIP] User $username already exists."
        continue
    fi

    # 사용자 생성
    useradd -m -s /bin/bash "$username"
    
    # 비밀번호 설정
    echo "$username:$password" | chpasswd
    
    # 첫 로그인 시 비밀번호 변경 강제
    chage -d 0 "$username"
    
    echo "[OK] User $username created."
    
done < "$USER_FILE"
```

### 시나리오: 비활성 사용자 일괄 잠금
마지막 로그인 후 90일 이상 지난 사용자를 찾아 계정을 잠근다.

**스크립트 (lock_inactive.sh)**:
```bash
#!/bin/bash

INACTIVE_DAYS=90
TODAY=$(date +%s)

# lastlog 명령어로 모든 사용자 조회
lastlog -b $INACTIVE_DAYS | tail -n +2 | awk '{print $1}' | while read user; do
    # 시스템 계정(UID 1000 미만)은 제외
    UID_NUM=$(id -u "$user")
    if [ "$UID_NUM" -ge 1000 ]; then
        echo "Locking inactive user: $user"
        usermod -L "$user"
    fi
done
```

![스크립트 실행 결과](/assets/images/linux/BashScript.png)

---

## 4. 트러블슈팅

### 권한 오류
스크립트 실행 시 `Permission denied` 오류가 발생하면 두 가지를 확인한다.
1.  **실행 권한**: 스크립트 파일에 실행 권한(`x`)이 있는지 확인한다.
    ```bash
    chmod +x create_users.sh
    ```
2.  **루트 권한**: 사용자 생성(`useradd`) 등의 명령어는 root 권한이 필요하므로 `sudo`로 실행한다.
    ```bash
    sudo ./create_users.sh
    ```

### 개행 문자 문제 (Windows -> Linux)
윈도우에서 작성한 텍스트 파일을 리눅스로 가져오면 개행 문자(`\r\n`) 문제로 오류가 발생할 수 있다.
`dos2unix` 명령어로 변환하거나 `sed`를 사용한다.
```bash
sed -i 's/\r//' users.txt
```

---

## 5. 보안 고려사항

*   **민감 정보 하드코딩 금지**: 스크립트에 비밀번호를 직접 작성하지 않는다. 환경 변수나 별도의 암호화된 파일에서 읽어오도록 구현한다.
*   **입력값 검증**: 사용자 입력을 그대로 명령어에 사용하면 명령어 인젝션 공격에 취약해진다. 변수를 따옴표(`"$var"`)로 감싸고 입력값을 검증한다.
*   **`set -euo pipefail` 사용**: 스크립트 상단에 이 옵션을 추가하여 오류 발생 시 즉시 중단하고, 정의되지 않은 변수 사용 시 에러를 발생시킨다.
*   **스크립트 권한 관리**: 실행 스크립트는 소유자만 수정할 수 있도록 권한을 `750` 또는 `700`으로 제한한다.

<hr class="short-rule">

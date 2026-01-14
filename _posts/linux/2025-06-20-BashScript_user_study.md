---
layout: post
title: "Bash 스크립트 사용자 관리"
date: 2025-06-20 17:00:00 +0900
categories: [linux]
---

## 1. 개념

**Bash 스크립트**는 쉘 명령어를 순차적으로 실행하여 시스템 관리 작업을 자동화하는 스크립트입니다.
사용자 관리와 같이 반복적이고 대량의 처리가 필요한 작업을 효율적으로 수행할 때 사용합니다.

### 활용 사례
- 신입 사원 일괄 계정 생성
- 퇴사자 계정 자동 비활성화
- 비밀번호 정책 적용
- 그룹 멤버십 관리

### 관련 명령어
| 명령어 | 설명 |
|--------|------|
| `useradd` | 사용자 생성 |
| `usermod` | 사용자 수정 |
| `userdel` | 사용자 삭제 |
| `passwd` | 비밀번호 설정 |
| `chage` | 비밀번호 정책 |
| `groupadd` | 그룹 생성 |

---

## 2. 사용법

### 사용자 생성 기본
```bash
# 기본 사용자 생성
useradd username

# 홈 디렉터리 생성 + 쉘 지정
useradd -m -s /bin/bash username

# 그룹 지정하여 생성
useradd -m -g users -G wheel,docker username

# 만료일 설정
useradd -m -e 2025-12-31 username
```

### 비밀번호 설정
```bash
# 대화형
passwd username

# 한 줄로 비밀번호 설정
echo "username:password" | chpasswd

# 비밀번호 정책 설정
chage -M 90 -W 7 -I 30 username
# -M: 최대 사용 기간
# -W: 만료 경고 일
# -I: 비활성화 기간
```

---

## 3. 스크립트 예제

### 일괄 사용자 생성

`create_users.sh`:
```bash
#!/bin/bash
# 사용자 목록 파일에서 일괄 생성

USER_FILE="users.txt"
DEFAULT_GROUP="users"
DEFAULT_SHELL="/bin/bash"

if [[ ! -f "$USER_FILE" ]]; then
    echo "Error: $USER_FILE not found!"
    exit 1
fi

while IFS=: read -r username password; do
    # 공백 라인 건너뛰기
    [[ -z "$username" ]] && continue
    
    # 사용자 존재 확인
    if id "$username" &>/dev/null; then
        echo "User $username already exists, skipping..."
        continue
    fi
    
    # 사용자 생성
    useradd -m -g "$DEFAULT_GROUP" -s "$DEFAULT_SHELL" "$username"
    
    # 비밀번호 설정
    echo "$username:$password" | chpasswd
    
    # 첫 로그인 시 비밀번호 변경 강제
    chage -d 0 "$username"
    
    echo "Created user: $username"
done < "$USER_FILE"

echo "User creation completed!"
```

`users.txt` 형식:
```
user1:P@ssw0rd_01!
user2:P@ssw0rd_02!
user3:P@ssw0rd_03!
```

### 실행
```bash
chmod +x create_users.sh
./create_users.sh
```

### 사용자 삭제 스크립트

`delete_users.sh`:
```bash
#!/bin/bash
# 사용자 목록 파일에서 일괄 삭제

USER_FILE="delete_users.txt"

while read -r username; do
    [[ -z "$username" ]] && continue
    
    if ! id "$username" &>/dev/null; then
        echo "User $username does not exist, skipping..."
        continue
    fi
    
    # 홈 디렉터리 백업
    tar -czvf "/backup/${username}_home.tar.gz" "/home/$username" 2>/dev/null
    
    # 사용자 삭제 (홈 디렉터리 포함)
    userdel -r "$username"
    
    echo "Deleted user: $username"
done < "$USER_FILE"
```

---

## 4. 실습 예시

### CSV에서 사용자 생성

`create_from_csv.sh`:
```bash
#!/bin/bash
# CSV: username,fullname,department,email

CSV_FILE="employees.csv"

# 첫 줄(헤더) 건너뛰기
tail -n +2 "$CSV_FILE" | while IFS=, read -r username fullname dept email; do
    # 그룹 생성 (없으면)
    groupadd "$dept" 2>/dev/null
    
    # 사용자 생성
    useradd -m -g "$dept" -c "$fullname" "$username"
    
    # 초기 비밀번호 (사원번호 기반)
    echo "$username:Welcome123!" | chpasswd
    
    # 강제 비밀번호 변경
    chage -d 0 "$username"
    
    echo "Created: $username ($fullname) - $dept"
done
```

### 비활성 사용자 잠금

`lock_inactive.sh`:
```bash
#!/bin/bash
# 90일 이상 로그인하지 않은 사용자 잠금

INACTIVE_DAYS=90

for user in $(lastlog -b $INACTIVE_DAYS | awk 'NR>1 {print $1}'); do
    # 시스템 계정 제외
    uid=$(id -u "$user" 2>/dev/null)
    [[ $uid -lt 1000 ]] && continue
    
    echo "Locking inactive user: $user"
    usermod -L "$user"
done
```

![스크립트 실행 결과](/assets/images/linux/BashScript.png)

---

## 5. 트러블슈팅

### 권한 오류
```bash
# root 권한으로 실행
sudo ./create_users.sh

# 또는 sudoers에 등록
```

# useradd 전 그룹 확인 (users 그룹은 기본 존재)
grep users /etc/group

### 로그 기록
```bash
# 스크립트에 로깅 추가
exec > >(tee -a /var/log/user_management.log) 2>&1
echo "[$(date)] Script started"
```

<hr class="short-rule">

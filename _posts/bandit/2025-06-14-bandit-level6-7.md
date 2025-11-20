---
layout: post
title: "[Bandit] Level 6 → 7 풀이"
date: 2025-06-14 09:02:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux]
---

> 📝 **공식 문제 (Level 6 → 7)**
>
> **Level Goal**
> The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit6`
  - 비밀번호: `HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`
  
- **접속 명령어**

  ```bash
ssh bandit6@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `find` 명령어로 `/` (최상위 경로)부터 조건에 맞는 파일 검색
2.  조건: 소유자 `bandit7`, 그룹 `bandit6`, 크기 33바이트
3.  권한 문제로 발생하는 오류 메시지는 `2>/dev/null`로 숨김 처리
4.  검색된 파일의 내용을 `cat`으로 출력

```bash
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
```

</details>

---

## 💡 배운 점

1. `find` 명령어의 소유자/그룹 검색 옵션: `-user`, `-group`
2. `2>/dev/null`: 명령어 실행 시 발생하는 오류 메시지(stderr)를 버려서 결과만 깔끔하게 볼 수 있음.

<hr class="short-rule">
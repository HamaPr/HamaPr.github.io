---
layout: post
title: "[Bandit] Level 5 → 6 풀이"
date: 2025-06-14 09:01:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux]
---

> 📝 **공식 문제 (Level 5 → 6)**
>
> **Level Goal**
> The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit5`
  - 비밀번호: `4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`
  
- **접속 명령어**

  ```bash
ssh bandit5@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `find` 명령어로 여러 조건을 조합하여 파일 검색
2.  조건: `inhere` 디렉토리 내부, 일반 파일(`-type f`), 1033바이트 크기(`-size 1033c`), 실행 불가능(`! -executable`)
3.  검색된 파일의 내용을 `cat`으로 출력

```bash
bandit5@bandit:~$ find inhere -type f -size 1033c ! -executable
inhere/maybehere07/.file2
bandit5@bandit:~$ cat inhere/maybehere07/.file2
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
```

</details>

---

## 💡 배운 점

1. find 명령어의 다양한 옵션 활용법
  .: 현재 디렉토리부터 검색
  -type f: 파일 타입만 검색
  -size 1033c: 크기가 정확히 1033 바이트인 파일 검색
  ! -executable: 실행 가능하지 않은 파일 검색

<hr class="short-rule">
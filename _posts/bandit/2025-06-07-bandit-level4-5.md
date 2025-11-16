---
layout: post
title: "[Bandit] Level 4 → 5 풀이"
date: 2025-06-07 09:05:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux]
---

> 📝 **공식 문제 (Level 4 → 5)**
>
> **Level Goal**
> The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit4`
  - 비밀번호: `2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`
  
- **접속 명령어**

  ```bash
ssh bandit4@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `inhere` 디렉토리로 이동
2.  `file *` 명령어로 모든 파일의 종류를 확인
3.  `ASCII text` 타입으로 확인된 사람이 읽을 수 있는 파일의 내용을 출력

```bash
bandit4@bandit:~$ cd inhere
bandit4@bandit:~/inhere$ file *
-file00: data
-file01: data
-file02: data
-file03: data
-file04: data
-file05: data
-file06: data
-file07: ASCII text
-file08: data
-file09: data
bandit4@bandit:~/inhere$ cat ./-file07
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```

</details>

---

## 💡 배운 점

1. `file` 명령어는 파일의 종류(타입)를 식별하는 데 사용됨.
2. `*` (와일드카드)는 현재 디렉토리의 모든 파일을 의미함.

<hr class="short-rule">
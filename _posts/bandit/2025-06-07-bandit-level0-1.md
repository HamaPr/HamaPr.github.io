---
layout: post
title: "[Bandit] Level 0 → 1 풀이"
date: 2025-06-07 09:01:00 +0900
categories: [bandit]
tags: [overthewire, bandit, ssh]
---

> 📝 **공식 문제 (Level 0 → 1)**
>
> **Level Goal**
> The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`

---

## 🔐 Level Info

- **접속 정보**
  - 호스트: `bandit.labs.overthewire.org`
  - 포트: `2220`
  - 사용자: `bandit0`
  - 비밀번호 : `bandit0`

- **접속 명령어**

  ```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `readme` 파일의 내용을 `cat` 명령어로 확인

```bash
bandit0@bandit:~$ cat readme
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
```

</details>

---

## 💡 배운 점

1. 리눅스 기본 명령어: cat (파일 내용 출력)

<hr class="short-rule">
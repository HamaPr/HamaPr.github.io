---
layout: post
title: "[Bandit] Level 1 → 2 풀이"
date: 2025-06-07 09:02:00 +0900
categories: [bandit]
tags: [overthewire, bandit, ssh, special-character]
---

> 📝 **공식 문제 (Level 1 → 2)**
>
> **Level Goal**
> The password for the next level is stored in a file called - located in the home directory.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`
>
> **Helpful Reading Material**
> - [Google Search for “dashed filename”](https://www.google.com/search?q=dashed+filename)
> - [Advanced Bash-scripting Guide - Chapter 3 - Special Characters](https://tldp.org/LDP/abs/html/special-chars.html)

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit1`
  - 비밀번호: `ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

- **접속 명령어**

  ```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `ls` 명령어로 현재 디렉토리의 파일 목록 확인
2.  `-` 라는 이름의 파일 발견
3.  `cat`으로 `-` 파일을 직접 열려고 하면 옵션으로 인식되어 오류 발생
4.  `./-` 와 같이 현재 경로를 명시하여 파일임을 알려준 뒤 내용 확인

```bash
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat ./-
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
```

</details>

---

## 💡 배운 점

1. 파일 이름이 - 와 같은 특수 문자로 시작할 경우 ./ 를 앞에 붙여 현재 디렉토리의 파일임을 명시

<hr class="short-rule">
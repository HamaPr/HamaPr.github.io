---
layout: post
title: "[Bandit] Level 2 → 3 풀이"
date: 2025-06-07 09:03:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux]
---

> 📝 **공식 문제 (Level 2 → 3)**
>
> **Level Goal**
> The password for the next level is stored in a file called spaces in this filename located in the home directory.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`
>
> **Helpful Reading Material**
> - [Google Search for “spaces in filename”](https://www.google.com/search?q=spaces+in+filename)

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit2`
  - 비밀번호: `263JGJPfgU6LtdEvgfWU1XP5yac29mFx`
  
- **접속 명령어**

  ```bash
ssh bandit2@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `ls`로 `spaces in this filename`이라는 이름의 파일 발견
2.  파일 이름에 공백이 포함되어 있어 그대로 입력하면 여러 개의 인자로 인식됨
3.  큰따옴표(`"`)로 파일 이름 전체를 감싸서 하나의 인자로 인식시켜 내용 확인

```bash
bandit2@bandit:~$ ls -l
total 4
-rw-r----- 1 bandit3 bandit2 15 May  7  2020 spaces in this filename
bandit2@bandit:~$ cat "spaces in this filename"
```

## 🧪 다른 풀이 방법
1.  각 공백 문자 앞에 역슬래시(\)를 사용하여 해당 공백이 일반 문자임을 쉘에게 알려줌

```bash
bandit2@bandit:~$ cat spaces\ in\ this\ filename
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```

</details>

---

## 💡 배운 점

1. 파일 이름에 공백이 있을 경우 큰따옴표("...")나 작은따옴표('...')로 감싸거나 각 공백 앞에 역슬래시(\)를 붙여 처리할 수 있다.

<hr class="short-rule">
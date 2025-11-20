---
layout: post
title: "[Bandit] Level 7 → 8 풀이"
date: 2025-06-14 09:03:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux]
---

> 📝 **공식 문제 (Level 7 → 8)**
>
> **Level Goal**
> The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit7`
  - 비밀번호: `morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`
  
- **접속 명령어**

  ```bash
ssh bandit7@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `grep` 명령어로 `data.txt` 파일에서 `millionth` 단어가 포함된 줄 검색

```bash
bandit7@bandit:~$ grep millionth data.txt
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```

</details>

---

## 💡 배운 점

1. `grep [패턴] [파일명]`: 파일 안에서 특정 패턴(문자열)이 포함된 줄을 찾아 출력함.

<hr class="short-rule">
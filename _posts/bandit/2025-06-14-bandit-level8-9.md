---
layout: post
title: "[Bandit] Level 8 → 9 풀이"
date: 2025-06-14 09:04:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux]
---

> 📝 **공식 문제 (Level 8 → 9)**
>
> **Level Goal**
> The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit8`
  - 비밀번호: `dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`
  
- **접속 명령어**

  ```bash
ssh bandit8@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `sort` 명령어로 `data.txt` 파일의 내용을 정렬
2.  `|` (파이프)를 사용해 정렬된 결과를 `uniq` 명령어의 입력으로 전달
3.  `uniq -u` 옵션으로 유일한 줄만 필터링

```bash
bandit8@bandit:~$ sort data.txt | uniq -u
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
```

</details>

---

## 💡 배운 점

1. | (파이프): 한 명령어의 출력 결과를 다음 명령어의 입력으로 연결함.
2. sort: 텍스트 데이터를 정렬함.
3. uniq -u: 정렬된 데이터에서 중복되지 않고 한 번만 나타나는 줄만 출력함.

<hr class="short-rule">
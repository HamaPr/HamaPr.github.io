---
layout: post
title: "[Bandit] Level 3 → 4 풀이"
date: 2025-06-07 09:04:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux]
---

> 📝 **공식 문제 (Level 3 → 4)**
>
> **Level Goal**
> The password for the next level is stored in a hidden file in the inhere directory.
>
> **Commands you may need to solve this level**
> `ls`, `cd`, `cat`, `file`, `du`, `find`

---

## 🔐 Level Info

- **접속 정보**
  - 사용자: `bandit3`
  - 비밀번호: `MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

- **접속 명령어**

  ```bash
ssh bandit3@bandit.labs.overthewire.org -p 2220
  ```

---

## 🧪 풀이 과정

1.  `inhere` 디렉토리로 이동
2.  `ls -a` 명령어로 숨겨진 파일을 포함한 모든 항목 확인
3.  `.hidden` 파일 발견 후 내용 출력

```bash
bandit3@bandit:~$ cd inhere
bandit3@bandit:~/inhere$ ls -a
.  ..  .hidden
bandit3@bandit:~/inhere$ cat .hidden
```

---

## 🎯 결과

<details markdown="1">
<summary>👀 클릭하여 비밀번호 확인하기</summary>

```
2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
```

</details>

---

## 💡 배운 점

1. 리눅스에서 .으로 시작하는 파일/디렉토리는 숨김 처리됨.
2. ls -a 옵션으로 숨겨진 항목을 확인할 수 있음.

<hr class="short-rule">
---
layout: post
title: "[Bandit] Level 1 → Level 2"
date: 2025-06-07 09:02:00 +0900
categories: [bandit]
tags: [overthewire, bandit, ssh, special-character]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in a file called `-` located in the home directory.


파일명이 **`-`** 문자 하나로만 되어 있어 읽기가 까다롭습니다. 리눅스 쉘에서 `-`는 **표준 입력**이라는 특수한 의미로 해석되기 때문에, 이를 파일명으로 정확히 인식시키는 방법을 알아야 합니다.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `cat ./-` | `-`라는 파일명을 경로로 명시하여 읽기 |
| `cat < -` | 입력 리다이렉션으로 `-` 파일 읽기 |

---

## 3. 풀이 과정

```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
# 이전 레벨에서 획득한 비밀번호 사용
```

### 1. 파일 확인
`ls` 명령어로 파일 목록을 봅니다.

```bash
bandit1@bandit:~$ ls
-
```
파일명이 하이픈(`-`) 하나로 되어 있습니다.

### 2. 문제 상황
일반적인 방법인 `cat -`를 입력하면 아무런 반응이 없습니다.
리눅스 명령어에서 단독으로 쓰이는 `-`는 **표준 입력**을 의미하기 때문입니다. 즉, 파일 내용을 보여주는 게 아니라 사용자의 키보드 입력을 기다리는 상태가 됩니다.

### 3. 해결 방법
파일명이라는 것을 쉘에게 확실히 알려주기 위해 **상대 경로**인 `./`를 붙여줍니다.

```bash
bandit1@bandit:~$ cat ./-
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
```

</details>

---

## 5. 배운 점

1. 파일명이 `-`로 시작할 경우 `./`를 붙여 경로로 인식시키기
2. 리눅스 쉘에서 `-`는 표준 입력/출력을 의미하는 특수 문자

---

## 6. 보안 관점

- **특수 파일명을 이용한 은닉**: 공격자는 `-`, `..`, `. ` 등 특수한 파일명으로 파일을 숨길 수 있습니다.
- **명령어 인젝션 방어**: 스크립트에서 파일명 처리 시 `--`를 사용하여 옵션 파싱 종료
  ```bash
  cat -- "$filename"
  ```

<hr class="short-rule">
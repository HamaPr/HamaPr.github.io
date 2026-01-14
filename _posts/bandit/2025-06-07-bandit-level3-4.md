---
layout: post
title: "[Bandit] Level 3 → Level 4"
date: 2025-06-07 09:04:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux, hidden-files]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in a hidden file in the `inhere` directory.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `ls -a` | 숨김 파일(.으로 시작)을 포함한 모든 파일 표시 |
| `cd` | 디렉토리 이동 |

---

## 3. 풀이 과정

```bash
ssh bandit3@bandit.labs.overthewire.org -p 2220
```

### 1. 디렉토리 이동 및 확인
`inhere` 디렉토리로 이동하여 파일을 찾습니다.

```bash
bandit3@bandit:~$ cd inhere
bandit3@bandit:~/inhere$ ls
(출력 없음)
```
`ls`를 쳤는데 아무것도 나오지 않습니다.

### 2. 숨김 파일 확인 (`-a` 옵션)
리눅스에서 파일명이 `.`(점)으로 시작하면 숨김 파일이 됩니다. `-a` (All) 옵션을 사용하면 숨김 파일까지 볼 수 있습니다.

```bash
bandit3@bandit:~/inhere$ ls -a
.  ..  .hidden
```
`.hidden`이라는 파일이 숨어있었습니다.

### 3. 파일 내용 읽기
이제 평소처럼 `cat`으로 내용을 확인합니다.

```bash
bandit3@bandit:~/inhere$ cat .hidden
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
```

</details>

---

## 5. 배운 점

1. 리눅스에서 `.`으로 시작하는 파일은 숨김 처리됨
2. `ls -a` 옵션으로 숨김 파일 확인 가능
3. 숨김은 보안 설정이 아닌 단순 표시 옵션

---

## 6. 보안 관점

- **숨김 파일의 오용**: 악성코드는 종종 `.cache`, `.config` 등 숨김 디렉토리에 잠복합니다.
- **포렌식 관점**: 시스템 침해 조사 시 반드시 `ls -la`로 숨김 파일 확인 필수
- **dotfiles**: `.bashrc`, `.profile` 등은 쉘 시작 시 자동 실행되어 백도어 삽입 가능

<hr class="short-rule">
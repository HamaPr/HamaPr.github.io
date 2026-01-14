---
layout: post
title: "[Bandit] Level 0 → Level 1"
date: 2025-06-07 09:01:00 +0900
categories: [bandit]
tags: [overthewire, bandit, ssh, cat, ls]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in a file called `readme` located in the home directory.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `ls` | 현재 디렉토리의 파일 목록 출력 |
| `cat` | 파일 내용을 화면에 출력 |

---

## 3. 풀이 과정

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
# 비밀번호: bandit0
```

### 1. 파일 목록 확인
먼저 `ls` 명령어를 사용하여 현재 디렉토리에 어떤 파일이 있는지 확인합니다.

```bash
bandit0@bandit:~$ ls
readme
```

### 2. 파일 내용 읽기
`readme`라는 파일이 존재합니다. `cat` 명령어로 내용을 읽어봅니다.

```bash
bandit0@bandit:~$ cat readme
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
```

</details>

---

## 5. 배운 점

1. `cat` 명령어로 파일 내용 출력
2. `ls` 명령어로 디렉토리 내용 확인
3. 리눅스 홈 디렉토리(`~`) 개념

---

## 6. 보안 관점

- **평문 비밀번호 저장의 위험성**: 이 레벨에서 비밀번호가 일반 텍스트 파일에 저장되어 있습니다. 실제 시스템에서는 절대 평문으로 저장하면 안 됩니다.
- **파일 권한의 중요성**: `readme` 파일은 `bandit0` 사용자만 읽을 수 있도록 권한이 설정되어 있습니다.

<hr class="short-rule">
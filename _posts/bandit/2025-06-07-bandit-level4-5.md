---
layout: post
title: "[Bandit] Level 4 → Level 5"
date: 2025-06-07 09:05:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux, file-command]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in the only human-readable file in the `inhere` directory.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `file` | 파일의 종류(타입) 식별 |
| `file *` | 현재 디렉토리의 모든 파일 타입 확인 |

---

## 3. 풀이 과정

```bash
ssh bandit4@bandit.labs.overthewire.org -p 2220
```

### 1. 파일 목록 확인
`inhere` 디렉토리에 들어가니 `-file00`부터 `-file09`까지 파일이 잔뜩 있습니다.
어떤 것이 사람이 읽을 수 있는 파일인지 알 수 없습니다.

### 2. 파일 타입 식별 (`file` 명령어)
하나씩 열어볼 수도 있지만, `file` 명령어를 쓰면 파일의 종류를 미리 알 수 있습니다.
와일드카드(`*`)를 사용하여 모든 파일을 한 번에 검사합니다. (파일명이 `-`로 시작하므로 `./-*` 패턴을 사용합니다)

```bash
bandit4@bandit:~/inhere$ file ./-*
./-file00: data
./-file01: data
...
./-file07: ASCII text
...
```
대부분 `data` (바이너리) 파일이지만, 유독 **`-file07`만 `ASCII text`**라고 나옵니다. 이것이 우리가 찾는 텍스트 파일입니다.

### 3. 비밀번호 확인
찾아낸 파일을 읽습니다.

```bash
bandit4@bandit:~/inhere$ cat ./-file07
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```

</details>

---

## 5. 배운 점

1. `file` 명령어로 파일 타입 식별
2. `*` (와일드카드)는 모든 파일과 매칭
3. `ASCII text`는 사람이 읽을 수 있는 텍스트 파일

---

## 6. 보안 관점

- **파일 확장자를 신뢰하지 마라**: 리눅스에서 확장자는 힌트일 뿐, 실제 타입은 `file` 명령어로 확인
- **악성 파일 탐지**: 악성코드는 종종 `.jpg`, `.pdf` 등으로 위장합니다
- **바이너리 파일 주의**: `data` 타입을 `cat`으로 열면 터미널이 깨질 수 있음 (`reset`으로 복구)

<hr class="short-rule">
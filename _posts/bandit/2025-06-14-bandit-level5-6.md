---
layout: post
title: "[Bandit] Level 5 → Level 6"
date: 2025-06-14 09:01:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux, find-command]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in a file somewhere under the `inhere` directory and has all of the following properties:
> - **human-readable** (사람이 읽을 수 있음)
> - **1033 bytes in size** (크기가 1033바이트)
> - **not executable** (실행 불가능)

이전 레벨들과 달리 파일명에 대한 힌트가 없고, 파일의 **속성(Properties)** 만 주어졌습니다. 리눅스에서 파일 속성을 기반으로 검색하는 방법을 익힐 수 있었습니다.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `find [경로] [조건]` | 지정한 경로 하위에서 조건에 맞는 파일을 검색합니다. |
| `-type f` | 파일 타입이 '일반 파일(file)'인 것만 검색 (디렉토리 제외) |
| `-size [크기]` | 파일 크기로 검색. 접미사 주의: `c`(바이트), `k`(KB), `M`(MB) |
| `!` | 조건을 부정(NOT)합니다. `! -executable`은 실행 불가능한 파일을 의미 |
| `-executable` | 실행 권한이 있는 파일을 검색 |

---

## 3. 풀이 과정

### 1. 조건 분석
문제에서 제시한 파일의 특징은 3가지입니다.
1. `human-readable`: 사람이 읽을 수 있는 텍스트 파일
2. `1033 bytes`: 파일 크기가 정확히 1033 바이트
3. `not executable`: 실행 불가능한 파일

### 2. 명령어 조합 (find)
`find` 명령어로 이 조건들을 만족하는 파일을 `inhere` 디렉토리 아래에서 찾습니다.

```bash
find inhere -type f -size 1033c ! -executable
```
- `-type f`: 파일만 찾기
- `-size 1033c`: 크기가 1033 바이트(`c`)인 것
- `! -executable`: 실행 권한이 없는(`!`) 것

### 3. 결과 확인
명령어를 실행하면 파일 경로가 나옵니다.
`inhere/maybehere07/.file2`

이 파일을 읽으면 비밀번호가 있습니다.

```bash
cat inhere/maybehere07/.file2
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
```

</details>

---

## 5. 배운 점

1. **`find`의 강력함**: 파일 이름뿐만 아니라 크기, 권한, 소유자, 시간 등 다양한 속성으로 파일을 정교하게 검색할 수 있습니다.
2. **크기 단위 접미사**: `find`에서 `-size` 사용 시 단위(`c`, `k`, `M`, `G`)를 명시하지 않으면 예상과 다른 결과가 나올 수 있습니다.
3. **논리 연산자**: `!`(NOT), `-o`(OR), `-a`(AND, 생략가능)를 사용하여 복잡한 조건을 구성할 수 있습니다.

---

## 6. 보안 관점

- **웹쉘 탐지**: 침해 사고 분석 시 `find` 명령어는 공격자가 숨겨놓은 악성 파일(웹쉘 등)을 찾는 데 필수적입니다. 예를 들어, 최근 24시간 이내에 생성된 php 파일을 찾으려면:
  ```bash
  find /var/www/html -name "*.php" -mtime -1
  ```
- **권한 관리**: `-executable` 옵션으로 의도치 않게 실행 권한이 부여된 파일을 찾아 권한을 회수(`chmod -x`)하는 보안 점검에도 활용됩니다.

<hr class="short-rule">
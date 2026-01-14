---
layout: post
title: "[Bandit] Level 7 → Level 8"
date: 2025-06-14 09:03:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux, grep]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in the file `data.txt` next to the word **millionth** (백만 번째).

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `grep [패턴] [파일]` | 파일 내에서 특정 패턴(문자열)이 포함된 줄을 찾아 출력 |

---

## 3. 풀이 과정

 `bandit7` 계정으로 로그인합니다.

```bash
ssh bandit7@bandit.labs.overthewire.org -p 2220
```

### 1. 파일 크기 확인
먼저 `ls -lh` 명령어로 파일 크기를 확인합니다.

```bash
bandit7@bandit:~$ ls -lh data.txt
-rw-r----- 1 bandit8 bandit7 4.0M ... data.txt
```

파일 크기가 4MB나 됩니다. 텍스트 파일치고는 매우 큽니다. `cat data.txt`를 실행하면 수만 줄의 데이터가 화면을 가득 채워 터미널이 마비될 수도 있습니다.

### 2. 검색 (grep)
힌트인 `millionth`라는 단어를 `grep`으로 검색합니다.

```bash
bandit7@bandit:~$ grep "millionth" data.txt
millionth       dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```

명령어 한 줄로 수많은 데이터 중에서 `millionth`가 포함된 딱 한 줄만 찾아냈습니다. 탭으로 구분된 오른쪽 문자열이 비밀번호입니다.

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```

</details>

---

## 5. 배운 점

1. **`grep` (Global Regular Expression Print)**: 리눅스에서 텍스트 검색을 할 때 가장 기본적이면서도 강력한 도구입니다.
2. **효율적인 데이터 탐색**: 대용량 파일은 전체를 열어보는 것(`cat`, `vim`)보다 필요한 정보만 필터링(`grep`)하는 것이 훨씬 빠르고 효율적입니다.

---

## 6. 보안 관점

- **로그 분석과 침해 대응**: 보안 담당자는 매일 기가바이트(GB) 단위의 로그 파일을 분석해야 합니다. 이때 눈으로 로그를 읽는 것은 불가능합니다.
- `grep`을 사용하여 `Failed password`, `Error`, `Attack` 같은 키워드를 검색하거나 정규표현식으로 특정 공격 패턴(예: SQL Injection 시도)을 탐지합니다.
  ```bash
  # 예시: 실패한 로그인 시도 검색
  grep "Failed password" /var/log/auth.log
  ```

<hr class="short-rule">
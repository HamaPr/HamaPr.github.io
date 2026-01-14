---
layout: post
title: "[Bandit] Level 2 → Level 3"
date: 2025-06-07 09:03:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux, spaces]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in a file called `spaces in this filename` located in the home directory.


파일명에 **공백**이 포함된 경우를 다룹니다. 쉘은 띄어쓰기를 **'명령어와 인자의 구분'**으로 처리하므로, 공백이 포함된 파일 이름을 온전히 하나로 인식시키는 것이 핵심입니다.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `cat "file name"` | 따옴표로 감싸서 공백 포함 파일 읽기 |
| `cat file\ name` | 역슬래시로 공백 이스케이프 |

---

## 3. 풀이 과정

```bash
ssh bandit2@bandit.labs.overthewire.org -p 2220
```

### 1. 파일 확인
```bash
bandit2@bandit:~$ ls
spaces in this filename
```
파일명에 **공백**이 포함되어 있습니다. 이를 `cat spaces in this filename` 처럼 그냥 입력하면, 리눅스는 `spaces`, `in`, `this`, `filename`이라는 4개의 파일을 각각 찾는 것으로 오해합니다.

### 2. 해결 방법 1: 따옴표 사용
파일 전체 이름을 따옴표(`"`)로 감싸서 하나의 덩어리임을 알려줍니다.

```bash
bandit2@bandit:~$ cat "spaces in this filename"
```

### 3. 해결 방법 2: 탭 키 자동완성
가장 실용적인 방법입니다. 파일명의 앞글자 `spa` 정도만 치고 **Tab** 키를 누르면 쉘이 알아서 이스케이프 처리를 해줍니다.

```bash
bandit2@bandit:~$ cat spa[Tab]
# 결과: cat spaces\ in\ this\ filename
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```

</details>

---

## 5. 배운 점

1. 파일명에 공백이 있을 경우 따옴표나 역슬래시로 처리
2. Tab 자동완성 활용하면 특수문자 자동 이스케이프
3. 쉘에서 공백은 인자 구분자로 사용됨

---

## 6. 보안 관점

- **파일명 조작 공격**: 특수문자가 포함된 파일명은 스크립트에서 예상치 못한 동작을 유발할 수 있습니다.
- **안전한 스크립트 작성**: 변수 사용 시 항상 따옴표로 감싸기
  ```bash
  cat "$filename"  # 안전
  cat $filename    # 위험
  ```

<hr class="short-rule">
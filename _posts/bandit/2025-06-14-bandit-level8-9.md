---
layout: post
title: "[Bandit] Level 8 → Level 9"
date: 2025-06-14 09:04:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux, pipes, sort, uniq]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored in the file `data.txt` and is the **only line of text that occurs only once** (유일하게 중복되지 않는 한 줄).

`data.txt` 파일에는 수많은 문자열이 들어있고, 대부분은 여러 번 중복되어 나타납니다. 중복되지 않고 딱 한 번만 등장하는 줄을 찾아야 했습니다.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `sort` | 텍스트 내용을 알파벳/숫자 순서로 정렬 |
| `uniq` | 중복된 줄을 제거하거나 표시 (단, **인접한** 중복만 처리 가능) |
| `-u` | 중복되지 않은(Unique) 유일한 줄만 출력하는 `uniq`의 옵션 |
| `\|` (파이프) | 앞 명령어의 출력 결과를 뒤 명령어의 입력으로 연결 |

---

## 3. 풀이 과정

`bandit8` 계정으로 로그인합니다.

```bash
ssh bandit8@bandit.labs.overthewire.org -p 2220
```

### 1. 파일 내용 확인
`data.txt` 내용을 `head` 명령어로 살짝만 확인해봅니다.

```bash
bandit8@bandit:~$ head data.txt
a8s9df8as9d...
fsd78fd7sf8...
a8s9df8as9d...
```
같은 문자열이 여러 번 반복해서 보이는 것 같습니다.

### 2. 단순 시도 (실패)
`uniq` 명령어를 바로 사용하면 원하는 결과가 나오지 않습니다. `uniq`는 **인접한 줄**끼리만 비교하기 때문입니다.

```bash
bandit8@bandit:~$ uniq -u data.txt
(여전히 수많은 문자열이 출력됨)
```

### 3. 명령어 파이프라인 (Sort & Uniq)
따라서 `sort`로 먼저 정렬하고, 그 결과를 `|` (파이프)로 `uniq -u` 에게 넘겨줍니다.

```bash
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

**동작 원리**:
1. `sort data.txt`: 모든 내용을 가나다순으로 정렬 (메모리나 임시 공간 사용)
2. `|`: 정렬된 결과를 다음 명령어로 토스
3. `uniq -u`: 윗줄과 아랫줄을 비교하며 중복이 없는 딱 한 줄만 남김

### 4. 결과 확인
수많은 텍스트 중에서 딱 한 줄만 남습니다.
```
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
```

</details>

---

## 5. 배운 점

1. **파이프라인 (`|`)**: 리눅스의 철학인 "한 가지 일을 잘하는 작은 도구들을 조합하여 복잡한 작업 수행"을 보여주는 핵심 기능입니다.
2. **`uniq` 사용 시 주의점**: 단순히 `uniq`만 쓰면 되는 줄 알았는데, **입력 데이터가 정렬(`sort`)되어 있어야만** 제대로 동작한다는 점을 알게 되었습니다.
   - 자주 쓰는 패턴: `sort | uniq -c | sort -nr` (빈도수대로 정렬)

---

## 6. 보안 관점

- **이상 징후(Anomaly) 탐지**: 보안 관제 시스템에서 "정상적인 트래픽"은 패턴화되어 반복적으로 나타납니다. 반면, "공격"이나 "해킹 시도"는 평소와 다른 유일한(Unique) 패턴으로 나타나는 경우가 많습니다.
- 이 문제처럼 수많은 중복 속에서 **튀는 하나**를 찾아내는 기술은 침해 위협을 탐지하는 기본 원리입니다.

<hr class="short-rule">
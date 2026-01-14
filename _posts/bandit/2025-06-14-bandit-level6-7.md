---
layout: post
title: "[Bandit] Level 6 → Level 7"
date: 2025-06-14 09:02:00 +0900
categories: [bandit]
tags: [overthewire, bandit, linux, find-command, stderr]
---

## 1. 문제 개요

> **Level Goal**
> 
> The password for the next level is stored somewhere on the server and has all of the following properties:
> - **owned by user bandit7** (소유자가 bandit7)
> - **owned by group bandit6** (소유 그룹이 bandit6)
> - **33 bytes in size** (크기가 33바이트)

이번 레벨은 검색 범위가 **서버 전체**로 확장되었습니다. 하지만 일반 사용자(`bandit6`)는 시스템의 모든 파일에 접근할 권한이 없으므로, 검색 중 수많은 "Permission denied" 에러를 마주하게 됩니다. 이 에러 메시지(노이즈)를 처리하는 새로운 방법을 알게 되었습니다.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `find` | 파일 검색 |
| `-user [사용자]` | 파일의 소유자로 검색 |
| `-group [그룹]` | 파일의 소유 그룹으로 검색 |
| `2> /dev/null` | 표준 에러 스트림(Stderr, 2번)을 `/dev/null`로 보내서 버림 |

---

## 3. 풀이 과정

먼저 `bandit6` 계정으로 로그인합니다.

```bash
ssh bandit6@bandit.labs.overthewire.org -p 2220
```

### 1. 조건 분석
- `owned by user bandit7`: 소유자가 bandit7
- `owned by group bandit6`: 소유 그룹이 bandit6
- `33 bytes`: 크기가 33 바이트
- 전체 시스템(`/`)에서 찾아야 함

### 2. 명령어 구성 (find)
```bash
find / -user bandit7 -group bandit6 -size 33c
```
이렇게만 치면 어떻게 될까요?
`Permission denied` 에러가 수천 줄 쏟아져 나와서 정작 찾은 파일이 안 보일 것입니다. 우리는 일반 유저라서 시스템의 대부분의 폴더를 읽을 수 없기 때문입니다.

```bash
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c
find: ‘/var/log’: Permission denied
find: ‘/var/crash’: Permission denied
... (수백 줄의 에러 메시지) ...
```

### 3. 에러 숨기기 (리다이렉션)
에러 메시지(Standard Error, 2번)를 "블랙홀"인 `/dev/null`로 버려서 안 보이게 처리해야 깔끔합니다.

```bash
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c 2> /dev/null
```
뒤에 `2> /dev/null`을 붙이면 에러는 휴지통으로 가고, 우리가 찾는 "성공한 결과"만 화면에 남습니다.

### 4. 결과 확인
딱 하나의 파일 경로가 출력됩니다.
`/var/lib/dpkg/info/bandit7.password`
내용을 확인합니다.
```bash
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
```

---

## 4. 결과

<details markdown="1">
<summary>비밀번호 확인</summary>

```
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
```

</details>

---

## 5. 배운 점

1. **리눅스 표준 입출력 (Standard Streams)**
   - `0` (Stdin): 표준 입력
   - `1` (Stdout): 표준 출력 (정상적인 결과값)
   - `2` (Stderr): 표준 에러 (오류 메시지)
2. **리다이렉션**: `2> /dev/null`은 "2번 스트림(에러)을 null 장치(버리는 곳)로 보내라"는 의미입니다.
3. **`find`의 소유권 검색**: `-user`와 `-group` 옵션으로 특정 사용자나 그룹 소유의 파일을 찾을 수 있습니다.

---

## 6. 보안 관점

- **정보 은닉**: 리눅스 시스템은 수많은 로그와 에러를 발생시킵니다. 공격자나 보안 분석가는 이런 방대한 데이터 속에서 자신이 원하는 "신호(Signal)"만 걸러내기 위해 필터링 기술을 사용합니다.
- **권한 분리**: 리눅스는 다중 사용자 시스템입니다. `bandit6` 사용자가 다른 사용자의 민감한 파일에 접근하려 할 때 "Permission denied"가 뜨는 것은 운영체제의 기본적인 접근 제어(Access Control)가 작동하고 있음을 보여줍니다.

<hr class="short-rule">
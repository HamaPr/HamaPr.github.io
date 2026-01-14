---
layout: post
title: "[Bandit] Level 0 - SSH로 서버 접속하기"
date: 2025-06-07 09:00:00 +0900
categories: [bandit]
tags: [overthewire, bandit, ssh, intro, putty]
---

## 1. 문제 개요

> **Level Goal**
> 
> The goal of this level is for you to log into the game using SSH. The host is `bandit.labs.overthewire.org` on port `2220`. Username and password are both `bandit0`.

---

## 2. 사용 명령어

| 명령어 | 설명 |
|--------|------|
| `ssh` | Secure Shell. 원격 서버에 암호화된 연결로 접속 |
| `-p` | 접속할 포트 번호 지정 (기본값: 22) |

---

## 3. 풀이 과정

### 1. 리눅스 (터미널)
터미널을 열고 다음 명령어를 입력합니다. `-p` 옵션으로 포트 번호 2220을 지정해야 합니다.

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```
비밀번호를 물어보면 `bandit0`을 입력합니다. (보안상 화면에는 아무것도 표시되지 않습니다)

### 2. 윈도우 사용자
1. PuTTY를 실행하고 접속 정보를 입력합니다.
   - **Host Name:** `bandit.labs.overthewire.org`
   - **Port:** `2220`

![PuTTY session 화면]({{ "/assets/images/bandit/putty-session-screenshot.png" | relative_url }})

2. `Open` 버튼을 누르면 검은색 창이 뜹니다.
3. `login as:` 라고 나오면 `bandit0`을 입력하고 엔터를 칩니다.
4. 비밀번호 `bandit0`을 입력합니다. 타이핑하는 동안 커서가 움직이지 않아도 정상적으로 입력되고 있는 것입니다.

---

## 4. 추가 팁

### PuTTY 설정
![PuTTY appearance 화면]({{ "/assets/images/bandit/putty-appearance-screenshot.png" | relative_url }})
글씨체가 너무 작다면 'Appearance' 탭에서 폰트와 크기를 조절할 수 있습니다.

![PuTTY selection 화면]({{ "/assets/images/bandit/putty-selection-screenshot.png" | relative_url }})
'Selection' 탭에서 복사/붙여넣기 방식을 설정할 수 있습니다. 보통 마우스 드래그로 복사하고, 우클릭으로 붙여넣는 방식이 편리합니다.

---

## 5. 배운 점

1. SSH 기본 접속 방법
2. PuTTY 사용법
3. 비표준 포트(-p 옵션)로 SSH 접속

---

## 6. 보안 관점

- **SSH vs Telnet**: SSH는 모든 통신이 암호화되어 네트워크 스니핑 공격으로부터 안전
- **기본 포트 변경**: 표준 포트(22) 대신 2220 사용 → 자동화된 스캔 공격 회피

<hr class="short-rule">
---
layout: post
title: "[Bandit] Level 0 시작하기"
date: 2025-06-07 09:00:00 +0900
categories: [bandit]
tags: [overthewire, bandit, ssh, intro, putty]
---

> 📝 **공식 문제 (Level 0)**
>
> **Level Goal**
> The goal of this level is for you to log into the game using SSH. The host to which you need to connect is bandit.labs.overthewire.org, on port 2220. The username is bandit0 and the password is bandit0. Once logged in, go to the Level 1 page to find out how to beat Level 1.
>
> **Commands you may need to solve this level**
> ssh
>
> **Helpful Reading Material**
> - [Secure Shell (SSH) on Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
> - [How to use SSH on wikiHow](https://www.wikihow.com/Use-SSH)


---

## 🚀 워게임 시작

Bandit 워게임의 첫 번째 관문은 SSH를 통해 원격 서버에 접속하는 것입니다. 
Windows 환경에서는 **PuTTY**라는 프로그램을 사용하면 아주 편리합니다.

---

### PuTTY 접속 방법

1.  PuTTY를 실행하고 아래와 같이 접속 정보를 입력합니다.
    - **Host Name (or IP address):** `bandit.labs.overthewire.org`
    - **Port:** `2220`
    - **Connection type:** `SSH` (기본값)

    ![PuTTY session 화면]({{ "/assets/images/putty-session-screenshot.png" | relative_url }})
2.  `Open` 버튼을 누르면 검은색 터미널 창이 나타납니다.
3.  `login as:` 프롬프트에 `bandit0`을 입력하고 엔터를 칩니다.
4.  `bandit0@bandit.labs.overthewire.org's password:` 프롬프트에 
비밀번호 `bandit0`을 입력하고 엔터를 칩니다. (비밀번호는 화면에 보이지 않는 것이 정상입니다.)

접속에 성공하면 워게임 서버에 들어오신 겁니다!

---

## 추가 팁

![PuTTY appearance 화면]({{ "/assets/images/putty-appearance-screenshot.png" | relative_url }})

> 글씨체와 글씨 크기를 조절 할 수 있습니다.

![PuTTY selection 화면]({{ "/assets/images/putty-selection-screenshot.png" | relative_url }})

> 마우스 우 클릭으로 paste붙여넣기를 할 수 있습니다.

![PuTTY save 화면]({{ "/assets/images/putty-save-screenshot.png" | relative_url }})

> Saved Sessions에 원하는 이름을 입력하고 Save 하면 설정 정보가 저장 됩니다.
> 이후 접속시 아래 목록에 있는 OvertheWire_bandit(설정한 이름)을 더블 클릭하면 접속 됩니다.



---

## 💡 배운 점

1. SSH 기본 접속 방법 이해
2. PuTTY 사용법

<hr class="short-rule">
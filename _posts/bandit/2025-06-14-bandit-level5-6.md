---
layout: post
title: "[Bandit]Level5→6풀이"
date: 2025-06-14 09:01:00 +0900
categories: [bandit]
tags: [overthewire,bandit,linux]
---

>📝**공식문제(Level5→6)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredintheonlyhuman-readablefileintheinheredirectory.Tip:ifyourterminalismessedup,trythe“reset”command.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit5`
-비밀번호:`4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`

-**접속명령어**

```bash
sshbandit5@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`find`명령어로여러조건을조합하여파일검색
2.조건:`inhere`디렉토리내부,일반파일(`-typef`),1033바이트크기(`-size1033c`),실행불가능(`!-executable`)
3.검색된파일의내용을`cat`으로출력

```bash
bandit5@bandit:~$findinhere-typef-size1033c!-executable
inhere/maybehere07/.file2
bandit5@bandit:~$catinhere/maybehere07/.file2
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
```

</details>

---

##💡배운점

1.find명령어의다양한옵션활용법
.:현재디렉토리부터검색
-typef:파일타입만검색
-size1033c:크기가정확히1033바이트인파일검색
!-executable:실행가능하지않은파일검색

<hrclass="short-rule">
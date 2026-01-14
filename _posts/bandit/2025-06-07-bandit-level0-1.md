---
layout: post
title: "[Bandit]Level0→1풀이"
date: 2025-06-07 09:01:00 +0900
categories: [bandit]
tags: [overthewire,bandit,ssh]
---

>📝**공식문제(Level0→1)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredinafilecalledreadmelocatedinthehomedirectory.Usethispasswordtologintobandit1usingSSH.Wheneveryoufindapasswordforalevel,useSSH(onport2220)tologintothatlevelandcontinuethegame.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`

---

##🔐LevelInfo

-**접속정보**
-호스트:`bandit.labs.overthewire.org`
-포트:`2220`
-사용자:`bandit0`
-비밀번호:`bandit0`

-**접속명령어**

```bash
sshbandit0@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`readme`파일의내용을`cat`명령어로확인

```bash
bandit0@bandit:~$catreadme
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
```

</details>

---

##💡배운점

1.리눅스기본명령어:cat(파일내용출력)

<hrclass="short-rule">
---
layout: post
title: "[Bandit]Level1→2풀이"
date: 2025-06-07 09:02:00 +0900
categories: [bandit]
tags: [overthewire,bandit,ssh,special-character]
---

>📝**공식문제(Level1→2)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredinafilecalled-locatedinthehomedirectory.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`
>
>**HelpfulReadingMaterial**
>-[GoogleSearchfor“dashedfilename”](https://www.google.com/search?q=dashed+filename)
>-[AdvancedBash-scriptingGuide-Chapter3-SpecialCharacters](https://tldp.org/LDP/abs/html/special-chars.html)

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit1`
-비밀번호:`ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

-**접속명령어**

```bash
sshbandit1@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`ls`명령어로현재디렉토리의파일목록확인
2.`-`라는이름의파일발견
3.`cat`으로`-`파일을직접열려고하면옵션으로인식되어오류발생
4.`./-`와같이현재경로를명시하여파일임을알려준뒤내용확인

```bash
bandit1@bandit:~$ls
-
bandit1@bandit:~$cat./-
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
```

</details>

---

##💡배운점

1.파일이름이-와같은특수문자로시작할경우./를앞에붙여현재디렉토리의파일임을명시

<hrclass="short-rule">
---
layout: post
title: "[Bandit]Level4→5풀이"
date: 2025-06-07 09:05:00 +0900
categories: [bandit]
tags: [overthewire,bandit,linux]
---

>📝**공식문제(Level4→5)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredintheonlyhuman-readablefileintheinheredirectory.Tip:ifyourterminalismessedup,trythe“reset”command.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit4`
-비밀번호:`2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`

-**접속명령어**

```bash
sshbandit4@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`inhere`디렉토리로이동
2.`file*`명령어로모든파일의종류를확인
3.`ASCIItext`타입으로확인된사람이읽을수있는파일의내용을출력

```bash
bandit4@bandit:~$cdinhere
bandit4@bandit:~/inhere$file*
-file00:data
-file01:data
-file02:data
-file03:data
-file04:data
-file05:data
-file06:data
-file07:ASCIItext
-file08:data
-file09:data
bandit4@bandit:~/inhere$cat./-file07
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```

</details>

---

##💡배운점

1.`file`명령어는파일의종류(타입)를식별하는데사용됨.
2.`*`(와일드카드)는현재디렉토리의모든파일을의미함.

<hrclass="short-rule">
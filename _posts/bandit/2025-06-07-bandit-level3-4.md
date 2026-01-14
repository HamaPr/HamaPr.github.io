---
layout:post
title:"[Bandit]Level3→4풀이"
date:2025-06-0709:04:00+0900
categories:[bandit]
tags:[overthewire,bandit,linux]
---

>📝**공식문제(Level3→4)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredinahiddenfileintheinheredirectory.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit3`
-비밀번호:`MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

-**접속명령어**

```bash
sshbandit3@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`inhere`디렉토리로이동
2.`ls-a`명령어로숨겨진파일을포함한모든항목확인
3.`.hidden`파일발견후내용출력

```bash
bandit3@bandit:~$cdinhere
bandit3@bandit:~/inhere$ls-a
....hidden
bandit3@bandit:~/inhere$cat.hidden
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
```

</details>

---

##💡배운점

1.리눅스에서.으로시작하는파일/디렉토리는숨김처리됨.
2.ls-a옵션으로숨겨진항목을확인할수있음.

<hrclass="short-rule">
---
layout:post
title:"[Bandit]Level6→7풀이"
date:2025-06-1409:02:00+0900
categories:[bandit]
tags:[overthewire,bandit,linux]
---

>📝**공식문제(Level6→7)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredintheonlyhuman-readablefileintheinheredirectory.Tip:ifyourterminalismessedup,trythe“reset”command.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit6`
-비밀번호:`HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`

-**접속명령어**

```bash
sshbandit6@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`find`명령어로`/`(최상위경로)부터조건에맞는파일검색
2.조건:소유자`bandit7`,그룹`bandit6`,크기33바이트
3.권한문제로발생하는오류메시지는`2>/dev/null`로숨김처리
4.검색된파일의내용을`cat`으로출력

```bash
bandit6@bandit:~$find/-userbandit7-groupbandit6-size33c2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$cat/var/lib/dpkg/info/bandit7.password
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
```

</details>

---

##💡배운점

1.`find`명령어의소유자/그룹검색옵션:`-user`,`-group`
2.`2>/dev/null`:명령어실행시발생하는오류메시지(stderr)를버려서결과만깔끔하게볼수있음.

<hrclass="short-rule">
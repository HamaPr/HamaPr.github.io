---
layout: post
title: "[Bandit]Level7→8풀이"
date: 2025-06-14 09:03:00 +0900
categories: [bandit]
tags: [overthewire,bandit,linux]
---

>📝**공식문제(Level7→8)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredintheonlyhuman-readablefileintheinheredirectory.Tip:ifyourterminalismessedup,trythe“reset”command.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit7`
-비밀번호:`morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`

-**접속명령어**

```bash
sshbandit7@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`grep`명령어로`data.txt`파일에서`millionth`단어가포함된줄검색

```bash
bandit7@bandit:~$grepmillionthdata.txt
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```

</details>

---

##💡배운점

1.`grep[패턴][파일명]`:파일안에서특정패턴(문자열)이포함된줄을찾아출력함.

<hrclass="short-rule">
---
layout:post
title:"[Bandit]Level8→9풀이"
date:2025-06-1409:04:00+0900
categories:[bandit]
tags:[overthewire,bandit,linux]
---

>📝**공식문제(Level8→9)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredintheonlyhuman-readablefileintheinheredirectory.Tip:ifyourterminalismessedup,trythe“reset”command.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit8`
-비밀번호:`dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`

-**접속명령어**

```bash
sshbandit8@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`sort`명령어로`data.txt`파일의내용을정렬
2.`|`(파이프)를사용해정렬된결과를`uniq`명령어의입력으로전달
3.`uniq-u`옵션으로유일한줄만필터링

```bash
bandit8@bandit:~$sortdata.txt|uniq-u
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
```

</details>

---

##💡배운점

1.|(파이프):한명령어의출력결과를다음명령어의입력으로연결함.
2.sort:텍스트데이터를정렬함.
3.uniq-u:정렬된데이터에서중복되지않고한번만나타나는줄만출력함.

<hrclass="short-rule">
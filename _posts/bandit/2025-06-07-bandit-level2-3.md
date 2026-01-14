---
layout:post
title:"[Bandit]Level2→3풀이"
date:2025-06-0709:03:00+0900
categories:[bandit]
tags:[overthewire,bandit,linux]
---

>📝**공식문제(Level2→3)**
>
>**LevelGoal**
>Thepasswordforthenextlevelisstoredinafilecalledspacesinthisfilenamelocatedinthehomedirectory.
>
>**Commandsyoumayneedtosolvethislevel**
>`ls`,`cd`,`cat`,`file`,`du`,`find`
>
>**HelpfulReadingMaterial**
>-[GoogleSearchfor“spacesinfilename”](https://www.google.com/search?q=spaces+in+filename)

---

##🔐LevelInfo

-**접속정보**
-사용자:`bandit2`
-비밀번호:`263JGJPfgU6LtdEvgfWU1XP5yac29mFx`

-**접속명령어**

```bash
sshbandit2@bandit.labs.overthewire.org-p2220
```

---

##🧪풀이과정

1.`ls`로`spacesinthisfilename`이라는이름의파일발견
2.파일이름에공백이포함되어있어그대로입력하면여러개의인자로인식됨
3.큰따옴표(`"`)로파일이름전체를감싸서하나의인자로인식시켜내용확인

```bash
bandit2@bandit:~$ls-l
total4
-rw-r-----1bandit3bandit215May72020spacesinthisfilename
bandit2@bandit:~$cat"spacesinthisfilename"
```

##🧪다른풀이방법
1.각공백문자앞에역슬래시(\)를사용하여해당공백이일반문자임을쉘에게알려줌

```bash
bandit2@bandit:~$catspaces\in\this\filename
```

---

##🎯결과

<detailsmarkdown="1">
<summary>👀클릭하여비밀번호확인하기</summary>

```
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```

</details>

---

##💡배운점

1.파일이름에공백이있을경우큰따옴표("...")나작은따옴표('...')로감싸거나각공백앞에역슬래시(\)를붙여처리할수있다.

<hrclass="short-rule">
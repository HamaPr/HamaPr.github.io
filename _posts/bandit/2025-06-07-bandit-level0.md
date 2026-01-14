---
layout:post
title:"[Bandit]Level0시작하기"
date:2025-06-0709:00:00+0900
categories:[bandit]
tags:[overthewire,bandit,ssh,intro,putty]
---

>📝**공식문제(Level0)**
>
>**LevelGoal**
>ThegoalofthislevelisforyoutologintothegameusingSSH.Thehosttowhichyouneedtoconnectisbandit.labs.overthewire.org,onport2220.Theusernameisbandit0andthepasswordisbandit0.Onceloggedin,gototheLevel1pagetofindouthowtobeatLevel1.
>
>**Commandsyoumayneedtosolvethislevel**
>ssh
>
>**HelpfulReadingMaterial**
>-[SecureShell(SSH)onWikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
>-[HowtouseSSHonwikiHow](https://www.wikihow.com/Use-SSH)


---

##🚀워게임시작

Bandit워게임의첫번째관문은SSH를통해원격서버에접속하는것입니다.
Windows환경에서는**PuTTY**라는프로그램을사용하면아주편리합니다.

---

###PuTTY접속방법

1.PuTTY를실행하고아래와같이접속정보를입력합니다.
-**HostName(orIPaddress):**`bandit.labs.overthewire.org`
-**Port:**`2220`
-**Connectiontype:**`SSH`(기본값)

![PuTTYsession화면]({{"/assets/images/bandit/putty-session-screenshot.png"|relative_url}})
2.`Open`버튼을누르면검은색터미널창이나타납니다.
3.`loginas:`프롬프트에`bandit0`을입력하고엔터를칩니다.
4.`bandit0@bandit.labs.overthewire.org'spassword:`프롬프트에
비밀번호`bandit0`을입력하고엔터를칩니다.(비밀번호는화면에보이지않는것이정상입니다.)

접속에성공하면워게임서버에들어오신겁니다!

---

##추가팁

![PuTTYappearance화면]({{"/assets/images/bandit/putty-appearance-screenshot.png"|relative_url}})

>글씨체와글씨크기를조절할수있습니다.

![PuTTYselection화면]({{"/assets/images/bandit/putty-selection-screenshot.png"|relative_url}})

>마우스우클릭으로paste붙여넣기를할수있습니다.

![PuTTYsave화면]({{"/assets/images/bandit/putty-save-screenshot.png"|relative_url}})

>SavedSessions에원하는이름을입력하고Save하면설정정보가저장됩니다.
>이후접속시아래목록에있는OvertheWire_bandit(설정한이름)을더블클릭하면접속됩니다.



---

##💡배운점

1.SSH기본접속방법이해
2.PuTTY사용법

<hrclass="short-rule">
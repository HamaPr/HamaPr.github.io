---
layout: post
title: "Burp Suite 공부"
date: 2025-08-27 17:00:00 +0900
categories: [해킹 툴]
---

### 1. Burp Suite 개요

Burp Suite는 웹 브라우저와 서버 사이의 모든 통신을 가로채고 조작하는 웹 프록시 도구이다.

웹 애플리케이션 보안 테스트를 위한 통합 플랫폼으로, 핵심 기능은 웹 브라우저와 웹 서버 사이에서 중간자(Man-in-the-Middle) 역할을 하는 프록시 서버이다. 이 프록시를 통해 사용자가 주고받는 모든 HTTP/HTTPS 요청과 응답을 가로채고 분석하거나 변조할 수 있다. 웹 취약점 분석의 필수 도구로 여겨진다.

---

### 2. 기본 설정

Burp Suite를 사용하려면 먼저 브라우저의 트래픽이 Burp Suite를 거치도록 설정해야 한다.

1.  **Burp Suite 프록시 활성화:** Burp Suite를 실행하고 `Proxy` 탭의 `Intercept` 탭에서 `Intercept is on` 버튼을 활성화한다. 기본적으로 프록시 서버는 `127.0.0.1:8080`에서 동작한다.

2.  **브라우저 프록시 설정:** 웹 브라우저가 `127.0.0.1:8080`으로 트래픽을 보내도록 설정한다. Firefox의 `FoxyProxy`와 같은 확장 프로그램을 사용하면 프록시 설정을 쉽게 켜고 끌 수 있어 편리하다.

3.  **CA 인증서 설치:** HTTPS 트래픽을 분석하려면 Burp Suite의 CA 인증서를 브라우저에 설치해야 한다. Burp Suite가 켜진 상태에서 브라우저로 `http://burpsuite`에 접속하여 인증서를 다운로드하고 브라우저 설정에서 신뢰하는 인증 기관으로 가져온다.

---

### 3. 핵심 기능

#### ***Proxy: 트래픽 가로채기***
`Proxy` 탭은 모든 트래픽을 확인하고 제어하는 관문이다. `Intercept` 기능이 활성화된 상태에서 웹 페이지에 접속하면 요청이 서버로 전송되기 전에 Burp Suite에 잡힌다. 여기서 `Forward` 버튼을 눌러 요청을 그대로 보내거나 `Drop` 버튼으로 요청을 버릴 수 있다. 또는 요청 내용을 수정한 뒤 보낼 수도 있다.

   ![BurpIntercept](/assets/images/Burp_1.png)

#### ***Repeater: 요청 재전송 및 수정***
`Repeater` 탭은 가로챈 요청을 수동으로 여러 번 보내볼 수 있는 기능이다. 특정 파라미터 값을 바꿔가며 서버가 어떻게 다르게 반응하는지 확인할 때 매우 유용하다.

예를 들어 [SQL Injection](https://hamap0.github.io/projects/owasp-top-10/2025/08/27/A03_Injection.html)이나 [Broken Access Control](https://hamap0.github.io/projects/owasp-top-10/2025/08/25/A01_Broken-Access-Control.html) 취약점을 테스트할 때 ID 값이나 다른 파라미터를 변경하며 서버의 응답 변화를 관찰할 수 있다.

   ![BurpRepeater](/assets/images/Burp_2.png)

#### ***Intruder: 공격 자동화***
`Intruder` 탭은 요청의 특정 부분을 자동화된 방식으로 바꾸어 대량으로 보내는 기능이다. 주로 무차별 대입 공격(Brute-force)이나 특정 파라미터에 대한 값 추측 공격에 사용된다.

1.  공격할 요청을 `Intruder` 탭으로 보낸다.
2.  `Positions` 탭에서 공격할 위치(파라미터)를 `§` 기호로 지정한다.
3.  `Payloads` 탭에서 주입할 값 목록(예: 비밀번호 사전 파일)을 설정한다.
4.  공격을 시작하면 각 페이로드에 대한 서버의 응답 코드나 길이(Length)를 비교하여 유의미한 차이를 찾아낼 수 있다.

   ![BurpIntruder](/assets/images/A04_P1-1.png)

<hr class="short-rule">
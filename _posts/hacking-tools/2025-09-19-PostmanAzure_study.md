---
layout: post
title: "Postman과 Azure Storage Explorer 공부: 클라우드 및 API 해킹 도구"
date: 2025-09-19 17:00:00 +0900
categories: [hacking-tools]
tags: [Postman, Azure Storage Explorer, API Hacking, Cloud Security, Tool]
description: "Postman을 이용한 API 취약점 진단과 Azure Storage Explorer를 이용한 데이터 유출 시나리오"
---

## 1. 개요

**Postman**과 **Azure Storage Explorer**는 개발자와 운영자에게 필수적인 도구이지만, 공격자에게는 API 취약점을 찾고 클라우드 데이터를 탈취하는 강력한 무기가 됩니다.
이번 글에서는 이 두 도구를 보안 진단(또는 공격) 관점에서 어떻게 활용하는지 알아봅니다.

---

## 2. Postman: API 취약점 진단

Postman은 HTTP 요청을 자유자재로 조작하여 서버로 보낼 수 있는 도구입니다.

### 2.1. 주요 활용 기능
*   **Interceptor**: 브라우저의 요청을 프록시처럼 가로채서 Postman으로 가져옵니다.
*   **Environment**: 공격 대상 서버(Dev, Prod)나 토큰 값을 변수로 관리하여 빠르게 스위칭합니다.
*   **Automated Testing**: 여러 공격 페이로드를 리스트로 만들어 자동화된 Fuzzing을 수행할 수 있습니다.

### 2.2. 실습: IDOR 취약점 찾기
모바일 앱이나 웹에서 사용하는 API를 분석하여 다른 사용자의 정보를 탈취하는 시나리오입니다.

1.  **요청 캡처**: 정상적인 내 프로필 조회 요청(`GET /api/v1/users/me`)을 캡처합니다.
2.  **토큰 재사용**: `Authorization: Bearer <Token>` 헤더는 그대로 둡니다.
3.  **엔드포인트 변조**: URL을 `/api/v1/users/100` (다른 사용자 ID)으로 변경하여 전송합니다.
4.  **결과 확인**: `200 OK`와 함께 다른 사용자의 JSON 데이터가 반환된다면 IDOR 취약점이 존재하는 것입니다.

![Postman](/assets/images/hacking-tools/Postman_API.png)

---

## 3. Azure Storage Explorer: 클라우드 데이터 유출

Azure Storage Explorer는 Azure의 Blob, File, Queue, Table 스토리지에 접근하는 GUI 도구입니다.

### 3.1. 공격 시나리오: Leaked SAS Token
공격자가 GitHub나 클라이언트 소스코드에서 **SAS(Shared Access Signature) 토큰**을 발견했다고 가정합니다.

SAS 토큰 예시:
`?sv=2020-08-04&ss=b&srt=sco&sp=rwdlac&se=2025-01-01T00:00:00Z&st=2021-01-01T00:00:00Z&spr=https&sig=...`

1.  **연결 추가**: Azure Storage Explorer를 실행하고 '연결(Connect)' 아이콘을 클릭합니다.
2.  **리소스 선택**: 'Blob Container' 또는 'Storage Account'를 선택합니다.
3.  **연결 방법**: 'SAS(공유 액세스 서명) URI'를 선택하고 탈취한 URL을 입력합니다.
4.  **데이터 접근**: 연결이 성공하면, 해당 스토리지의 모든 파일을 내 PC로 다운로드하거나 삭제할 수 있습니다.

### 3.2. 위험성
SAS 토큰은 유효기간과 권한(읽기/쓰기/삭제)이 포함되어 있습니다. 만약 `sp=rwdlac` (Read, Write, Delete, List, Add, Create) 권한이 있고 유효기간이 길다면, 공격자는 스토리지 전체를 장악할 수 있습니다.

---

## 4. 방어 대책

1.  **API 보안**:
    *   모든 API 엔드포인트에 대해 철저한 **인증(Authentication)**과 **권한 검증(Authorization)**을 수행합니다.
    *   불필요한 정보(Verbose Error)를 노출하지 않습니다.
2.  **클라우드 스토리지 보안**:
    *   **액세스 키 관리**: 스토리지 계정의 마스터 키(Access Key)는 절대 코드에 포함하지 않고 Key Vault 등을 통해 관리합니다.
    *   **최소 권한 SAS**: SAS 토큰 발급 시 필요한 최소한의 권한과 짧은 유효기간만 부여합니다.
    *   **네트워크 제한**: 특정 IP 대역이나 VNet에서만 스토리지에 접근할 수 있도록 방화벽을 설정합니다.

<hr class="short-rule">
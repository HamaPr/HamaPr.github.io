---
layout: post
title: "Postman & Azure API"
date: 2025-09-19 17:00:00 +0900
categories: [hacking-tools]
tags: [Postman, Azure Storage Explorer, API Hacking, Cloud Security, Tool]
description: "Postman을 이용한 API 취약점 진단과 Azure Storage Explorer를 이용한 데이터 유출 시나리오"
---

## 1. 개요

**Postman**과 **Azure Storage Explorer**는 개발자와 운영자에게 필수적인 도구이지만, 보안 진단 및 공격 관점에서는 API 취약점을 탐색하고 클라우드 데이터를 탈취하는 강력한 무기가 된다.
개발 과정에서 방치된 테스트용 API나 관리 소홀로 노출된 클라우드 액세스 키는 심각한 침해 사고로 이어질 수 있다.
본 글에서는 두 도구를 활용하여 API의 **IDOR (부적절한 직접 객체 참조)** 취약점을 찾아내고, 유출된 SAS 토큰을 이용해 Azure 스토리지를 장악하는 과정을 다룬다.

---

## 2. 실습: Postman

Postman은 HTTP 요청을 자유자재로 조작하여 서버로 보낼 수 있어 로직 취약점 진단에 최적화되어 있다.

### 주요 활용 기능
*   **Interceptor**: 브라우저의 트래픽을 프록시처럼 가로채서 Postman History에 자동으로 저장한다.
*   **Environment**: 개발(Dev), 운영(Prod) 서버 주소나 토큰 값을 변수로 관리하여 환경을 빠르게 전환한다.
*   **Automated Testing**: 공격 페이로드를 리스트로 만들어 Fuzzing을 수행하거나 반복적인 테스트를 자동화한다.

### 시나리오: IDOR 취약점 탐지
타 사용자 프로필을 무단으로 조회하는 시나리오이다.

1.  **요청 캡처**: 정상적인 내 프로필 조회 요청(`GET /api/v1/users/me`)을 캡처한다.
2.  **토큰 재사용**: 인증 헤더(`Authorization: Bearer <Token>`)는 내 계정의 토큰을 그대로 유지한다.
3.  **엔드포인트 변조**: URL의 경로를 다른 사용자 ID(`100`)로 변경하여 전송한다. (`/api/v1/users/100`)
4.  **결과 확인**: 서버가 권한 오류(`403`)를 반환하지 않고 `200 OK`와 함께 타인의 정보를 반환한다면 IDOR 취약점이 존재하는 것이다.

![Postman](/assets/images/hacking-tools/Postman_API.png)

---

## 3. 실습: Azure Storage Explorer (데이터 유출)

Azure Storage Explorer는 GUI 환경에서 클라우드 저장소(Blob, File, Queue, Table)에 접근하는 도구이다.

### 공격 시나리오: Leaked SAS Token
공격자가 GitHub 검색 등을 통해 소스코드에 하드코딩된 **SAS(Shared Access Signature) 토큰**을 발견했다고 가정한다.

**SAS 토큰 예시**:
`https://target.blob.core.windows.net/?sv=2020-08-04&ss=b&srt=sco&sp=rwdlac&se=2025-01-01...&sig=...`

1.  **연결 추가 (Connect)**: Azure Storage Explorer를 실행하고 플러그 아이콘(Connect)을 클릭한다.
2.  **리소스 선택**: `Blob Container` 또는 `Storage Account`를 선택한다.
3.  **연결 방법**: `Shared Access Signature URI (SAS)`를 선택하고 획득한 URL을 입력한다.
4.  **데이터 접근**: 연결이 성공하면 해당 스토리지의 모든 파일을 다운로드하거나, 권한(`sp=rwdlac`)에 따라 삭제 및 변조할 수 있다.

### 위험성 분석
SAS 토큰에 `Write(w)`, `Delete(d)`, `List(l)` 권한이 포함되어 있다면, 공격자는 데이터를 유출하는 것을 넘어 랜섬웨어처럼 파일을 암호화하거나 삭제하여 서비스 장애를 유발할 수 있다.

---

## 4. 보안 대책

### API 보안
1.  **철저한 인증 및 권한 부여**: 모든 API 엔드포인트에서 요청자의 권한을 검증(Authorization)해야 한다.
2.  **정보 노출 최소화**: API 응답 메시지에 불필요한 시스템 정보나 에러 메시지를 포함하지 않는다.

### 클라우드 스토리지 보안
1.  **액세스 키 코드 분리**: Storage Account Key나 SAS 토큰을 코드에 포함하지 않고 **Azure Key Vault**나 환경 변수로 관리한다.
2.  **최소 권한 원칙**: SAS 토큰 발급 시 필요한 최소한의 권한(예: Read Only)과 짧은 유효 기간을 설정한다.
3.  **네트워크 격리**: 스토리지 방화벽을 설정하여 특정 IP나 가상 네트워크(VNet)에서의 접근만 허용한다.

<hr class="short-rule">
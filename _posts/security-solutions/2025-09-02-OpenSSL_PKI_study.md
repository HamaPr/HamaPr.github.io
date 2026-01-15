---
layout: post
title: "OpenSSL & PKI"
date: 2025-09-02 18:00:00 +0900
categories: [security-solutions]
---

## 1. 개요

**PKI (Public Key Infrastructure, 공개키 기반 구조)**는 네트워크 상에서 신뢰할 수 있는 제3자(CA)를 통해 사용자 및 서버의 신원을 증명하고, 공개키 암호화 기술을 이용해 데이터의 기밀성, 무결성, 인증, 부인 방지를 제공하는 보안 인프라이다.
리눅스 환경에서는 **OpenSSL** 도구를 사용하여 사설 CA(Certificate Authority)를 구축하고 SSL/TLS 인증서를 직접 발급하여 테스트할 수 있다.

### 핵심 용어
| 용어 | 설명 |
|---|---|
| **CA (Certificate Authority)** | 인증서 발급 및 관리를 담당하는 신뢰할 수 있는 기관 |
| **Root CA** | 최상위 인증 기관. 자신의 인증서를 스스로 서명(Self-Signed)한다. |
| **CSR (Certificate Signing Request)** | 인증서 서명 요청. 공개키와 조직 정보를 담아 CA에 제출하는 파일 |
| **Private Key (개인키)** | 절대 유출되어서는 안 되는 비밀키. 서명 및 복호화에 사용 |
| **Public Key (공개키)** | 누구나 가질 수 있는 키. 검증 및 암호화에 사용 |
| **X.509** | PKI 인증서의 표준 포맷 |

### 인증서 체인 구조
```mermaid
flowchart TB
    Root[Root CA<br>(최상위 신뢰)] --> Intermediate[Intermediate CA<br>(중간 인증 기관)]
    Intermediate --> ServerCert[Server Certificate<br>(최종 사용자 인증서)]
    Intermediate --> ClientCert[Client Certificate<br>(클라이언트 인증서)]
```

---

## 2. OpenSSL 설치 및 환경 준비

대부분의 리눅스 배포판에는 OpenSSL이 기본 설치되어 있다.

```bash
# 설치 확인
openssl version

# (필요 시) 설치
dnf install -y openssl
```

### 디렉터리 구조 생성
CA 관리를 위한 표준 디렉터리 구조를 생성한다.
```bash
mkdir -p /etc/pki/CA/{certs,crl,newcerts,private}
chmod 700 /etc/pki/CA/private
touch /etc/pki/CA/index.txt
echo 1000 > /etc/pki/CA/serial   # 시리얼 번호 초기화
```

---

## 3. 사설 Root CA 구축

### 1) Root CA 개인키 생성
```bash
cd /etc/pki/CA
# AES256으로 암호화된 4096비트 RSA 키 생성
openssl genrsa -aes256 -out private/ca.key 4096

# 퍼미션 보안 설정
chmod 400 private/ca.key
```

### 2) Root CA 인증서 생성 (Self-Signed)
CSR 생성 없이 바로 인증서를 생성한다(`-x509` 옵션). 유효기간은 길게(10년) 설정한다.
```bash
openssl req -config /etc/pki/tls/openssl.cnf \
    -key private/ca.key \
    -new -x509 -days 3650 -sha256 -extensions v3_ca \
    -out certs/ca.crt

# 입력 예시:
# Country Name: KR
# Organization Name: MyPrivateCA
# Common Name: Root CA
```

---

## 4. 서버 인증서 발급

웹 서버(HTTPS) 등에 사용할 인증서를 발급하는 과정이다.

### 1) 서버용 개인키 생성
서버 데몬이 자동 실행되게 하려면 암호를 걸지 않는 것이 일반적이다.
```bash
openssl genrsa -out server.key 2048
```

### 2) 인증서 서명 요청(CSR) 생성
인증서에 들어갈 정보(도메인 등)를 입력하여 CSR을 만든다.
```bash
openssl req -new -key server.key -out server.csr

# 중요: Common Name (CN)에 실제 도메인 또는 IP 입력
# Common Name: www.example.com
```

### 3) SAN (Subject Alternative Name) 설정 (선택 사항)
최신 브라우저(Chrome 등)는 CN 대신 SAN 필드를 확인하므로, 설정 파일(`san.cnf`)을 만들어 포함시키는 것이 좋다.

**[san.cnf 파일 작성]**
```ini
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = www.example.com
DNS.2 = example.com
IP.1 = 192.168.1.100
```

### 4) CA 서명 및 인증서 발급
CA의 개인키로 CSR에 서명하여 최종 인증서(`server.crt`)를 생성한다.
```bash
openssl x509 -req -in server.csr \
    -CA /etc/pki/CA/certs/ca.crt \
    -CAkey /etc/pki/CA/private/ca.key \
    -CAcreateserial \
    -out server.crt \
    -days 365 -sha256 \
    -extfile san.cnf -extensions v3_req
```

---

## 5. 인증서 형식 변환 및 확인

### 인증서 내용 확인
```bash
# 텍스트로 정보 출력
openssl x509 -in server.crt -text -noout

# 만료일 확인
openssl x509 -in server.crt -enddate -noout
```

### 포맷 변환
```bash
# PEM -> DER (바이너리)
openssl x509 -in server.crt -outform der -out server.der

# PEM -> PKCS#12 (PFX, Windows용)
openssl pkcs12 -export -out server.pfx \
    -inkey server.key -in server.crt -certfile ca.crt
```

---

## 6. 웹 서버 적용 예시 (Apache/Nginx)

### Apache (httpd.conf 또는 ssl.conf)
```apache
<VirtualHost *:443>
    ServerName www.example.com
    SSLEngine on
    SSLCertificateFile /etc/pki/tls/certs/server.crt
    SSLCertificateKeyFile /etc/pki/tls/private/server.key
    SSLCertificateChainFile /etc/pki/tls/certs/ca.crt
</VirtualHost>
```

### Nginx (nginx.conf)
```nginx
server {
    listen 443 ssl;
    server_name www.example.com;
    
    ssl_certificate /etc/pki/tls/certs/server.crt;
    ssl_certificate_key /etc/pki/tls/private/server.key;
}
```

---

## 7. 트러블슈팅

### 인증서 검증 실패 (Browser Warning)
*   **원인**: 사설 CA 인증서가 클라이언트 PC(브라우저)의 "신뢰할 수 있는 루트 인증 기관" 저장소에 등록되지 않았기 때문.
*   **해결**: `ca.crt` 파일을 클라이언트 PC에 복사한 후 수동으로 신뢰된 루트 인증 기관으로 등록해야 한다.

### 키와 인증서 불일치 (Mismatch)
개인키와 인증서가 쌍이 맞는지 확인하려면 Modulus 해시 값을 비교한다.
```bash
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
```
출력된 해시 값이 다르면 잘못된 키 쌍이다.

<hr class="short-rule">

---
layout: post
title: "Nmap 공부"
date: 2025-08-23 17:00:00 +0900
categories: [해킹 툴]
---

### 1. 개요

Nmap은 IP 패킷을 분석해 네트워크의 호스트와 서비스를 파악하는 오픈소스 스캐너이다. 침투 테스트의 정찰 단계에서 열려 있는 포트와 실행 중인 서비스를 식별하는 데 사용된다.

---

### 2. 스캔 타입별 결과 비교

#### ***기본 TCP 스캔 (TCP Connect Scan)***
가장 기본적인 스캔. 대상 IP의 열린 포트와 포트가 사용하는 서비스를 보여준다.
```bash
nmap 192.9.200.11
```
***결과***
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

#### ***-sV (Version Scan)***
기본 스캔에 서비스의 상세 버전을 추가로 확인한다.
```bash
nmap -sV 192.9.200.11
```
***결과***
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```
   ![NmapsV](/assets/images/Nmap_1.png)

`VERSION` 항목이 추가되어 정확한 버전 정보가 나타난다. 이 정보는 [A06: 취약하고 오래된 구성 요소](https://hamap0.github.io/projects/owasp-top-10/2025/08/30/A06_Vulnerable-and-Outdated-Components.html) 분석의 핵심 근거가 된다.

#### ***-sC (Script Scan)***
기본 스캔에 Nmap의 기본 스크립트를 실행하여 추가 정보를 얻는다.
```bash
nmap -sC 192.9.200.11
```
***결과***
```
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 34:d0:49:d9:fc:53:38:1d:49:64:60:f0:39:22:72:77 (ECDSA)
|_  256 d5:04:7d:b5:de:35:d5:8a:93:34:f5:6a:12:c4:54:ea (ED25519)
80/tcp open  http
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2025-09-08 13:43  dvwa/
|_
|_http-title: Index of /
```
   ![NmapsC](/assets/images/Nmap_2.png)

기본 스캔 결과 아래에 스크립트 실행 결과가 추가된다. 웹 서버의 타이틀 같은 구체적인 정보를 얻을 수 있다.

---

### 3. 주요 옵션

*   **-sC -sV**: 두 옵션을 함께 사용하면 효율적으로 많은 정보를 얻을 수 있어 가장 자주 사용된다.
*   **-p-**: 1번부터 65535번까지 모든 포트를 스캔한다. 시간이 오래 걸린다.
*   **-p [Ports]**: 특정 포트만 지정해서 스캔한다. (예: `-p 80, 443`)
*   **-r**: 포트 스캔 순서를 무작위로 섞지 않고 1번부터 순차적으로 진행한다.

---

### 4. Nmap Scripting Engine (NSE)

NSE는 Nmap 스캔 과정에서 특정 작업을 자동화하는 Lua 스크립트를 실행하는 기능이다.

*   **-sC**: 이 옵션은 `--script=default`와 동일하며 `default` 카테고리로 분류된 스크립트를 실행하여 추가 정보를 수집한다.
*   **--script=vuln**: `vuln` 카테고리의 스크립트를 실행하여 대상 서비스 버전에 알려진 취약점(CVE)이 있는지 점검한다.

```bash
nmap -sV --script=vuln 192.9.200.11
```
   ![Nmap2vuln](/assets/images/Nmap_3.png)

이 명령을 실행하면 스캔된 서비스 버전에 해당하는 `vuln` 스크립트가 실행된다. 결과에 관련 CVE 번호와 `VULNERABLE` 상태가 출력될 경우 이는 `A06` 분석의 직접적인 증거가 된다.

<hr class="short-rule">
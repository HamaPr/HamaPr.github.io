---
layout: post
title: "Wazuh"
date: 2025-09-01 17:00:00 +0900
categories: [security-solutions]
---

## 1. 개요

**Wazuh**는 로그 분석, 파일 무결성 모니터링(FIM), 취약점 탐지, 컴플라이언스 관리 기능을 통합한 무료 오픈소스 **SIEM (Security Information and Event Management)** 및 **XDR** 플랫폼이다.
초기에는 OSSEC의 포크(Fork) 프로젝트로 시작했으나 현재는 ELK Stack(Elasticsearch, Logstash, Kibana) 또는 자체 Indexer/Dashboard와 결합하여 강력한 시각화와 분석 기능을 제공한다.

### 핵심 기능
*   **로그 데이터 수집**: 다양한 OS와 애플리케이션 로그를 중앙 수집 및 분석.
*   **파일 무결성 모니터링 (FIM)**: 중요 시스템 파일의 변조를 실시간 감지.
*   **위협 탐지**: 루트킷, 멀웨어, 이상 행위 탐지.
*   **취약점 탐지**: 설치된 소프트웨어 버전을 확인하여 CVE 취약점 매핑.
*   **컴플라이언스**: PCI-DSS, GDPR, HIPAA 등 규정 준수 여부 모니터링.

### 아키텍처
Wazuh는 중앙 서버와 엔드포인트에 설치되는 에이전트로 구성된다.

```mermaid
flowchart TB
    subgraph Endpoints ["보호 대상 (에이전트)"]
        Linux[Linux Agent]
        Win[Windows Agent]
        Mac[macOS Agent]
    end
    
    subgraph Server ["Wazuh Server"]
        Manager[Wazuh Manager<br>분석 및 룰 매칭]
        API[Wazuh API]
        Filebeat[Filebeat]
    end
    
    subgraph Storage ["데이터 저장 및 시각화"]
        Indexer[Wazuh Indexer<br>(OpenSearch)]
        Dashboard[Wazuh Dashboard<br>(Kibana Fork)]
    end

    Endpoints -->|Encrypted TCP 1514| Manager
    Manager --> API
    Filebeat -->|Log Data| Indexer
    Indexer --> Dashboard
```

---

## 2. 설치 방법 (All-in-One)

가장 간편한 설치 방법인 **Quick Start** 스크립트를 사용하여 Wazuh Manager, Indexer, Dashboard를 한 서버에 모두 설치한다.

### 요구 사항
*   **OS**: Ubuntu 20.04/22.04, CentOS 등
*   **RAM**: 최소 4GB (8GB 권장)
*   **CPU**: 2 Core 이상

### 설치 스크립트 실행
```bash
# 설치 스크립트 다운로드 및 실행
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
설치가 완료되면 `User: admin`, `Password: <생성된_비밀번호>`가 출력되므로 반드시 기록해 두어야 한다.

### 설치 결과 확인
비밀번호를 잊어버렸다면 다음 명령어로 확인할 수 있다.
```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

### 웹 대시보드 접속
브라우저에서 `https://<서버IP>`로 접속하여 로그인한다.

---

## 3. Wazuh Agent 설치

보호항 대상 서버(엔드포인트)에 에이전트를 설치하여 Wazuh 서버와 연동한다.

### Linux (Ubuntu/Debian)
1.  **GPG 키 및 저장소 추가**
    ```bash
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --deref --output /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt update
    ```

2.  **Agent 설치 및 매니저 IP 지정**
    ```bash
    WAZUH_MANAGER="<WAZUH_SERVER_IP>" apt install wazuh-agent
    ```

3.  **서비스 시작**
    ```bash
    systemctl daemon-reload
    systemctl enable --now wazuh-agent
    ```

### Windows
1.  Wazuh 공식 사이트에서 Windows용 MSI 설치 파일 다운로드.
2.  설치 마법사 실행 또는 PowerShell 명령어로 설치.
    ```powershell
    .\wazuh-agent-4.x.x.msi /q WAZUH_MANAGER="<WAZUH_SERVER_IP>" WAZUH_REGISTRATION_SERVER="<WAZUH_SERVER_IP>"
    ```
3.  서비스 관리자에서 `Wazuh` 서비스 시작.

---

## 4. 주요 기능 설정 (ossec.conf)

에이전트 설정 파일은 `/var/ossec/etc/ossec.conf`에 위치한다.

### 파일 무결성 모니터링 (FIM) 설정
중요 디렉터리(`/etc`, `/bin` 등)의 파일 변경을 감지한다.
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency> <!-- 12시간마다 전체 스캔 -->
  
  <!-- 실시간 감시 -->
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">/usr/bin</directories>
  <directories check_all="yes" realtime="yes">/var/www/html</directories>
  
  <!-- 무시할 파일 -->
  <ignore>/etc/mtab</ignore>
</syscheck>
```

### 로그 수집 설정 (Log Collection)
시스템 로그나 애플리케이션 로그(Apache, Nginx 등)를 수집한다.
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
```

---

## 5. 사용자 정의 탐지 룰 (Custom Rules)

Wazuh 서버의 `/var/ossec/etc/rules/local_rules.xml` 파일에 사용자 정의 룰을 추가할 수 있다.

### 기본 예시: 특정 파일 수정 시 경고 레벨 상향
```xml
<group name="syscheck, custom_alert,">
  <rule id="100010" level="12">
    <if_sid>550</if_sid> <!-- FIM 변경 탐지 기본 룰 ID -->
    <match>/var/www/html/index.php</match>
    <description>Critical file modified: index.php</description>
  </rule>
</group>
```

---

## 6. Windows AD 공격 탐지

Active Directory 환경에서 발생하는 주요 공격을 탐지하기 위한 룰셋이다. Windows Security 이벤트 로그를 수집하여 분석한다.

### 필수 이벤트 로그 수집 설정

Windows Agent의 `ossec.conf`에 Security 로그 수집을 추가한다.
```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 주요 Event ID 참조

| Event ID | 설명 | 위협 |
|----------|------|------|
| 4624 | 로그온 성공 | 정상 또는 Lateral Movement |
| 4625 | 로그온 실패 | Brute Force |
| 4672 | 특수 권한 할당 | 권한 상승 |
| 4768 | Kerberos TGT 요청 | Kerberoasting (RC4) |
| 4769 | Kerberos TGS 요청 | Kerberoasting |
| 4771 | Kerberos Pre-Auth 실패 | AS-REP Roasting |
| 4776 | NTLM 인증 시도 | Pass-the-Hash |
| 5136 | 디렉터리 객체 변경 | AD 변조 |

---

### AD 공격 탐지 룰셋

#### Brute Force (로그온 실패 다수)
```xml
<group name="windows, authentication_failed,">
  <rule id="100100" level="10" frequency="5" timeframe="60">
    <if_matched_sid>60122</if_matched_sid> <!-- 4625 -->
    <same_source_ip />
    <description>Brute Force: 5+ failed logins from same IP in 60s</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

#### Kerberoasting 탐지 (RC4 암호화 TGS 요청)
```xml
<group name="windows, kerberos,">
  <rule id="100110" level="12">
    <if_sid>60103</if_sid> <!-- 4769 -->
    <field name="win.eventdata.ticketEncryptionType">0x17</field> <!-- RC4 -->
    <description>Kerberoasting: TGS requested with RC4 encryption</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>
</group>
```

#### AS-REP Roasting 탐지
```xml
<group name="windows, kerberos,">
  <rule id="100111" level="12">
    <if_sid>60100</if_sid> <!-- 4768 -->
    <field name="win.eventdata.preAuthType">0</field>
    <description>AS-REP Roasting: TGT without pre-authentication</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
  </rule>
</group>
```

#### DCSync 공격 탐지 (디렉터리 복제 권한 사용)
```xml
<group name="windows, ad_attack,">
  <rule id="100120" level="14">
    <if_sid>60144</if_sid> <!-- 4662 -->
    <field name="win.eventdata.properties" type="pcre2">1131f6aa.*1131f6ad</field>
    <description>DCSync Attack: DS-Replication-Get-Changes detected</description>
    <mitre>
      <id>T1003.006</id>
    </mitre>
  </rule>
</group>
```

#### Golden Ticket 탐지 (TGT 이상 징후)
```xml
<group name="windows, kerberos,">
  <rule id="100130" level="14">
    <if_sid>60103</if_sid> <!-- 4769 -->
    <field name="win.eventdata.serviceName" type="pcre2">krbtgt</field>
    <field name="win.eventdata.ticketOptions">0x40810000</field>
    <description>Golden Ticket: Suspicious TGT usage pattern</description>
    <mitre>
      <id>T1558.001</id>
    </mitre>
  </rule>
</group>
```

#### Pass-the-Hash 탐지 (NTLM 인증)
```xml
<group name="windows, lateral_movement,">
  <rule id="100140" level="12">
    <if_sid>60110</if_sid> <!-- 4776 -->
    <field name="win.eventdata.status">0xC0000064</field>
    <description>Pass-the-Hash: NTLM auth with invalid username</description>
    <mitre>
      <id>T1550.002</id>
    </mitre>
  </rule>
</group>
```

---

### 탐지 룰 적용 및 테스트

```bash
# 룰 문법 검사
/var/ossec/bin/wazuh-analysisd -t

# 서비스 재시작
systemctl restart wazuh-manager

# 로그 확인
tail -f /var/ossec/logs/alerts/alerts.json
```

---

## 7. 트러블슈팅

### Agent가 연결되지 않음 (Disconnected)
1.  **방화벽 확인**: Manager와 Agent 간 **TCP 1514**, **TCP 1515** 포트가 열려 있는지 확인한다.
2.  **로그 확인**: Agent 로그(`/var/ossec/logs/ossec.log`)에서 에러 메시지를 확인한다.
    *   `Waiting for server reply`: 네트워크 연결 문제 또는 IP 오설정.
3.  **키 문제**: 서버에서 `agent_control -l`로 리스트 확인 후, 필요 시 `manage_agents` 툴로 키를 재생성한다.

### Elasticsearch/Indexer 메모리 오류
Wazuh Indexer(Java 기반)는 메모리를 많이 사용한다. 실행이 안 된다면 힙 메모리 설정을 확인한다.
```bash
vi /etc/wazuh-indexer/jvm.options
# -Xms1g
# -Xmx1g 
# 시스템 메모리의 50% 이하로 설정 권장
```

---

## 8. 보안 고려사항

*   **API 접근 제어**: Wazuh API는 강력한 권한을 가지므로, 접근 IP를 제한하고 강력한 자격 증명을 사용한다.
*   **에이전트 인증**: 에이전트-매니저 간 통신은 암호화되지만, 에이전트 등록 시 인증 키 관리에 주의한다.
*   **민감 정보 마스킹**: FIM이나 로그에 비밀번호, 토큰 등 민감 정보가 노출되지 않도록 필터링 규칙을 적용한다.
*   **대시보드 접근 보안**: HTTPS를 강제하고, MFA(다중 인증)나 LDAP 연동을 통해 접근을 제한한다.

<hr class="short-rule">

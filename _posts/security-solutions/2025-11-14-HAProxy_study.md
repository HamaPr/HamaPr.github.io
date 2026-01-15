---
layout: post
title: "HAProxy"
date: 2025-11-14 17:00:00 +0900
categories: [security-solutions]
---

## 1. 개요

**HAProxy (High Availability Proxy)**는 TCP(L4) 및 HTTP(L7) 기반의 로드 밸런싱과 고가용성을 제공하는 업계 표준 오픈소스 소프트웨어이다.
매우 높은 성능과 안정성을 자랑하며, 수많은 동시 연결을 낮은 지연 시간으로 처리할 수 있어 대규모 웹 서비스의 트래픽 분산에 필수적으로 사용된다.

### 핵심 기능
*   **로드 밸런싱**: 여러 대의 백엔드 서버로 트래픽을 분산하여 부하를 줄인다.
*   **고가용성 (HA)**: 헬스 체크를 통해 장애가 발생한 서버를 자동으로 제외하고 정상 서버로만 트래픽을 보낸다.
*   **SSL Offloading**: 무거운 암/복호화 처리를 로드밸런서가 대신 하여 웹 서버의 부하를 경감시킨다.

### 아키텍처 다이어그램
```mermaid
flowchart TB
    Client["User (Browser)"] -->|HTTPS (443)| HAP["HAProxy (Load Balancer)<br>SSL Termination"]
    
    subgraph Backend ["Web Server Pool"]
        Web1["Web Server 1<br>(192.168.1.11)"]
        Web2["Web Server 2<br>(192.168.1.12)"]
        Web3["Web Server 3<br>(192.168.1.13)"]
    end
    
    HAP -->|HTTP (80)| Web1
    HAP -->|HTTP (80)| Web2
    HAP -->|HTTP (80)| Web3
```

### 부하 분산 알고리즘 비교
| 알고리즘 | 설명 | 적합한 환경 |
|---|---|---|
| **Round Robin** | 서버에 순차적으로 하나씩 트래픽을 분배 | 일반적인 웹 서버 |
| **Least Conn** | 현재 연결 수가 가장 적은 서버로 보냄 | 긴 연결 세션 (DB 등) |
| **Source** | 출발지 IP 해시값 사용 (항상 같은 서버로 연결) | 세션 유지가 필요한 경우 |
| **URI** | 요청 URI 해시값 사용 | 캐싱 서버 등 |

---

## 2. 설치 방법 (CentOS/Rocky Linux)

공식 패키지 저장소를 통해 손쉽게 설치할 수 있다.

```bash
# 설치
dnf install -y haproxy

# 서비스 등록 및 시작
systemctl enable --now haproxy

# 설정 파일 위치 확인
ls -l /etc/haproxy/haproxy.cfg
```

---

## 3. HAProxy 설정 (haproxy.cfg)

설정 파일은 크게 global, defaults, frontend, backend 섹션으로 나뉜다.

### 1) 기본(Defaults) 설정
모든 섹션에 공통으로 적용될 기본값을 정의한다.
```cfg
defaults
    mode                    http            # 기본 모드 (http 또는 tcp)
    log                     global
    option                  httplog         # HTTP 로그 형식 사용
    option                  dontlognull     # 빈 연결 로깅 안 함
    timeout connect         5000ms          # 연결 타임아웃
    timeout client          50000ms         # 클라이언트 유휴 타임아웃
    timeout server          50000ms         # 서버 유휴 타임아웃
```

### 2) L7 HTTP 로드 밸런싱 설정
사용자의 요청(Frontend)을 받아 백엔드 서버들(Backend)로 분산한다.
```cfg
frontend http_front
    bind *:80
    default_backend web_servers

backend web_servers
    balance roundrobin                      # 라운드 로빈 알고리즘
    option httpchk GET /health HTTP/1.1\r\nHost:\ localhost  # 헬스 체크
    http-check expect status 200            # 응답 코드가 200이면 정상
    
    server web1 192.168.1.11:80 check inter 3000 rise 2 fall 3
    server web2 192.168.1.12:80 check inter 3000 rise 2 fall 3
    server web3 192.168.1.13:80 check backup  # 백업 서버 (장애 시에만 투입)
```

### 3) L4 TCP 로드 밸런싱 설정 (DB 등)
```cfg
frontend mysql_front
    mode tcp
    bind *:3306
    default_backend mysql_servers

backend mysql_servers
    mode tcp
    balance leastconn                       # 최소 연결 알고리즘
    server db1 192.168.1.21:3306 check
    server db2 192.168.1.22:3306 check
```

---

## 4. 고급 기능 설정

### SSL Offloading (HTTPS 설정)
클라이언트와는 HTTPS로 통신하고, 백엔드와는 HTTP로 통신한다.
```cfg
frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/combined.pem
    default_backend web_servers
    
    # HTTP 접근 시 HTTPS로 리다이렉트
    http-request redirect scheme https unless { ssl_fc }
```
> **인증서 파일**: HAProxy는 개인키와 인증서가 합쳐진 PEM 파일을 사용한다.
> `cat server.crt server.key > combined.pem`

### 모니터링 대시보드 (Stats Page)
실시간 트래픽 및 서버 상태를 웹에서 확인할 수 있다.
```cfg
listen stats
    bind *:8080
    stats enable
    stats uri /stats
    stats auth admin:password123  # 로그인 계정 정보
    stats refresh 10s             # 10초마다 자동 갱신
```

---

## 5. 실습: Ansible을 활용한 3-Tier 구축 자동화

HAProxy를 포함한 웹/WAS/DB 3계층 아키텍처를 Ansible Playbook으로 자동 구축하는 예시이다.

### 구성 호스트 정보
| 호스트 | IP | 역할 |
|---|---|---|
| **LB** | 10.0.0.11 | HAProxy |
| **Web1** | 10.0.0.12 | Apache + WordPress |
| **Web2** | 10.0.0.13 | Nginx + WordPress |
| **DB** | 10.0.0.14 | MariaDB |

### Ansible Playbook 예시 (`haproxy.yml`)
```yaml
---
- name: Deploy HAProxy Load Balancer
  hosts: lb
  become: yes
  tasks:
    - name: HAProxy 패키지 설치
      yum:
        name: haproxy
        state: present

    - name: HAProxy 설정 파일 배포
      copy:
        dest: /etc/haproxy/haproxy.cfg
        content: |
          global
              log 127.0.0.1 local2
              chroot /var/lib/haproxy
              user haproxy
              group haproxy
              daemon
          
          defaults
              mode http
              log global
              option httplog
              timeout connect 5000ms
              timeout client 50000ms
              timeout server 50000ms

          frontend http_front
              bind *:80
              default_backend nodes

          backend nodes
              balance roundrobin
              server web1 10.0.0.12:80 check
              server web2 10.0.0.13:80 check
      notify: Restart HAProxy

  handlers:
    - name: Restart HAProxy
      service:
        name: haproxy
        state: restarted
        enabled: yes
```

---

## 6. 트러블슈팅

### 1) 설정 파일 문법 검사
수정 후 재시작하기 전에 반드시 검사를 수행해야 한다.
```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
# "Configuration file is valid" 메시지 확인
```

### 2) 503 Service Unavailable 에러
*   **원인**: 모든 백엔드 서버가 헬스 체크를 통과하지 못해 죽어있는 상태이다.
*   **해결**: 백엔드 웹 서버의 가동 상태를 점검하고, 방화벽(80 포트)이 열려 있는지 확인한다.

### 3) SELinux 문제 (Permission Denied)
HAProxy가 네트워크에 연결하거나 특정 포트를 바인딩할 때 SELinux가 차단할 수 있다.
```bash
# HAProxy가 아무 포트나 바인딩하도록 허용
setsebool -P haproxy_connect_any 1
```

<hr class="short-rule">

---
layout: post
title: "Cisco Commands"
date: 2025-07-01 17:00:00 +0900
categories: [network]
---

## 1. 개요

**Cisco IOS (Internetwork Operating System)**는 전 세계 네트워크 장비의 표준과도 같은 Cisco 라우터와 스위치를 운영하는 운영체제이다.
GUI가 아닌 **CLI (Command Line Interface)** 환경에서 명령어 기반으로 장비를 제어하며, 보안 설정, 인터페이스 IP 할당, 라우팅 프로토콜 구성 등 모든 네트워크 관리 작업을 수행한다.

### 주요 특징
*   **계층적 모드**: 사용자 모드, 관리자 모드, 설정 모드 등으로 권한과 기능이 분리되어 있다.
*   **Context-Sensitive Help**: `?`를 입력하면 현재 위치에서 사용 가능한 명령어 목록을 보여준다.
*   **자동 완성**: `Tab` 키를 사용하여 명령어를 자동 완성할 수 있다.

---

## 2. CLI 모드 및 전환

Cisco 장비는 보안과 기능 분리를 위해 여러 단계를 거쳐야 설정이 가능하다.

| 모드 | 프롬프트 | 용도 |
|---|---|---|
| **User EXEC** | `Router>` | 기본 모드, 제한된 확인 명령(ping, show 일부)만 가능 |
| **Privileged EXEC** | `Router#` | 관리자 모드, 모든 확인 명령(show, debug) 및 저장 가능 |
| **Global Config** | `Router(config)#` | 장비 전체에 영향을 미치는 전역 설정 (호스트명 등) |
| **Interface Config** | `Router(config-if)#` | 특정 인터페이스(포트)에 대한 IP 할당 등 설정 |

### 모드 진입 순서
```cisco
Router> enable                  ! 특권(관리자) 모드 진입
Router# configure terminal      ! 전역 설정 모드 진입
Router(config)# interface g0/0  ! 인터페이스 설정 모드 진입
Router(config-if)# exit         ! 한 단계 상위로
Router(config)# end             ! 관리자 모드로 즉시 복귀
```

---

## 3. 필수 기본 설정

장비 초기 세팅 시 반드시 수행해야 하는 보안 및 관리 설정들이다.

### 1. 호스트네임 및 계정 보안
```cisco
! 장비 이름 변경
Router(config)# hostname R1

! 콘솔(물리적) 접속 비밀번호
Router(config)# line console 0
Router(config-line)# password cisco
Router(config-line)# login

! 텔넷/SSH(원격) 접속 비밀번호
Router(config)# line vty 0 4
Router(config-line)# password cisco
Router(config-line)# login
Router(config-line)# transport input ssh  ! SSH만 허용

! 관리자 모드 진입 암호 (Enable Secret: 암호화 저장)
Router(config)# enable secret cisco123

! 모든 비밀번호 암호화 (Service Password Encryption)
Router(config)# service password-encryption
```

### 2. 인터페이스(IP) 설정
```cisco
Router(config)# interface g0/0
Router(config-if)# ip address 192.168.1.1 255.255.255.0
Router(config-if)# no shutdown       ! 포트 활성화 (Cisco는 기본이 Shutdown)
Router(config-if)# description LAN-Interface
```

---

## 4. 설정 저장 및 초기화

Cisco 장비의 설정은 RAM(`running-config`)과 NVRAM(`startup-config`)으로 나뉜다. 저장하지 않으면 재부팅 시 설정이 날아간다.

### 설정 저장
```cisco
! 현재 설정을 시작 설정으로 복사 (권장)
Router# copy running-config startup-config

! 단축 명령어 (구형 스타일)
Router# write memory
```

### 설정 초기화 (공장 초기화) 및 재부팅
```cisco
Router# erase startup-config
Router# reload
```

---

## 5. 상태 확인 (Monitoring)

문제가 발생했을 때 가장 먼저 사용하는 `show` 명령어들이다.

```cisco
! 전체 설정 확인
Router# show running-config

! 인터페이스 요약 정보 (IP, 상태 확인)
Router# show ip interface brief
! 출력 예: GigabitEthernet0/0   192.168.1.1   YES manual up                    up

! 라우팅 테이블 확인 (L3)
Router# show ip route

! MAC 주소 테이블 확인 (L2 스위치)
Switch# show mac address-table

! 인접한 Cisco 장비 확인 (CDP)
Router# show cdp neighbors
```

---

## 6. 트러블슈팅 도구

### 연결성 테스트
```cisco
! Ping 테스트
Router# ping 8.8.8.8

! 경로 추적
Router# traceroute 8.8.8.8
```

### 디버깅 (Debugging)
실시간으로 장비의 동작 로그를 확인한다. CPU 부하를 줄 수 있으므로 주의해서 사용해야 한다.
```cisco
! ICMP 패킷 디버깅 활성화
Router# debug ip icmp

! 모든 디버깅 끄기 (필수)
Router# undebug all
! 또는
Router# u all
```

<hr class="short-rule">

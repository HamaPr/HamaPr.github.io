---
layout: post
title: "Cisco 라우터/스위치 기본 명령어"
date: 2025-07-01 17:00:00 +0900
categories: [network]
---

## 1. 개념

**Cisco IOS (Internetwork Operating System)**는 Cisco 네트워크 장비를 제어하고 라우팅/스위칭 기능을 수행하는 운영체제입니다.
CLI (Command Line Interface) 환경에서 다양한 모드를 통해 장비를 설정하고 모니터링합니다.

### CLI 모드

| 모드 | 프롬프트 | 설명 |
|------|----------|------|
| User EXEC | `Router>` | 기본 모드, 제한된 명령 |
| Privileged EXEC | `Router#` | 관리 명령 (show, debug) |

| Global Config | `Router(config)#` | 전역 설정 |

| Interface Config | `Router(config-if)#` | 인터페이스 설정 |

### 모드 전환
```cisco
Router> enable                  ! User → Privileged
Router# configure terminal      ! Privileged → Global
Router(config)# interface g0/0  ! Global → Interface
Router(config-if)# exit         ! 상위 모드로
Router(config)# end             ! Privileged로 바로 이동
```

---

## 2. 기본 설정

### 호스트명 및 보안
```cisco
! 호스트명 설정
Router(config)# hostname R1

! 콘솔 비밀번호
Router(config)# line console 0
Router(config-line)# password cisco
Router(config-line)# login

! VTY (원격 접속) 비밀번호
Router(config)# line vty 0 4
Router(config-line)# password cisco
Router(config-line)# login
Router(config-line)# transport input ssh

! Enable 비밀번호 (암호화)
Router(config)# enable secret cisco123

! 비밀번호 암호화 (평문 방지)
Router(config)# service password-encryption
```

### 배너 설정
```cisco
Router(config)# banner motd #
*** Unauthorized access is prohibited! ***
#
```

### 인터페이스 설정
```cisco
! IP 주소 할당
Router(config)# interface g0/0
Router(config-if)# ip address 192.168.1.1 255.255.255.0
Router(config-if)# no shutdown
Router(config-if)# description LAN Interface
```

---

## 3. 설정 저장 및 관리

### 설정 저장
```cisco
! Running-config → Startup-config
Router# copy running-config startup-config
! 또는
Router# write memory
```

### 설정 파일 개념

| 파일 | 저장소 | 설명 |
|------|--------|------|
| running-config | RAM | 현재 동작 중인 설정 |
| startup-config | NVRAM | 부팅 시 로드되는 설정 |

### 설정 초기화
```cisco
! 설정 삭제
Router# erase startup-config

! 재부팅
Router# reload
```

### 설정 백업 (TFTP)
```cisco
! TFTP 서버로 백업
Router# copy running-config tftp://10.0.0.100/router-backup.cfg

! TFTP에서 복원
Router# copy tftp://10.0.0.100/router-backup.cfg running-config
```

---

## 4. 확인 명령어 (show)

```cisco
! 장비 정보
Router# show version

! 현재 설정
Router# show running-config
Router# show startup-config

! 인터페이스 상태
Router# show ip interface brief
Router# show interfaces g0/0

! 라우팅 테이블
Router# show ip route

! ARP 테이블
Router# show arp

! CDP 이웃 장비
Router# show cdp neighbors
```

### show ip interface brief 출력
```
Interface         IP-Address      OK?  Method  Status  Protocol
GigabitEthernet0/0  192.168.1.1   YES  manual  up      up
GigabitEthernet0/1  unassigned    YES  unset   admin down down
```

### 상태 의미

| Status | Protocol | 의미 |
|--------|----------|------|
| up | up | 정상 동작 |
| up | down | L2 문제 (케이블, 속도) |
| admin down | down | shutdown 상태 |

---

## 5. 스위치 전용 명령어

```cisco
! VLAN 목록
Switch# show vlan brief

! MAC 주소 테이블
Switch# show mac address-table

! Trunk 상태
Switch# show interfaces trunk

! STP 상태
Switch# show spanning-tree
```

---

## 6. 트러블슈팅

### 연결 테스트
```cisco
Router# ping 192.168.1.1
Router# traceroute 8.8.8.8
```

### 디버깅
```cisco
! 디버그 활성화 (주의: 성능 영향)
Router# debug ip icmp

! 디버그 중지
Router# undebug all
```

### 설정 되돌리기
```cisco
! 저장 전 설정 복원
Router# copy startup-config running-config
```

<hr class="short-rule">

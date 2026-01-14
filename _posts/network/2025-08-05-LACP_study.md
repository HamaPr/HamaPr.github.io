---
layout: post
title: "LACP (Link Aggregation)"
date: 2025-08-05 17:00:00 +0900
categories: [network]
---

## 1. 개념

**LACP (Link Aggregation Control Protocol)**는 여러 물리적 포트를 하나로 묶어 대역폭을 확장하고 링크 이중화를 제공하는 표준 프로토콜입니다.
IEEE 802.3ad 표준으로 정의되며, Cisco의 EtherChannel 기술을 구현하는 방식 중 하나입니다.

### 기본 정보

| 항목 | 설명 |
|------|------|
| 표준 | IEEE 802.3ad (802.1AX) |
| 목적 | 대역폭 확장 + 이중화 |
| Cisco 용어 | EtherChannel |

### 장점
- **대역폭 증가**: 링크 수만큼 대역폭 합산
- **고가용성**: 일부 링크 장애 시 나머지로 동작
- **부하 분산**: 트래픽 분산

### Link Aggregation 프로토콜

| 프로토콜 | 표준 | 협상 |
|----------|------|------|
| LACP | IEEE 802.3ad | 동적 |
| PAgP | Cisco 전용 | 동적 |
| Static | - | 수동 (권장 안 함) |

### LACP 모드

| 모드 | 설명 |
|------|------|
| Active | 적극적으로 LACP 협상 시도 |
| Passive | 상대가 Active일 때만 응답 |

---

## 2. 설정 방법

### Cisco EtherChannel with LACP
```cisco
! Port-Channel 인터페이스 생성
Switch(config)# interface range g0/1-2
Switch(config-if-range)# channel-group 1 mode active
! 또는 passive

! Port-Channel 인터페이스 설정
Switch(config)# interface port-channel 1
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan all
```

### L3 EtherChannel
```cisco
! 라우티드 포트로 구성
Switch(config)# interface range g0/1-2
Switch(config-if-range)# no switchport
Switch(config-if-range)# channel-group 1 mode active

Switch(config)# interface port-channel 1
Switch(config-if)# ip address 10.0.0.1 255.255.255.0
```

### 부하 분산 설정
```cisco
! 부하 분산 알고리즘 설정
Switch(config)# port-channel load-balance src-dst-mac
```

### 부하 분산 옵션

| 옵션 | 기준 |
|------|------|
| src-mac | 출발지 MAC |
| dst-mac | 목적지 MAC |
| src-dst-mac | 출발/목적지 MAC |
| src-ip | 출발지 IP |
| dst-ip | 목적지 IP |
| src-dst-ip | 출발/목적지 IP |

---

## 3. 확인 명령어

```cisco
! EtherChannel 요약
Switch# show etherchannel summary

! 상세 정보
Switch# show etherchannel detail

! Port-Channel 인터페이스
Switch# show interfaces port-channel 1

! 부하 분산 설정
Switch# show etherchannel load-balance
```

### 출력 예시
```
Group  Port-channel  Protocol    Ports
------+-------------+-----------+-------
1      Po1(SU)         LACP      Gi0/1(P)  Gi0/2(P)

(P) - bundled in port-channel
(S) - suspended
```

---

## 4. 실습 예시

### 스위치 간 LACP 구성

```
         LACP (Port-Channel 1)
SW1 [G0/1]========[G0/1] SW2
SW1 [G0/2]========[G0/2] SW2
```

#### SW1 설정
```cisco
Switch1(config)# interface range g0/1-2
Switch1(config-if-range)# channel-group 1 mode active
Switch1(config)# interface port-channel 1
Switch1(config-if)# switchport mode trunk
```

#### SW2 설정
```cisco
Switch2(config)# interface range g0/1-2
Switch2(config-if-range)# channel-group 1 mode active
Switch2(config)# interface port-channel 1
Switch2(config-if)# switchport mode trunk
```

---

## 5. 트러블슈팅

### Channel 구성 실패
- **양쪽 설정 불일치**: 속도, 듀플렉스, VLAN 설정 확인
- **모드 조합**: Active-Active 또는 Active-Passive만 가능
- **Passive-Passive는 안됨**

### 포트가 Suspended 상태
```cisco
! 인터페이스 설정 일치 확인
Switch# show interfaces g0/1 switchport
Switch# show interfaces g0/2 switchport

! 강제 재구성
Switch(config)# interface range g0/1-2
Switch(config-if-range)# no channel-group 1
Switch(config-if-range)# channel-group 1 mode active
```

### STP와 EtherChannel
- Port-Channel은 하나의 논리 링크로 STP가 인식
- 개별 포트에 STP 적용 안 됨

<hr class="short-rule">

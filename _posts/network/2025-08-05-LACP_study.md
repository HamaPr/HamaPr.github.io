---
layout: post
title: "LACP"
date: 2025-08-05 17:00:00 +0900
categories: [network]
---

## 1. 개요

**LACP (Link Aggregation Control Protocol)**는 여러 개의 물리적인 포트를 논리적으로 묶어 하나의 고대역폭 링크(채널)를 만드는 기술인 **Link Aggregation**을 위한 IEEE 802.3ad 표준 프로토콜이다.
Cisco 장비에서는 이를 **EtherChannel (이더채널)**이라고 부르며, LACP는 이더채널을 구성하는 방법 중 하나이다.

### 주요 이점
1.  **대역폭 확장**: 물리 링크 대역폭의 합만큼 속도가 증가한다. (1G x 4 = 4G)
2.  **고가용성 (Redundancy)**: 하나의 물리 링크가 끊어져도 전체 논리 링크는 유지되므로 통신이 중단되지 않는다.
3.  **부하 분산 (Load Balancing)**: 트래픽을 여러 물리 포트로 나누어 전송한다.

### Link Aggregation 프로토콜 비교
| 프로토콜 | 표준 | 모드 (적극적/소극적) | 특징 |
|---|---|---|---|
| **LACP** | IEEE 802.3ad | **Active** / **Passive** | 업계 표준. 이기종 장비 간 연결 가능 |
| **PAgP** | Cisco | **Desirable** / **Auto** | 시스코 장비끼리만 연결 가능 |
| **Static** | - | **On** | 프로토콜 없이 강제 결합 (권장하지 않음) |

### LACP 모드 조합
LACP가 정상적으로 동작하려면 양쪽 장비의 모드 조합이 맞아야 한다.
*   **Active + Active**: ✅ (가장 권장)
*   **Active + Passive**: ✅
*   **Passive + Passive**: ❌ (둘 다 기다리기만 하므로 채널 형성 안 됨)

---

## 2. 설정 방법 (Cisco)

### 1) L2 EtherChannel (스위칭)
물리 포트를 묶어 Trunk 또는 Access 포트로 사용하는, 가장 흔한 방식이다.

**[설정 순서]**
1.  물리 인터페이스 범위 지정 (`interface range`)
2.  채널 그룹 생성 및 모드 설정 (`channel-group`)
3.  논리 인터페이스(`port-channel`) 설정

```cisco
! 1. 물리 인터페이스 설정
Switch(config)# interface range gi0/1 - 2
Switch(config-if-range)# channel-group 1 mode active
! mode active 입력 시 LACP가 자동 선택됨

! 2. 논리 인터페이스 설정
Switch(config)# interface port-channel 1
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20
```
> **중요**: 물리 포트가 채널에 묶인 후에는, 모든 설정을 **Port-Channel 인터페이스**에 적용해야 한다. 물리 포트에 개별 설정하면 동기화 오류로 채널이 깨질 수 있다.

### 2) L3 EtherChannel (라우팅)
스위치 포트를 라우티드 포트(No Switchport)로 변환하여 IP 주소를 할당한다. 백본 스위치 간 연결에 주로 사용된다.

```cisco
Switch(config)# interface range gi0/1 - 2
Switch(config-if-range)# no switchport       ! L2 기능 끄기
Switch(config-if-range)# channel-group 1 mode active

Switch(config)# interface port-channel 1
Switch(config-if)# ip address 10.1.1.1 255.255.255.0
```

### 3) 부하 분산 (Load Balancing) 설정
트래픽을 어떤 기준으로 물리 링크에 나눌지 결정한다.
```cisco
Switch(config)# port-channel load-balance src-dst-ip
```

**[알고리즘 종류]**
*   **src-mac**: 출발지 MACC 주소 기준 (기본값인 경우가 많음)
*   **dst-mac**: 목적지 MAC 주소 기준
*   **src-dst-mac**: 출발지/목적지 MAC 주소 조합 (XOR)
*   **src-ip**: 출발지 IP 주소 기준
*   **dst-ip**: 목적지 IP 주소 기준
*   **src-dst-ip**: 출발지/목적지 IP 주소 조합 (권장 - 가장 고르게 분산됨)

---

## 3. 확인 명령어

```cisco
! 1. 이더채널 요약 정보 (가장 중요)
Switch# show etherchannel summary
! 출력 해석:
! Po1(SU)  P(Gi0/1) P(Gi0/2)
! SU: S=Layer2, U=In Use (정상)
! P: Bundled in port-channel (정상)
! D: Down (다운됨)
! I: Stand-alone (독립 상태, 묶이지 않음)

! 2. 상세 정보 확인
Switch# show etherchannel detail

! 3. 논리 인터페이스 상태 확인
Switch# show interfaces port-channel 1

! 4. 부하 분산 방식 확인
Switch# show etherchannel load-balance
```

---

## 4. 실습 구성 예시

두 대의 스위치(SW1, SW2)를 LACP로 묶는 전체 설정 코드이다.

**Topology:**
`SW1 [Gi0/1, Gi0/2] <=========> [Gi0/1, Gi0/2] SW2`

**[SW1 설정]**
```cisco
conf t
interface range gi0/1 - 2
 channel-group 1 mode active
 exit
interface port-channel 1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 end
```

**[SW2 설정]**
```cisco
conf t
interface range gi0/1 - 2
 channel-group 1 mode active
 exit
interface port-channel 1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 end
```

---

## 5. 트러블슈팅

### 포트가 묶이지 않고 Stand-alone(I) 상태일 때
EtherChannel 멤버가 되려면 물리적 조건이 완벽하게 일치해야 한다. 하나라도 다르면 채널 형성이 거부된다.
1.  **속도/이중화**: Speed와 Duplex가 양쪽 포트 모두 같은지 확인한다.
2.  **VLAN**: Access/Trunk 모드, Native VLAN, Allowed VLAN이 일치하는지 확인한다.
3.  **STP**: Spanning Tree 설정이 다르지 않은지 확인한다.

### 통신이 되다 안 되다 할 때 (Flapping)
*   로드 밸런싱 알고리즘 문제일 수 있다. 특정 해시 값에 트래픽이 몰리는 경우 `load-balance` 방식을 변경해 본다.
*   물리 케이블 불량으로 인해 하나의 링크가 간헐적으로 끊기는 경우일 수 있다.

### 포트가 Suspended 상태일 때
*   LACP 패킷을 받지 못하거나 Loop가 감지되어 차단된 상태이다.
*   `show interfaces status`로 포트 상태를 점검하고, 케이블 연결을 확인한다.
*   `shutdown` 후 `no shutdown`으로 인터페이스를 리셋해 본다.

<hr class="short-rule">

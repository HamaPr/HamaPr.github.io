---
layout: post
title: "Chainsaw"
date: 2025-08-11 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개요

**Chainsaw**는 Rust 기반으로 개발된 고속 윈도우 이벤트 로그(EVTX) 분석 및 위협 헌팅 도구이다.
Sigma 탐지 룰을 네이티브로 지원하여 대용량 로그 파일에서 악성 행위 패턴을 신속하게 식별한다.

### 기본 정보

| 항목 | 설명 |
|------|------|
| 개발 | WithSecure Labs |
| 용도 | 포렌식, 위협 탐지 |
| 입력 | EVTX 파일 |
| 출력 | JSON, CSV, 테이블 |

### 주요 기능
- Windows 이벤트 로그 고속 검색
- Sigma 룰 기반 자동 탐지
- 공격 타임라인 생성
- 악성 행위 패턴 식별

---

## 2. 설치 방법

Chainsaw는 별도의 설치 과정 없이 실행 파일만으로 동작한다.

### Windows
```powershell
# 다운로드
Invoke-WebRequest -Uri "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-pc-windows-msvc.zip" -OutFile chainsaw.zip

# 압축 해제
Expand-Archive -Path chainsaw.zip -DestinationPath .
```

### Linux
```bash
# 다운로드
wget https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-unknown-linux-gnu.tar.gz

# 압축 해제 및 실행 권한 부여
tar xzf chainsaw_x86_64-unknown-linux-gnu.tar.gz
cd chainsaw
chmod +x chainsaw
```

### Sigma 룰 준비
탐지에 필요한 Sigma 룰셋을 다운로드한다.
```bash
git clone https://github.com/SigmaHQ/sigma.git
```

---

## 3. 기본 사용법

### 로그 검색
특정 이벤트 ID나 키워드를 포함한 로그를 검색한다.

```bash
# 이벤트 ID 검색 (로그온 성공: 4624)
./chainsaw search -t "Event.System.EventID: 4624" ./logs/

# 키워드 검색 ("mimikatz" 문자열 포함)
./chainsaw search -s "mimikatz" ./logs/
```

### 위협 헌팅
Sigma 룰을 적용하여 악성 행위를 자동으로 탐지한다. 가장 많이 사용되는 기능이다.

```bash
./chainsaw hunt ./logs/ -s sigma/rules/windows/ --mapping mappings/sigma-event-logs-all.yml
```

### 출력 형식 지정
분석 결과를 JSON이나 CSV로 저장하여 다른 도구에서 활용할 수 있다.

```bash
# JSON 출력
./chainsaw hunt ./logs/ -s sigma/rules/ -o results.json --json --mapping mappings/sigma-event-logs-all.yml

# CSV 출력
./chainsaw hunt ./logs/ -s sigma/rules/ -o results.csv --csv --mapping mappings/sigma-event-logs-all.yml
```

---

## 4. 실습: 침해 사고 분석

### 주요 탐지 이벤트 ID
분석 시 중점적으로 확인해야 할 이벤트 ID이다.

| Event ID | 설명 | 카테고리 |
|----------|------|----------|
| **4624** | 로그온 성공 | 로그온 |
| **4625** | 로그온 실패 (Brute Force 의심) | 로그온 |
| **4672** | 특수 권한 할당 (Administrator 등) | 권한 상승 |
| **4720** | 사용자 계정 생성 | 지속성 유지 |
| **4688** | 새 프로세스 생성 (명령어 인자 확인) | 실행 |

### 분석 예시
**로그온 실패 분석 (Brute Force 탐지)**
```bash
./chainsaw search -t "Event.System.EventID: 4625" ./logs/ --json | jq '.[]'
```

**특정 기간 필터링**
침해 사고 발생 시간대를 알고 있다면 범위를 지정하여 분석 속도를 높일 수 있다.
```bash
./chainsaw hunt ./logs/ -s sigma/rules/ \
  --mapping mappings/sigma-event-logs-all.yml \
  --from "2024-01-01T00:00:00" \
  --to "2024-12-31T23:59:59"
```

![Chainsaw 탐지 결과](/assets/images/hacking-tools/Chainsaw.png)

---

## 5. 트러블슈팅

### 인코딩 문제
Windows 환경에서 한글 로그가 깨져 보일 경우 JSON으로 출력하여 확인하거나 PowerShell 인코딩을 변경해야 한다.
```bash
# 결과를 UTF-8 JSON으로 저장
./chainsaw hunt ./logs/ -s sigma/rules/ -o results.json --json --mapping mappings/sigma-event-logs-all.yml
```

### 매핑 오류
Sigma 룰과 Chainsaw 간의 필드 매핑이 맞지 않을 경우 오류가 발생할 수 있다. 반드시 최신 `mappings` 파일을 사용해야 한다.
```bash
--mapping mappings/sigma-event-logs-all.yml
```

<hr class="short-rule">

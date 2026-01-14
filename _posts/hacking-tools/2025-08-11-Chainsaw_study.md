---
layout: post
title: "Chainsaw 로그 분석"
date: 2025-08-11 17:00:00 +0900
categories: [hacking-tools]
---

## 1. 개념

**Chainsaw**는 Rust 기반으로 개발된 고속 Windows 이벤트 로그(EVTX) 분석 및 위협 헌팅 도구입니다.
Sigma 탐지 룰을 네이티브로 지원하여 대용량 로그 파일에서 악성 행위 패턴을 신속하게 식별합니다.

### 기본 정보

| 항목 | 설명 |
|------|------|
| 개발 | WithSecure Labs |
| 용도 | 포렌식, 위협 탐지 |
| 입력 | EVTX 파일 |
| 출력 | JSON, CSV, 테이블 |

### 주요 기능
- Windows 이벤트 로그 검색
- Sigma 룰 기반 탐지
- 타임라인 생성
- 악성 행위 탐지

---

## 2. 설치 방법

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

tar xzf chainsaw_x86_64-unknown-linux-gnu.tar.gz
cd chainsaw
chmod +x chainsaw
```

### Sigma 룰 다운로드
```bash
# chainsaw 디렉토리 내부에서 실행
git clone https://github.com/SigmaHQ/sigma.git
```

---

## 3. 사용법

### 기본 검색
```bash
# 이벤트 로그 검색
./chainsaw search -t "Event.System.EventID: 4624" ./logs/

# 키워드 검색
./chainsaw search -s "mimikatz" ./logs/
```

### Sigma 룰 적용
```bash
# 헌트 모드 (Sigma 룰 자동 적용)
./chainsaw hunt ./logs/ -s sigma/rules/windows/ --mapping mappings/sigma-event-logs-all.yml
```

### 출력 형식
```bash
# JSON 출력
./chainsaw hunt ./logs/ -s sigma/rules/ -o results.json --json --mapping mappings/sigma-event-logs-all.yml

# CSV 출력
./chainsaw hunt ./logs/ -s sigma/rules/ -o results.csv --csv --mapping mappings/sigma-event-logs-all.yml
```

---

## 4. 주요 탐지 항목

### 로그온 이벤트

| Event ID | 설명 |
|----------|------|
| 4624 | 로그온 성공 |
| 4625 | 로그온 실패 |
| 4634 | 로그오프 |
| 4648 | 명시적 자격 증명 로그온 |

### 권한 상승

| Event ID | 설명 |
|----------|------|
| 4672 | 특수 권한 할당 |
| 4673 | 권한 있는 서비스 호출 |
| 4728 | 보안 그룹에 멤버 추가 |

### 프로세스 실행

| Event ID | 설명 |
|----------|------|
| 4688 | 새 프로세스 생성 |
| 4689 | 프로세스 종료 |

---

## 5. 실습 예시

### 계정 변경 탐지
```bash
./chainsaw search -t "Event.System.EventID: 4720" ./logs/
# 4720: 사용자 계정 생성
```

### 로그온 실패 분석
```bash
./chainsaw search -t "Event.System.EventID: 4625" ./logs/ --json | jq '.[]'
```

### 시간 기반 필터링
```bash
./chainsaw hunt ./logs/ -s sigma/rules/ \
  --mapping mappings/sigma-event-logs-all.yml \
  --from "2019-01-01T00:00:00" \
  --to "2025-12-31T23:59:59"
```

![Chainsaw 탐지 결과](/assets/images/hacking-tools/Chainsaw.png)

---

## 6. 트러블슈팅

### 인코딩 문제
```bash
# 결과를 UTF-8로 저장
./chainsaw hunt ./logs/ -s sigma/rules/ -o results.json --json --mapping mappings/sigma-event-logs-all.yml
# Windows에서 한글 깨짐 시 PowerShell에서 실행
```

### Sigma 룰 매핑 오류
```bash
# 올바른 매핑 파일 사용
--mapping mappings/sigma-event-logs-all.yml
```

<hr class="short-rule">

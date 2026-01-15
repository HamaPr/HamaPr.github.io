---
layout: post
title: "Awk & Sed"
date: 2025-06-21 17:00:00 +0900
categories: [linux]
---

## 1. 개요

**awk**와 **sed**는 리눅스 커맨드 라인에서 텍스트 데이터를 효율적으로 처리하기 위한 표준 도구이다.
로그 파일 분석, 데이터 필터링, 문자열 치환 등의 작업을 자동화하여 시스템 관리자의 생산성을 크게 높여준다.

### 비교

| 도구 | 전체 이름 | 주 용도 | 특징 |
|------|-----------|---------|------|
| **sed** | Stream Editor | 행(Line) 단위 편집 | 문자열 치환, 삭제, 삽입에 강점 |
| **awk** | Aho, Weinberger, Kernighan | 필드(Field) 단위 처리 | 데이터 추출, 산술 연산, 보고서 생성 |

---

## 2. Awk (패턴 스캔 및 처리)

Awk는 데이터를 공백이나 구분자로 나뉜 '필드' 단위로 처리하는 프로그래밍 언어이다.

### 기본 문법
```bash
awk '패턴 {동작}' 파일명
```

### 주요 내장 변수
| 변수 | 의미 | 예시 |
|------|------|------|
| `$0` | 현재 처리 중인 전체 줄 | `print $0` |
| `$1`, `$2` | 첫 번째, 두 번째 필드 | `print $1` |
| `NR` | 현재 줄 번호 (Number of Records) | `print NR` |
| `NF` | 필드 개수 (Number of Fields) | `print NF` |
| `FS` | 필드 구분자 (Field Separator) | `awk -F:` (구분자 지정) |

### 사용 예시
```bash
# 1. 특정 필드 출력 (1번째, 3번째 컬럼)
awk '{print $1, $3}' employees.txt

# 2. 줄 번호와 함께 출력
awk '{print NR, $0}' employees.txt

# 3. 구분자 변경 (:으로 구분된 /etc/passwd 처리)
awk -F: '{print $1, $6}' /etc/passwd

# 4. 조건문 활용 (3번째 필드가 50000 이상인 경우)
awk '$3 >= 50000 {print $1, $3}' employees.txt

# 5. 통계 계산 (3번째 필드 합계 출력)
awk '{sum+=$3} END {print "Total:", sum}' employees.txt
```

---

## 3. Sed (스트림 편집기)

Sed는 텍스트 스트림을 입력받아 규칙에 따라 변환 후 출력하는 비대화형 편집기이다.

### 기본 문법
```bash
sed '옵션' '명령어' 파일명
```

### 주요 명령어
| 명령 | 의미 | 예시 |
|------|------|------|
| `s` | 치환 (Substitute) | `s/old/new/` |
| `d` | 삭제 (Delete) | `1d` (1행 삭제) |
| `p` | 출력 (Print) | `-n` 옵션과 함께 사용 |
| `i` | 삽입 (Insert) | 행 앞에 텍스트 추가 |

### 사용 예시
```bash
# 1. 문자열 치환 (모든 apple을 orange로 변경)
sed 's/apple/orange/g' fruits.txt

# 2. 특정 줄 삭제 (빈 줄 삭제)
sed '/^$/d' file.txt

# 3. 특정 줄만 출력 (10~20번째 줄)
sed -n '10,20p' file.txt

# 4. 파일 직접 수정 (-i 옵션, 주의 필요)
sed -i 's/foo/bar/g' config.conf
```

---

## 4. 실습: 로그 정제 및 분석

실제 로그 파일을 대상으로 awk와 sed를 조합하여 의미 있는 데이터를 추출한다.

### 시나리오 1: 로그 정제
날짜 형식을 단순화하고 디버그 로그를 제거하며 IP 주소를 마스킹한다.

```bash
# 원본 로그: [2025-06-21 10:00:01] DEBUG User 192.168.1.5 logged in
sed -E \
  -e 's/\[.*\]/[TIME]/' \                 # 시간 정보를 [TIME]으로 변경
  -e '/DEBUG/d' \                         # DEBUG 라인 삭제
  -e 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/***.***.***.***/g' \ # IP 마스킹
  app.log
```

### 시나리오 2: 웹 서버 로그 분석
Apache/Nginx 접속 로그(`access.log`)에서 가장 많이 접속한 IP Top 5를 추출한다.

```bash
# 1. IP 추출 (1번째 필드)
# 2. 정렬 및 카운트
# 3. 역순 정렬 후 상위 5개 출력
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -5
```

### 시나리오 3: 디스크 사용량 모니터링
디스크 사용량이 80% 이상인 파티션만 경고 메시지로 출력한다.

```bash
df -h | awk 'NR>1 {gsub("%","",$5); if($5 > 80) print "Warning: " $1 " is at " $5 "%"}'
```

![awk 실행 결과](/assets/images/linux/awk.png)

<hr class="short-rule">

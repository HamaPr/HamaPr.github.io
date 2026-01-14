---
layout: post
title: "awk와 sed 텍스트 처리"
date: 2025-06-21 17:00:00 +0900
categories: [linux]
---

## 1. 개념

**awk**와 **sed**는 Linux에서 텍스트 처리를 위한 핵심 도구.

### 기본 비교
| 도구 | 주 용도 | 특징 |
|------|---------|------|
| awk | 필드 단위 데이터 처리 | 계산, 분석, 보고서 생성 |
| sed | 패턴 기반 줄 편집 | 치환, 삭제, 추출 |

### 언제 무엇을 사용하나?
- **sed**: 단순 문자열 치환, 특정 줄 삭제, 패턴 추출
- **awk**: 필드별 데이터 추출, 계산, 조건 처리

---

## 2. awk 기초

### 기본 문법
```bash
awk 'pattern {action}' file
```

### 필드 변수
| 변수 | 의미 |
|------|------|
| $0 | 전체 줄 |
| $1, $2, ... | 첫 번째, 두 번째 필드... |
| NR | 현재 줄 번호 |
| NF | 현재 줄의 필드 개수 |
| FS | 필드 구분자 (기본: 공백) |

### 예제 파일 (employees.txt)
```
John Doe 50000 IT
Jane Smith 60000 HR
Bob Johnson 55000 IT
```

### 기본 사용법
```bash
# 특정 필드 출력
awk '{print $1, $3}' employees.txt
# John 50000
# Jane 60000
# Bob 55000

# 줄 번호와 함께 출력
awk '{print NR, $0}' employees.txt

# 필드 개수 확인
awk '{print NF " fields in line " NR}' employees.txt
```

### 필드 구분자 변경
```bash
# /etc/passwd 파일 분석 (: 구분자)
awk -F: '{print $1, $6}' /etc/passwd
# root /root
# nobody /nonexistent
# user /home/user

# CSV 파일 처리
awk -F, '{print $2, $3}' data.csv
```

---

## 3. awk 조건부 처리

### 조건문
```bash
# 급여 55000 이상인 직원
awk '$3 >= 55000 {print $1, $3}' employees.txt

# IT 부서 직원만
awk '$4 == "IT" {print $1, $3}' employees.txt

# 복합 조건 (AND)
awk '$3 > 50000 && $4 == "IT" {print}' employees.txt
```

### BEGIN/END 블록
```bash
# 헤더 추가
awk 'BEGIN {print "Name\tSalary"} {print $1, "\t", $3}' employees.txt

# 급여 합계 계산
awk '{sum+=$3} END {print "Total Salary:", sum}' employees.txt
# Total Salary: 165000

# 평균 계산
awk '{sum+=$3; count++} END {print "Average:", sum/count}' employees.txt
```

### 배열 활용
```bash
# 부서별 인원 수
awk '{dept[$4]++} END {for (d in dept) print d, dept[d]}' employees.txt
# IT 2
# HR 1

# 부서별 급여 합계
awk '{salaries[$4]+=$3} END {for (d in salaries) print d, salaries[d]}' employees.txt

# 부서별 평균 급여
awk '{sum[$4]+=$3; count[$4]++} END {for (d in sum) print d, sum[d]/count[d]}' employees.txt
```

---

## 4. sed 기초

### 기본 문법
```bash
sed 's/패턴/대체문자열/플래그' file
```

### 플래그
| 플래그 | 의미 |
|--------|------|
| g | 모든 매칭 치환 (global) |
| i | 대소문자 무시 (GNU sed) |
| p | 매칭된 줄 출력 |
| d | 줄 삭제 |

### 기본 치환
```bash
# 모든 "apple"을 "orange"로 변경
sed 's/apple/orange/g' fruits.txt

# 대소문자 무시
sed 's/apple/orange/gi' fruits.txt

# 첫 번째 매칭만 치환 (g 없이)
sed 's/error/warning/' log.txt
```

### 특정 줄만 치환
```bash
# 3번째 줄만 치환
sed '3s/error/warning/' log.txt

# 5~10줄에서만 치환
sed '5,10s/localhost/127.0.0.1/' config.txt
```

---

## 5. sed 줄 편집

### 줄 삭제
```bash
# 빈 줄 삭제
sed '/^$/d' file.txt

# 주석 줄 삭제 (#으로 시작)
sed '/^#/d' config.ini

# "DEBUG" 포함된 줄 삭제
sed '/DEBUG/d' app.log
```

### 줄 번호로 작업
```bash
# 첫 5줄만 출력 (나머지 삭제)
sed '6,$d' longfile.txt

# 특정 줄만 출력 (-n과 p 조합)
sed -n '10,20p' file.txt
```

### 패턴 사이 내용 추출
```bash
# <!-- START -->와 <!-- END --> 사이
sed -n '/<!-- START -->/,/<!-- END -->/p' html.txt
```

---

## 6. sed 실무 활용

### 파일 직접 수정 (-i 옵션)
```bash
# 원본 파일 직접 수정 (백업 .bak 생성)
sed -i.bak 's/old/new/g' original.txt

# 백업 없이 직접 수정 (주의!)
sed -i 's/old/new/g' original.txt
```

### 다중 명령 실행
```bash
# 여러 작업 한 번에
sed -e '/^$/d' -e '/^#/d' -e 's/\t/ /g' config.cfg
# 1. 빈 줄 삭제
# 2. 주석 삭제
# 3. 탭을 공백으로
```

### 역참조 (Backreference)
```bash
# 날짜 형식 변환 (YYYY-MM-DD → DD/MM/YYYY)
sed -E 's/([0-9]{4})-([0-9]{2})-([0-9]{2})/\3\/\2\/\1/' dates.txt
```

### 구분자 변경
```bash
# 경로 치환 시 / 대신 | 사용
sed 's|/path/old|/path/new|g' paths.txt
```

---

## 7. awk + sed 조합

### 로그 분석
```bash
# ERROR 줄에서 타임스탬프와 메시지 추출
sed -n '/ERROR/p' app.log | awk '{print $1, $3}'

# IP별 접속 횟수 (Top 5)
sed -nE 's/.*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p' access.log | \
awk '{ips[$1]++} END {for (ip in ips) print ip, ips[ip]}' | \
sort -nr -k2 | head -5
```

### 시스템 모니터링
```bash
# 디스크 사용량 80% 이상인 파티션
df -h | sed '1d' | awk '{gsub(/%/,"",$5); if ($5 > 80) print $1 " is at " $5 "%"}'

# 메모리 많이 쓰는 프로세스 Top 5
ps aux | sed 's/  */ /g' | awk '{print $4, $11}' | sort -nr | head -5
```

### /etc/passwd 분석
```bash
# bash 쉘 사용자 중 UID 1000 이상
sed '/\/bin\/bash/!d' /etc/passwd | awk -F: '$3 >= 1000 {print $1}'
```

---

## 8. 실무 예제

### 로그 파일 정제
```bash
# 타임스탬프 통일 + DEBUG 제거 + IP 마스킹
sed -E \
  -e 's/\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}\]/[TIMESTAMP]/' \
  -e '/DEBUG/d' \
  -e 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/***.***.***.***/g' \
  app.log
```

### CSV 파일 통계
```bash
# 두 번째 열의 평균
awk -F, '{sum+=$2; count++} END {print sum/count}' data.csv
```

### 설정 파일 변경
```bash
# 모든 .conf 파일에서 값 변경
find /etc -name "*.conf" -exec sed -i 's/old_value/new_value/g' {} +
```

![awk 실행 결과](/assets/images/linux/awk.png)

<hr class="short-rule">

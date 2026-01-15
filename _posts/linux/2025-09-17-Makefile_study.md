---
layout: post
title: "Make & Makefile"
date: 2025-09-17 17:00:00 +0900
categories: [linux]
---

## 1. 개요

**Make**는 파일 간의 의존성 관계를 파악하여, 소스 코드가 변경된 부분만 골라서 효율적으로 다시 컴파일(Rebuild)하는 빌드 자동화 도구이다.
**Makefile**은 이러한 의존성과 빌드 명령어를 정의한 설정 파일이다. 대규모 프로젝트에서 컴파일 시간을 단축하고 빌드 과정을 표준화하기 위해 필수적으로 사용된다.

### 소스 설치 과정 (Configure, Make, Install)
오픈소스 소프트웨어를 설치할 때 흔히 보는 3단계 과정의 핵심이 바로 `make`이다.

```mermaid
flowchart LR
    Configure["./configure"] -->|Makefile 생성| Make["make"]
    Make -->|컴파일 수행| Install["make install"]
```

---

## 2. Makefile 구조

Makefile은 **Target(목표)**, **Dependency(의존성)**, **Command(명령어)**의 세 가지 요소로 구성된다.

```makefile
target: dependency
    command
```

*   **Target**: 생성하고자 하는 파일명 (실행 파일, 오브젝트 파일 등) 또는 행동의 이름 (clean 등)
*   **Dependency**: 타겟을 만들기 위해 필요한 소스 파일이나 다른 타겟
*   **Command**: 타겟을 생성하기 위해 실행할 쉘 명령어. **반드시 탭(Tab)으로 들여써야 한다.**

### 기본 예제
```makefile
# 'app'이라는 실행 파일을 만들기 위해 'main.c'가 필요함
app: main.c
	gcc -o app main.c

# 빌드 산출물 삭제
clean:
	rm -f app
```

---

## 3. 변수 활용

반복되는 값(컴파일러, 옵션 등)을 변수로 정의하여 유지보수성을 높인다.

### 매크로 정의
```makefile
CC = gcc
CFLAGS = -Wall -g
TARGET = myapp

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c
```

### 자동 변수 (Automatic Variables)
명령어 작성 시 타겟과 의존성 파일명을 자동으로 대입해 준다.

| 변수 | 의미 |
|------|------|
| `$@` | 현재 타겟의 이름 |
| `$<` | 첫 번째 의존성 파일의 이름 |
| `$^` | 모든 의존성 파일의 목록 |

```makefile
app: main.o utils.o
	$(CC) -o $@ $^
    # -> gcc -o app main.o utils.o 와 동일
```

---

## 4. 실습: C 프로그램 빌드

`main.c`, `func.c`, `func.h`로 구성된 간단한 프로그램을 빌드하는 Makefile을 작성한다.

**Makefile**:
```makefile
CC = gcc
CFLAGS = -Wall -O2
OBJS = main.o func.o
TARGET = app

# 1. 최종 실행 파일 생성 (링크)
$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS)

# 2. 오브젝트 파일 생성 (컴파일)
# .c 파일이 변경되면 .o 파일을 다시 만듦
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# 3. 정리 (Clean)
clean:
	rm -f $(OBJS) $(TARGET)
```

### 실행 방법
```bash
# 빌드 수행
make

# 빌드 결과물 삭제
make clean
```

---

## 5. 트러블슈팅

### "missing separator" 오류
Make는 들여쓰기에 매우 민감하다. 명령어 라인은 반드시 스페이스가 아닌 **탭(Tab) 키**로 시작해야 한다.
```bash
Makefile:2: *** missing separator.  Stop.
```
*   **해결**: 에디터 설정에서 "Tab을 스페이스로 변환" 옵션을 끄거나, 직접 탭을 입력한다. `cat -A Makefile` 명령어로 `^I` 문자가 보이는지 확인한다.

### 의존성 누락
헤더 파일(.h)이 변경되었는데 재컴파일이 안 되는 경우, 타겟의 의존성 목록에 헤더 파일을 추가하지 않았기 때문이다.
```makefile
main.o: main.c func.h  # func.h 추가
```

<hr class="short-rule">

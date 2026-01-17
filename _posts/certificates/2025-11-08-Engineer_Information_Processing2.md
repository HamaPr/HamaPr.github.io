---
layout: post
title: 정보처리기사 최종 합격
date: 2025-11-08 15:00:00 +0900
categories: [certificates]
tags: [정보처리기사, KCA, software, 실기, C, Java, Python]
---

한국산업인력공단에서 시행하는 정보처리기사 실기 시험에 최종 합격했다. 실기 시험은 필기에서 다룬 이론적 지식을 바탕으로, C, Java, Python 등의 프로그래밍 언어 코드의 실행 결과를 예측하거나 빈칸을 채우는 실무적인 능력을 평가한다.

각 언어의 철학을 이해하고 핵심적인 메커니즘을 깊이 있게 파악하는 것이 중요했다.

---

### 1. C 언어: 메모리 직접 제어와 저수준(Low-Level) 프로그래밍의 정수

C 언어는 메모리 주소를 직접 다루는 포인터의 개념이 가장 중요하며, 이를 통해 컴퓨터의 동작 원리에 가장 가깝게 접근하는 능력을 평가한다. 배열, 구조체, 함수 포인터 등이 결합된 복합적인 문제 해결 능력이 요구된다.

- ***배열과 포인터의 관계 심층 이해***
  배열의 이름은 배열의 첫 번째 요소의 주소값, 즉 '포인터 상수'다. 따라서 `arr[i]`는 컴파일러에 의해 `*(arr + i)`로 해석된다. 이 원리를 이해하면 포인터의 증감 연산을 통해 배열의 요소를 순회하는 코드의 실행 결과를 정확히 예측할 수 있다.

- ***함수 포인터 (Function Pointer)***
  함수 또한 코드 영역에 저장된 메모리 주소를 가지며, 이 주소를 저장하는 변수가 바로 함수 포인터다. 함수 포인터를 사용하면 함수를 다른 함수의 인자로 전달하거나, 상황에 따라 호출할 함수를 동적으로 결정하는 '콜백(Callback)' 메커니즘을 구현할 수 있다.

- ***구조체 포인터와 동적 메모리 할당***
  `struct`는 관련 데이터를 묶는 역할뿐만 아니라, `malloc`과 `free`를 이용한 동적 메모리 할당과 결합될 때 그 진가가 드러난다. 구조체 포인터를 통해 할당된 메모리에 접근하며, 멤버를 참조할 때는 화살표 연산자(`->`)를 사용한다. 이는 연결 리스트나 트리 같은 동적 자료구조 구현의 기본이 된다.

```c
#include <stdio.h>
#include <stdlib.h>

// 학생 정보를 담는 구조체 정의
typedef struct {
    int id;
    char name[20];
} Student;

void printStudent(Student *s) {
    // 구조체 포인터를 통해 멤버에 접근
    printf("ID: %d, Name: %s\n", s->id, s->name);
}

int main() {
    // 구조체 크기만큼 동적으로 메모리 할당
    Student *p_std = (Student*)malloc(sizeof(Student));
    if (p_std == NULL) return -1; // 할당 실패 시 종료

    p_std->id = 20251108;
    strcpy(p_std->name, "홍길동");

    printStudent(p_std);

    free(p_std); // 할당된 메모리 해제는 필수
    return 0;
}
// 출력:
// ID: 20251108, Name: 홍길동
```

---

### 2. Java 언어: 객체지향 설계와 추상화의 활용

Java는 순수한 객체지향 언어로서, 상속과 다형성을 기반으로 한 유연하고 확장 가능한 코드 설계 능력을 중점적으로 평가한다. 추상 클래스와 인터페이스의 차이를 명확히 이해하고 활용하는 것이 핵심이다.

- ***상속과 다형성(Polymorphism)***
  다형성은 '하나의 타입으로 여러 타입의 객체를 참조'하는 기술이다. 부모 클래스 타입의 참조 변수로 자식 클래스의 인스턴스를 가리킬 수 있으며, 이때 메서드를 호출하면 참조 변수의 타입이 아닌 실제 인스턴스의 오버라이딩된 메서드가 호출된다. 이는 코드의 결합도를 낮추고 유연성을 높인다.

- ***추상 클래스(Abstract Class) vs 인터페이스(Interface)***
  **추상 클래스**는 미완성된 설계도로, 일부 구현된 메서드와 미구현된 추상 메서드를 모두 가질 수 있다. `extends`를 통해 상속받아 기능을 확장하는 'IS-A' 관계에 사용된다.
  **인터페이스**는 모든 메서드가 추상 메서드인 순수한 설계 명세다. `implements`를 통해 클래스에 특정 '기능'을 부여하는 'HAS-A' 또는 'CAN-DO' 관계에 사용되며, 다중 구현이 가능하다.

- ***컬렉션 프레임워크 (Collection Framework)***
  데이터의 그룹을 효율적으로 관리하기 위한 라이브러리로, `List`, `Set`, `Map` 인터페이스가 핵심이다. `ArrayList`의 동작 방식, `HashMap`의 키-값 쌍 저장 원리 등 각 컬렉션의 특징과 주요 메서드를 이해하고 있어야 한다.

```java
import java.util.ArrayList;
import java.util.List;

// '날 수 있는' 기능을 정의하는 인터페이스
interface Flyable {
    void fly();
}

class Bird implements Flyable {
    @Override
    public void fly() {
        System.out.println("새가 하늘을 납니다.");
    }
}

class Airplane implements Flyable {
    @Override
    public void fly() {
        System.out.println("비행기가 이륙합니다.");
    }
}

public class Main {
    public static void main(String[] args) {
        List<Flyable> flyingThings = new ArrayList<>();
        flyingThings.add(new Bird());
        flyingThings.add(new Airplane());

        for (Flyable thing : flyingThings) {
            thing.fly(); // 같은 fly() 호출이지만, 실제 인스턴스에 따라 다른 동작 수행 (다형성)
        }
    }
}
// 출력:
// 새가 하늘을 납니다.
// 비행기가 이륙합니다.
```

---

### 3. Python 언어: 파이썬다운(Pythonic) 코드와 동적 데이터 처리

Python은 간결하고 가독성 높은 문법을 통해 생산성을 극대화하는 언어다. 반복문을 대체하는 리스트 컴프리헨션, 일급 객체로서의 함수 등 파이썬 고유의 강력한 기능을 활용하는 능력을 평가한다.

- ***리스트 컴프리헨션 (List Comprehension)***
  `for` 루프와 `if` 조건문을 한 줄에 압축하여 새로운 리스트를 생성하는 매우 파이썬다운(Pythonic) 기능이다. 기존 코드보다 훨씬 간결하고 가독성이 높으며, 처리 속도 또한 빠르다.

- ***함수는 일급 객체 (First-Class Citizen)***
  Python에서 함수는 변수에 할당할 수 있고, 다른 함수의 인자로 전달할 수 있으며, 함수의 결과로 반환될 수도 있다. 이러한 특성은 코드를 모듈화하고 함수형 프로그래밍 스타일을 구현하는 데 핵심적인 역할을 한다.

- ***딕셔너리(Dictionary)의 고급 활용***
  단순한 키-값 조회를 넘어, `.keys()`, `.values()`, `.items()` 메서드를 이용해 딕셔너리의 구성 요소를 순회하는 방법을 이해해야 한다. 특히 `for key, value in my_dict.items():` 구문은 딕셔너리 처리에 필수적이다. 또한, 존재하지 않는 키에 접근할 때 오류 대신 기본값을 반환하는 `.get()` 메서드의 활용법도 중요하다.

```python
# 1. 리스트 컴프리헨션
# 1부터 10까지의 수 중에서 짝수만 제곱하여 리스트 생성
squares = [x**2 for x in range(1, 11) if x % 2 == 0]
print(f"Squares: {squares}")

# 2. 함수를 인자로 전달
def apply_operation(func, x, y):
    return func(x, y)

def add(x, y):
    return x + y

def subtract(x, y):
    return x - y

result_add = apply_operation(add, 10, 5)
result_sub = apply_operation(subtract, 10, 5)
print(f"Add result: {result_add}, Subtract result: {result_sub}")

# 3. 딕셔너리 아이템 순회
grades = {'Alice': 85, 'Bob': 92, 'Charlie': 78}
for name, score in grades.items():
    print(f"{name}'s score is {score}")
```
```python
# 출력:
# Squares: [4, 16, 36, 64, 100]
# Add result: 15, Subtract result: 5
# Alice's score is 85
# Bob's score is 92
# Charlie's score is 78
```

---

## 키워드 정리

### C언어

| 키워드 | 설명 |
|--------|------|
| `*ptr` | 포인터가 가리키는 값 (역참조) |
| `&var` | 변수의 주소 |
| `arr[i]` = `*(arr+i)` | 배열과 포인터 연산 등가 |
| `->` | 구조체 포인터 멤버 접근 |
| `malloc` / `free` | 동적 메모리 할당/해제 |
| `strcpy` / `strncpy` | 문자열 복사 (안전한 버전 권장) |
| `sizeof` | 자료형/변수 크기 반환 |

### Java

| 키워드 | 설명 |
|--------|------|
| `extends` | 클래스 상속 (단일 상속) |
| `implements` | 인터페이스 구현 (다중 가능) |
| `@Override` | 메서드 오버라이딩 명시 |
| `super` | 부모 클래스 참조 |
| `abstract` | 추상 클래스/메서드 선언 |
| `ArrayList` | 가변 크기 배열 (List 구현체) |
| `HashMap` | 키-값 쌍 저장 (Map 구현체) |

### Python

| 키워드 | 설명 |
|--------|------|
| `[x for x in list]` | 리스트 컴프리헨션 |
| `dict.items()` | 딕셔너리 키-값 쌍 순회 |
| `dict.get(key, default)` | 키 없을 때 기본값 반환 |
| `split()` | 문자열 분리 → 리스트 |
| `lambda x: x+1` | 익명 함수 |
| `range(start, end, step)` | 범위 생성 |

---

## 주요 학습 포인트

### C언어 주요 유형

**포인터 연산**
```c
int arr[] = {10, 20, 30, 40};
int *p = arr;
printf("%d", *(p + 2));  // 출력: 30
```

**구조체 포인터 멤버 접근**
```c
typedef struct { int x; int y; } Point;
Point *p = (Point*)malloc(sizeof(Point));
p->x = 10;  // 화살표 연산자
(*p).y = 20;  // 동일한 의미
```

**재귀 함수 결과값 추적**
```c
int func(int n) {
    if (n <= 1) return 1;
    return n * func(n - 1);
}
// func(5) = 5 * 4 * 3 * 2 * 1 = 120
```

### Java 주요 유형

**상속과 오버라이딩**
```java
class Parent {
    void print() { System.out.println("Parent"); }
}
class Child extends Parent {
    @Override
    void print() { System.out.println("Child"); }
}
Parent p = new Child();
p.print();  // 출력: Child (다형성)
```

**String 클래스 메서드**
```java
String s = "Hello World";
s.length();          // 11
s.substring(0, 5);   // "Hello"
s.charAt(6);         // 'W'
s.split(" ");        // ["Hello", "World"]
```

### Python 주요 유형

**리스트 컴프리헨션**
```python
# 1~10 중 짝수의 제곱
[x**2 for x in range(1, 11) if x % 2 == 0]
# 결과: [4, 16, 36, 64, 100]
```

**딕셔너리 순회**
```python
d = {'a': 1, 'b': 2}
for k, v in d.items():
    print(k, v)
# 출력:
# a 1
# b 2
```

**split과 join**
```python
s = "a,b,c"
arr = s.split(",")  # ['a', 'b', 'c']
"-".join(arr)       # "a-b-c"
```

---

## 핵심 요약

### 언어별 핵심 차이

| 항목 | C | Java | Python |
|------|---|------|--------|
| 타입 | 정적 | 정적 | 동적 |
| 메모리 관리 | 수동 (malloc/free) | 자동 (GC) | 자동 (GC) |
| 포인터 | 직접 사용 | 없음 (참조만) | 없음 |
| 상속 | 없음 (구조체) | 단일 상속 | 다중 상속 |
| 실행 | 컴파일 | JVM 바이트코드 | 인터프리터 |

### 자주 헷갈리는 개념

| 항목 | 설명 |
|------|------|
| `=` vs `==` | 대입 vs 비교 |
| `++i` vs `i++` | 전위 증가 vs 후위 증가 |
| `&&` vs `&` | 논리 AND vs 비트 AND |
| `break` vs `continue` | 루프 탈출 vs 다음 반복 |

### 컬렉션 비교 (Java)

| 인터페이스 | 특징 | 구현체 |
|------------|------|--------|
| List | 순서 O, 중복 O | ArrayList, LinkedList |
| Set | 순서 X, 중복 X | HashSet, TreeSet |
| Map | 키-값 쌍 | HashMap, TreeMap |

### 정렬 알고리즘 시간복잡도

| 알고리즘 | 평균 | 최악 |
|----------|------|------|
| 버블 정렬 | O(n²) | O(n²) |
| 선택 정렬 | O(n²) | O(n²) |
| 삽입 정렬 | O(n²) | O(n²) |
| 퀵 정렬 | O(n log n) | O(n²) |
| 병합 정렬 | O(n log n) | O(n log n) |

---

필기에서 배운 개념을 바탕으로 C, Java, Python 각 언어의 핵심 철학을 통해 실제 코드가 어떻게 작동하는지 확인하며 실무 능력을 키울 수 있었다. 이 덕분에 정보처리기사 자격증 취득이라는 결실을 맺을 수 있었다.

<hr class="short-rule">
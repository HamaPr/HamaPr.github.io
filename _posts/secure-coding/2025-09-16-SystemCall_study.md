---
layout: post
title: "C Language System Call"
date: 2025-09-16 17:00:00 +0900
categories: [secure-coding]
---

## 1. 개요

**시스템 콜(System Call)**은 사용자 모드(User Mode)에서 실행되는 프로그램이 커널 모드(Kernel Mode)의 기능을 사용하기 위해 운영체제에 요청하는 표준 인터페이스이다.
파일 읽기/쓰기, 프로세스 생성, 하드웨어 제어와 같은 특권 명령은 직접 실행할 수 없으므로 반드시 시스템 콜을 통해야 한다.

### 핵심 기능
1.  **자원 접근 제어**: 사용자 애플리케이션이 하드웨어(디스크, 네트워크 등)에 임의로 접근하는 것을 막고 커널을 통해서만 접근하게 한다.
2.  **보안 및 안정성**: 잘못된 요청으로부터 시스템을 보호하고, 프로세스 간의 간섭을 방지한다.
3.  **표준 입출력**: `open`, `read`, `write` 등의 함수를 통해 파일 및 장치 I/O를 수행한다.

### 파일 디스크립터 (File Descriptor)
리눅스/유닉스에서 파일을 다룰 때 사용하는 정수형 식별자이다.
| FD | 설명 | 스트림 |
|----|------|--------|
| **0** | 표준 입력 (Standard Input) | stdin |
| **1** | 표준 출력 (Standard Output) | stdout |
| **2** | 표준 에러 (Standard Error) | stderr |

---

## 2. open() 함수

파일을 열거나 생성할 때 사용하며, 성공 시 파일 디스크립터(FD)를 반환한다.

### 함수 원형 및 플래그
```c
#include <fcntl.h>
int open(const char *pathname, int flags, mode_t mode);
```

| 플래그 | 설명 |
|--------|------|
| **O_RDONLY** | 읽기 전용으로 열기 |
| **O_WRONLY** | 쓰기 전용으로 열기 |
| **O_RDWR** | 읽기/쓰기 모드로 열기 |
| **O_CREAT** | 파일이 없으면 생성 (mode 지정 필요) |
| **O_TRUNC** | 파일 내용을 모두 지우고 열기 |
| **O_APPEND** | 파일 끝에 내용 추가 |

### 사용 예시
```c
// 쓰기용으로 열기 (없으면 생성, 0644 권한)
int fd = open("log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
if (fd == -1) {
    perror("open error");
}
```

---

## 3. read() 함수

파일 디스크립터로부터 데이터를 읽는다.

### 함수 원형
```c
#include <unistd.h>
ssize_t read(int fd, void *buf, size_t count);
```
*   **반환값**: 읽은 바이트 수. `0`이면 파일 끝(EOF), `-1`이면 에러.

### 사용 예시
```c
char buffer[1024];
ssize_t bytes = read(fd, buffer, sizeof(buffer));
if (bytes > 0) {
    // 읽은 데이터 처리
}
```

---

## 4. write() 함수

파일 디스크립터에 데이터를 쓴다.

### 함수 원형
```c
#include <unistd.h>
ssize_t write(int fd, const void *buf, size_t count);
```

### 사용 예시
```c
const char *msg = "System Call Test\n";
write(fd, msg, strlen(msg));
```

---

## 5. 실습: cp 명령어 구현

`open`, `read`, `write` 시스템 콜을 사용하여 파일을 복사하는 간단한 `cp` 프로그램을 구현한다.

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    int src_fd, dst_fd;
    char buffer[BUFFER_SIZE];
    ssize_t n;

    if (argc != 3) {
        printf("Usage: %s <source> <dest>\n", argv[0]);
        return 1;
    }

    // 소스 파일 열기
    src_fd = open(argv[1], O_RDONLY);
    if (src_fd == -1) return 1;

    // 대상 파일 열기 (생성/초기화)
    dst_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd == -1) {
        close(src_fd);
        return 1;
    }

    // 읽어서 쓰기 (복사)
    while ((n = read(src_fd, buffer, BUFFER_SIZE)) > 0) {
        if (write(dst_fd, buffer, n) != n) {
            perror("write error");
            break;
        }
    }

    close(src_fd);
    close(dst_fd);
    return 0;
}
```

---

## 6. 트러블슈팅 (에러 처리)

시스템 콜 실패 시 `errno` 전역 변수에 에러 코드가 저장된다. 이를 확인하여 예외 처리를 해야 한다.

### 에러 확인 방법
```c
#include <errno.h>
#include <string.h>

int fd = open("missing.txt", O_RDONLY);
if (fd == -1) {
    // errno 번호 출력
    printf("Error code: %d\n", errno);
    // 사람이 읽을 수 있는 메시지로 변환
    printf("Error msg: %s\n", strerror(errno));
    // 표준 에러 출력 함수 사용 (권장)
    perror("open failed");
}
```

### 주요 에러 코드 (errno)
| 코드 | 의미 | 원인 예시 |
|------|------|-----------|
| **ENOENT** | No such file or directory | 파일 경로가 잘못됨 |
| **EACCES** | Permission denied | 읽기/쓰기 권한 부족 |
| **EEXIST** | File exists | `O_CREAT | O_EXCL` 사용 시 파일 이미 존재 |
| **EINTR** | Interrupted system call | 시그널에 의해 호출 중단됨 |

<hr class="short-rule">

---
layout: post
title: "C언어 시스템 콜 (open/read/write)"
date: 2025-09-16 17:00:00 +0900
categories: [secure-coding]
---

## 1. 개념

**시스템 콜(System Call)**은 사용자 공간(User Space)의 프로세스가 운영체제 커널(Kernel)의 서비스를 요청하기 위한 표준 인터페이스입니다.
파일 I/O, 프로세스 제어, 메모리 관리 등 하드웨어 자원에 대한 직접적인 접근을 제어합니다.

### 파일 I/O 시스템 콜

| 시스템 콜 | 설명 |
|-----------|------|
| open() | 파일 열기/생성 |
| read() | 파일 읽기 |
| write() | 파일 쓰기 |
| close() | 파일 닫기 |
| lseek() | 파일 포인터 이동 |

### 파일 디스크립터

| FD | 설명 |
|----|------|
| 0 | stdin (표준 입력) |
| 1 | stdout (표준 출력) |
| 2 | stderr (표준 에러) |
| 3+ | 사용자가 연 파일 |

---

## 2. open() 함수

### 함수 원형
```c
#include <fcntl.h>
#include <sys/stat.h>

int open(const char *pathname, int flags);
int open(const char *pathname, int flags, mode_t mode);
```

### 플래그

| 플래그 | 설명 |
|--------|------|
| O_RDONLY | 읽기 전용 |
| O_WRONLY | 쓰기 전용 |
| O_RDWR | 읽기/쓰기 |
| O_CREAT | 없으면 생성 |
| O_TRUNC | 기존 내용 삭제 |
| O_APPEND | 끝에 추가 |

### 예시
```c
int fd;

// 읽기 전용으로 열기
fd = open("file.txt", O_RDONLY);

// 쓰기용 새 파일 생성 (권한 0644)
fd = open("newfile.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
```

---

## 3. read() 함수

### 함수 원형
```c
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t count);
```

### 반환값

| 반환값 | 의미 |
|--------|------|
| > 0 | 읽은 바이트 수 |
| 0 | EOF (파일 끝) |
| -1 | 에러 |

### 예시
```c
char buffer[1024];
ssize_t bytes_read;

bytes_read = read(fd, buffer, sizeof(buffer));
if (bytes_read == -1) {
    perror("read error");
}
```

---

## 4. write() 함수

### 함수 원형
```c
#include <unistd.h>

ssize_t write(int fd, const void *buf, size_t count);
```

### 예시
```c
const char *msg = "Hello, World!\n";

ssize_t bytes_written = write(fd, msg, strlen(msg));
if (bytes_written == -1) {
    perror("write error");
}
```

---

## 5. 실습: cp 명령어 구현

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    int src_fd, dst_fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_written;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <source> <dest>\n", argv[0]);
        return 1;
    }

    // 소스 파일 열기
    src_fd = open(argv[1], O_RDONLY);
    if (src_fd == -1) {
        perror("open source");
        return 1;
    }

    // 대상 파일 생성
    dst_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd == -1) {
        perror("open dest");
        close(src_fd);
        return 1;
    }

    // 복사 루프
    while ((bytes_read = read(src_fd, buffer, BUFFER_SIZE)) > 0) {
        bytes_written = write(dst_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            perror("write error");
            break;
        }
    }

    // 정리
    close(src_fd);
    close(dst_fd);

    printf("File copied successfully!\n");
    return 0;
}
```

### 컴파일 및 실행
```bash
gcc -o mycp mycp.c
./mycp source.txt dest.txt
```

---

## 6. 에러 처리

```c
#include <errno.h>
#include <string.h>

int fd = open("nonexistent.txt", O_RDONLY);
if (fd == -1) {
    printf("Error code: %d\n", errno);
    printf("Error message: %s\n", strerror(errno));
    perror("open");  // 자동으로 에러 메시지 출력
}
```

### 주요 errno 값

| errno | 설명 |
|-------|------|
| ENOENT | 파일 없음 |
| EACCES | 권한 거부 |
| EEXIST | 파일 존재 (O_EXCL) |
| EINTR | 인터럽트 |

<hr class="short-rule">

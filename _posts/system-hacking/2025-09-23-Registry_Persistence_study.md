---
layout: post
title: "Registry Persistence (Run Keys)"
date: 2025-09-23
categories: [system-hacking]
tags: [Registry, Persistence, Run Keys, Windows, System Hacking]
description: "윈도우 레지스트리 Run 키를 조작하여 시스템 재부팅 후에도 악성코드를 지속적으로 실행시키는 기법 분석"
---

## 1. 개요

**지속성(Persistence)**은 공격자가 시스템에 초기 침투한 후, 재부팅이나 사용자 로그오프 등의 이벤트가 발생하더라도 시스템에 대한 접근 권한을 유지하기 위해 사용하는 핵심 기술이다.
윈도우 환경에서 가장 고전적이면서도 널리 사용되는 방법은 **레지스트리 Run 키**에 악성 프로그램을 등록하는 것이다. 이 키에 등록된 프로그램은 사용자가 로그인할 때마다 운영체제에 의해 자동으로 실행된다.
본 글에서는 공격자가 주로 악용하는 레지스트리 경로를 분석하고, 실제 악성코드가 등록되는 과정과 이를 탐지하기 위한 포렌식 접근 방법을 다룬다.

---

## 2. 공격 메커니즘

공격자가 지속성을 유지하기 위해 주로 악용하는 레지스트리 경로는 다음과 같다.

### HKCU (현재 사용자)
*   **경로**: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
*   **특징**: 현재 로그인한 사용자에게만 영향을 미친다. 중요한 점은 **관리자 권한이 없어도 수정이 가능하다**는 것이다. 따라서 권한 상승에 실패한 공격자가 가장 선호하는 위치이다.

### HKLM (로컬 머신)
*   **경로**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
*   **특징**: 시스템의 모든 사용자에게 영향을 미친다. 이 키를 수정하려면 **관리자 권한(Administrator)**이 필요하다.

---

## 3. 공격 실습

공격자는 `reg.exe`나 PowerShell을 사용하여 손쉽게 레지스트리에 백도어를 등록할 수 있다.

### 레지스트리 등록
다음 명령어는 `evil.exe`라는 악성 프로그램을 HKCU Run 키에 `MyBackdoor`라는 이름으로 등록한다.

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MyBackdoor /t REG_SZ /d "C:\Temp\evil.exe" /f
```

### 등록 확인
방어자는 `reg query` 명령어나 전용 도구를 사용하여 의심스러운 자동 실행 항목을 식별해야 한다.

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

**[공격 시나리오 검증]**
아래 이미지는 실제 공격 시나리오에서 백도어가 레지스트리에 등록되고, 시스템 재시작 시 자동 실행되는 과정을 보여준다.

![Registry Persistence](/assets/images/att-ck/5.1.1.wper.png)

---

## 5. 보안 대책

*   **Autoruns 모니터링**: Sysinternals의 **Autoruns** 도구를 사용하여 주기적으로 자동 실행 항목을 전수 점검하고, 서명되지 않거나(Unsigned) 의심스러운 경로(Temp 등)의 프로그램을 식별한다.
*   **레지스트리 접근 제어**: 일반 사용자가 불필요하게 레지스트리를 수정하지 못하도록 권한을 최소화한다.
*   **EDR/백신 탐지**: 프로세스가 레지스트리 Run 키를 수정하는 행위, 특히 `cmd.exe`나 `powershell.exe`가 레지스트리에 쓰기 작업을 시도하는 행위를 실시간으로 탐지하고 차단하도록 설정한다.
*   **파일 무결성 검사**: 중요한 시스템 파일이나 설정이 변경되었는지 주기적으로 확인한다.

<hr class="short-rule">

---
layout: post
title: "레지스트리 Run 키를 이용한 지속성 유지 (Persistence)"
date: 2025-09-23
categories: [system-hacking]
tags: [Registry, Persistence, Run Keys, Windows, System Hacking]
description: "윈도우 레지스트리 Run 키를 조작하여 시스템 재부팅 후에도 악성코드를 지속적으로 실행시키는 기법 분석"
---

## 1. 개요

**지속성(Persistence)**은 공격자가 시스템에 침투한 후, 재부팅이나 사용자 로그오프 등의 이벤트가 발생하더라도 시스템에 대한 접근 권한을 유지하기 위해 사용하는 기술입니다.

윈도우 시스템에서 가장 흔하게 사용되는 지속성 유지 방법 중 하나는 **레지스트리 Run 키**를 이용하는 것입니다. 이 키에 등록된 프로그램은 사용자가 로그인할 때마다 자동으로 실행됩니다.

## 2. 주요 레지스트리 키

공격자가 주로 악용하는 레지스트리 경로는 다음과 같습니다.

### 2.1. HKCU (현재 사용자)
*   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
*   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`

이 경로에 등록된 프로그램은 **현재 로그인한 사용자**가 로그인할 때 실행됩니다. 관리자 권한이 없어도 수정할 수 있어 공격자가 가장 선호하는 위치입니다.

### 2.2. HKLM (로컬 머신)
*   `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
*   `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
*   `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

이 경로에 등록된 프로그램은 **모든 사용자**에게 영향을 미칩니다. 하지만 이 키를 수정하려면 **관리자 권한(Administrator)**이 필요합니다.

## 3. 실습: 지속성 설정 및 확인

공격자는 커맨드 라인 도구(`reg`, `powershell`)를 사용하여 레지스트리에 악성 프로그램을 등록합니다.

### 3.1. 레지스트리 등록 (공격자 관점)
다음 명령어는 `evil.exe`라는 악성 프로그램을 HKCU Run 키에 `MyBackdoor`라는 이름으로 등록합니다.

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MyBackdoor /t REG_SZ /d "C:\Temp\evil.exe" /f
```

### 3.2. 등록 확인 (방어자/분석가 관점)
침해 사고 분석 시, `reg query` 명령어나 `Autoruns` 도구를 사용하여 의심스러운 자동 실행 항목을 식별해야 합니다.

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

## 4. 실습 및 증거

아래는 실제 공격 시나리오에서 공격자가 레지스트리 Run 키에 백도어를 등록하고, 이를 확인하는 과정입니다.

![Registry Persistence](/assets/images/att-ck/5.1.1.wper.png)

## 5. 보안 대책

1.  **Autoruns 모니터링**: Sysinternals의 **Autoruns** 도구를 사용하여 주기적으로 자동 실행 항목을 점검하고, 서명되지 않거나 의심스러운 경로의 프로그램을 식별합니다.
2.  **레지스트리 접근 제어**: 일반 사용자가 불필요하게 레지스트리를 수정하지 못하도록 권한을 최소화합니다.
3.  **EDR/백신 탐지**: 프로세스가 레지스트리 Run 키를 수정하는 행위(특히 `cmd.exe`, `powershell.exe` 등에 의한)를 실시간으로 탐지하고 차단하도록 보안 솔루션을 설정합니다.
4.  **파일 무결성 검사**: 중요한 시스템 파일이나 설정이 변경되었는지 주기적으로 확인합니다.

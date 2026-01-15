---
layout: post
title: "NFS & Samba"
date: 2025-06-18 17:00:00 +0900
categories: [linux]
---

## 1. 개요

**NFS (Network File System)**와 **Samba (SMB/CIFS)**는 네트워크를 통해 원격지의 디스크를 로컬 디스크처럼 사용할 수 있게 해주는 파일 공유 솔루션이다.
사용 환경에 따라 적절한 프로토콜을 선택해야 한다.

### 비교

| 특징 | NFS | Samba |
|------|-----|-------|
| **주 용도** | Linux/Unix 서버 간 고성능 파일 공유 | Windows와 Linux 간의 파일 공유 |
| **운영체제** | Linux/Unix 친화적 | Windows 친화적 (Active Directory 지원) |
| **속도** | 빠름 (오버헤드 적음) | 상대적으로 느림 (기능 많음) |
| **인증** | IP/Host 기반 (기본) | 사용자 계정/암호 기반 |

---

## 2. NFS 서버 구축

리눅스 서버 간의 파일 공유를 위해 NFS를 설정한다.

### 서버 설정
```bash
# 1. 패키지 설치
dnf install -y nfs-utils

# 2. 공유 디렉터리 생성 및 권한 설정
mkdir -p /srv/nfs/share
chmod 755 /srv/nfs/share

# 3. 설정 파일(/etc/exports) 편집
# 형식: [공유경로] [허용대상](옵션)
echo "/srv/nfs/share 10.0.0.0/24(rw,sync,no_root_squash)" >> /etc/exports

# 4. 서비스 시작 및 방화벽 오픈
systemctl enable --now nfs-server
firewall-cmd --permanent --add-service=nfs
firewall-cmd --permanent --add-service={rpc-bind,mountd}
firewall-cmd --reload
```

### exports 옵션
*   `rw`: 읽기/쓰기 허용
*   `sync`: 데이터를 디스크에 즉시 기록 (안전성)
*   `no_root_squash`: 클라이언트의 root 권한을 서버에서도 그대로 인정 (보안 주의)

### 클라이언트 설정
```bash
# 마운트 (임시)
mount -t nfs 10.0.0.11:/srv/nfs/share /mnt/nfs

# 마운트 (영구 - /etc/fstab)
10.0.0.11:/srv/nfs/share  /mnt/nfs  nfs  defaults  0 0
```

---

## 3. Samba 서버 구축

Windows 클라이언트와 파일을 공유하기 위해 Samba를 설정한다.

### 서버 설정
```bash
# 1. 패키지 설치
dnf install -y samba

# 2. 설정 파일(/etc/samba/smb.conf) 편집
cat >> /etc/samba/smb.conf << 'EOF'
[share]
    path = /srv/samba/share
    browseable = yes
    writable = yes
    valid users = sambauser
EOF

# 3. Samba 전용 계정 생성 (OS 계정과 별도 관리)
useradd -s /sbin/nologin sambauser
smbpasswd -a sambauser  # 비밀번호 설정

# 4. 서비스 시작
systemctl enable --now smb nmb
firewall-cmd --permanent --add-service=samba
firewall-cmd --reload
```

### SELinux 설정
Samba가 홈 디렉터리나 특정 경로에 접근하려면 SELinux 정책을 풀어줘야 한다.
```bash
setsebool -P samba_enable_home_dirs on
chcon -t samba_share_t /srv/samba/share
```

---

## 4. 실습: 자동 마운트 (Autofs)

항상 마운트해 두는 것이 아니라, 사용자가 해당 경로에 **접근할 때만 자동으로 마운트**하고, 사용하지 않으면 연결을 끊어 리소스를 절약하는 방법이다.

```bash
# 1. Autofs 설치
dnf install -y autofs

# 2. 마스터 파일 설정 (/etc/auto.master)
# /mnt/auto 디렉터리 하위의 마운트는 /etc/auto.nfs 파일의 정의를 따른다.
echo "/mnt/auto /etc/auto.nfs" >> /etc/auto.master

# 3. 맵 파일 설정 (/etc/auto.nfs)
# share라는 이름으로 접근하면 10.0.0.11의 공유 폴더를 마운트
echo "share -rw,sync 10.0.0.11:/srv/nfs/share" > /etc/auto.nfs

# 4. 서비스 재시작
systemctl restart autofs

# 5. 테스트 (디렉터리가 없어도 이동하면 자동 생성됨)
cd /mnt/auto/share
```

![Samba 공유 폴더 접속](/assets/images/linux/samba.png)

<hr class="short-rule">

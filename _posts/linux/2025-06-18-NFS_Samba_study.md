---
layout: post
title: "NFS/Samba 파일 공유"
date: 2025-06-18 17:00:00 +0900
categories: [linux]
---

## 1. 개념

**NFS**와 **Samba**는 네트워크를 통해 원격 파일 시스템을 로컬처럼 사용할 수 있게 해주는 파일 공유 프로토콜입니다.
NFS는 주로 Linux/Unix 시스템 간의 고속 공유에, Samba(SMB/CIFS)는 Windows와 Linux 간의 호환성 높은 공유에 사용됩니다.

### 비교

| 항목 | NFS | Samba (SMB/CIFS) |
|------|-----|------------------|
| 대상 | Linux ↔ Linux | Linux ↔ Windows |
| 포트 | 2049 (TCP/UDP) | 445, 139 |
| 인증 | UID/GID 기반 | 사용자 계정 |
| 속도 | 빠름 | 상대적으로 느림 |

---

## 2. NFS 서버 구축

### 서버 설정 (Rocky Linux)
```bash
# 1. NFS 패키지 설치
dnf install -y nfs-utils

# 2. 공유 디렉터리 생성
mkdir -p /srv/nfs/share
chmod 755 /srv/nfs/share

# 3. exports 파일 설정
echo "/srv/nfs/share 10.0.0.0/24(rw,sync,no_root_squash)" >> /etc/exports

# 4. exports 적용 및 서비스 시작
exportfs -ra
systemctl enable --now nfs-server

# 5. 방화벽 설정
firewall-cmd --permanent --add-service=nfs
firewall-cmd --permanent --add-service=rpc-bind
firewall-cmd --permanent --add-service=mountd
firewall-cmd --reload
```

### exports 옵션

| 옵션 | 설명 |
|------|------|
| `rw` | 읽기/쓰기 허용 |
| `ro` | 읽기 전용 |
| `sync` | 동기 쓰기 (안전) |
| `no_root_squash` | root 권한 유지 |
| `all_squash` | 모든 사용자를 nobody로 |

### 클라이언트 마운트
```bash
# 서버 공유 목록 확인
showmount -e 10.0.0.11

# 마운트
mkdir -p /mnt/nfs
mount -t nfs 10.0.0.11:/srv/nfs/share /mnt/nfs

# 영구 마운트 (/etc/fstab)
echo "10.0.0.11:/srv/nfs/share /mnt/nfs nfs defaults 0 0" >> /etc/fstab
```

---

## 3. Samba 서버 구축

### 서버 설정 (Rocky Linux)
```bash
# 1. Samba 패키지 설치
dnf install -y samba samba-client

# 2. 공유 디렉터리 생성
mkdir -p /srv/samba/share
chmod 777 /srv/samba/share

# 3. Samba 설정 파일 편집
cat >> /etc/samba/smb.conf << 'EOF'

[share]
    path = /srv/samba/share
    browseable = yes
    writable = yes
    guest ok = no
    valid users = sambauser
EOF

# 4. Samba 사용자 생성
useradd -s /sbin/nologin sambauser
smbpasswd -a sambauser

# 5. 서비스 시작
systemctl enable --now smb nmb

# 6. 방화벽 설정
firewall-cmd --permanent --add-service=samba
firewall-cmd --reload
```

### SELinux 설정
```bash
# Samba 공유 허용
setsebool -P samba_enable_home_dirs on
chcon -t samba_share_t /srv/samba/share
```

### Windows에서 접속
```
\\10.0.0.11\share
```

### Linux 클라이언트 마운트
```bash
# cifs-utils 설치
dnf install -y cifs-utils

# 마운트
mount -t cifs //10.0.0.11/share /mnt/samba -o username=sambauser,password=비밀번호

# 영구 마운트 (자격 증명 파일 사용)
echo "username=sambauser" > /root/.smbcreds
echo "password=비밀번호" >> /root/.smbcreds
chmod 600 /root/.smbcreds

echo "//10.0.0.11/share /mnt/samba cifs credentials=/root/.smbcreds 0 0" >> /etc/fstab
```

---

## 4. 실습 예시

### NFS 자동 마운트 (autofs)
```bash
# autofs 설치
dnf install -y autofs

# 마스터 맵 설정
echo "/mnt/auto /etc/auto.nfs" >> /etc/auto.master

# NFS 맵 설정
echo "share -rw,sync 10.0.0.11:/srv/nfs/share" > /etc/auto.nfs

# autofs 시작
systemctl enable --now autofs

# 접근 시 자동 마운트
ls /mnt/auto/share
```

![Samba 공유 폴더 접속](/assets/images/linux/samba.png)

---

## 5. 트러블슈팅

### NFS 마운트 실패
```bash
# RPC 서비스 확인
rpcinfo -p 10.0.0.11

# 방화벽 확인
firewall-cmd --list-all
```

### Samba 권한 문제
```bash
# SELinux 확인
getenforce
ls -Z /srv/samba/share

# Samba 로그 확인
tail -f /var/log/samba/log.smbd
```

### 공유 목록 확인
```bash
# NFS
showmount -e localhost

# Samba
smbclient -L localhost -U sambauser
```

<hr class="short-rule">

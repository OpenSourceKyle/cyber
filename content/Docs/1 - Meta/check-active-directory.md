+++
title = "Check - Active Directory"
+++

> **BEFORE DOING ANYTHING --  SYNC CLOCK WITH THE DOMAIN CONTROLLER**

```powershell
net time /domain /set /y
```

---

### Initial/Uncredentialed Enumeration

#### Host Identification

1. [ ] Create a document for all discovered hosts (hostnames and IP addresses).

2. [ ] Start Wireshark and listen for Layer 2 (ARP, MDNS, NBNS) traffic to discover IP addresses and hostnames.

3. [ ] Start [Responder in Analyze mode]({{% ref "protocol-poisoners.md" %}}) to discover IP addresses and hostnames.

4. [ ] Perform an [`fping` ICMP sweep]({{% ref "scanning.md#ping-sweep" %}}) to find all hosts on your subnet that respond to an ICMP echo request.

5. [ ] Perform an [NMAP identification scan]({{% ref "nmap.md" %}}) in case it picks up anything missed.

6. [ ] With all discovered hosts, perform an NMAP scan to determine services running on each host.
    - Save to a file all ports/services running on each discovered host; pay special attention to Domain Controllers, RDP, naming conventions, etc.
    - Look for any quick wins that can give us an initial foothold, like outdated software or OS.

#### User Identification

1. [ ] Create a document for all discovered users.

2. [ ] Grab all users by an [SMB Null Session against the DC with netexec]({{% ref "netexec.md#enumerate-users" %}})

3. [ ] Attempt to abuse an anonymous LDAP search against the domain controller with a tool like ldapsearch or [windapsearch]({{% ref "active-directory.md#ad-enumeration" %}}) to grab all users.

4. [ ] Try [Impacket's `lookupsid.py`]({{% ref "active-directory.md#user-enumeration" %}}) for discovering users with SID/RID brute forcing.

5. [ ] Use [Kerbrute]({{% ref "active-directory.md#user-enumeration" %}}) and common wordlists (that match the naming convention of the organization) to brute force usernames against a discovered DC.

6. [ ] Check for users that do not require Kerberos pre-auth ([AS-REP Roasting]({{% ref "active-directory.md#as-rep-roasting" %}})) to get their password hash.

7. [ ] Look for systems that can be exploited to gain SYSTEM level access (essentially like getting AD credentials).

#### User Foothold

1. [ ] Start [Responder]({{% ref "protocol-poisoners.md" %}})/Inveigh on network interface to listen for NTLM users and hashes. Attempt to crack with Hashcat/John.

2. [ ] Attempt a [password spray]({{% ref "netexec.md#password-spraying" %}}) on users identified during user identification.
    - Attempt to gather the password policy of the organization first
    - Password spray against discovered users using a common password like "Welcome1", "ChangeMe1", "SeasonYear (Spring2025)", username as the password, etc.

---

### Credentialed Enumeration

#### Host Identification

1. [ ] Run [BloodHound]({{% ref "bloodhound.md" %}}) with discovered credentials (mark anything we have control over as owned).

2. [ ] Use [ldapdomaindump]({{% ref "active-directory.md#ad-enumeration" %}}) to identify all domain-joined computers.

3. [ ] Enumerate accessible [shares on servers with NetExec]({{% ref "netexec.md#shares-enumeration" %}}), SMBMap, PowerView, or Snaffler.

#### User Identification

1. [ ] Run [BloodHound]({{% ref "bloodhound.md" %}}) with discovered credentials (mark anything we have control over as owned).
    - [Bloodhound.py]({{% ref "bloodhound.md" %}})
    - [BloodHound from Windows]({{% ref "bloodhound.md" %}})

2. [ ] Gather the [domain password policy using the discovered credentials]({{% ref "netexec.md#password-policy-enumeration" %}})

3. [ ] Use the discovered credentials and a tool like [NetExec]({{% ref "netexec.md" %}}) to get all users, groups, and logged-on users against the server you have credentials for (ultimate goal is DC).

4. [ ] Gather a list of Domain Admins or privileged users using the following tools:
    - [Windapsearch]({{% ref "active-directory.md#ad-enumeration" %}})
    - PowerView
    - [BloodHound]({{% ref "bloodhound.md" %}})
    - AD PowerShell module

5. [ ] [Credentialed Enumeration - from Linux]({{% ref "active-directory.md" %}})

6. [ ] [Credentialed Enumeration - from Windows]({{% ref "active-directory.md" %}})

#### Foothold Enumeration

1. [ ] Run [BloodHound]({{% ref "bloodhound.md" %}}) with discovered credentials.
    - [Bloodhound.py]({{% ref "bloodhound.md" %}})
    - [BloodHound from Windows]({{% ref "bloodhound.md" %}})

2. [ ] Enumerate security controls in place ([Defender]({{% ref "security-products.md#windows-defender" %}}), [AppLocker]({{% ref "security-products.md#applocker" %}}), PowerShell Constraints, [LAPS]({{% ref "security-products.md#local-administrator-password-solution-laps" %}})).

3. [ ] Look for other logged-on users using `netexec` to see if we can dump any credentials with [Mimikatz]({{% ref "mimikatz-post-exploit.md" %}}) or Rubeus.

4. [ ] Look for kerberoastable accounts through [BloodHound]({{% ref "bloodhound.md" %}}), PowerView, `GetUserSPNs.py`.

5. [ ] Look at owned users for abusable ACL entries (ForceChangePassword, AddMember, GenericAll, etc.). Easiest to do in [BloodHound]({{% ref "bloodhound.md" %}}).
    - [ACL Enumeration]({{% ref "active-directory.md" %}})

6. [ ] Check [BloodHound]({{% ref "bloodhound.md" %}}) for:
    1. [ ] [CanRDP]({{% ref "bloodhound.md#canrdp" %}})
    2. [ ] [CanPSRemote]({{% ref "bloodhound.md#canpsremote" %}})
    3. [ ] [SQLAdmin]({{% ref "bloodhound.md#sqladmin" %}})

#### Pivoting

1. [ ] Run [sshuttle, chisel, ligolo-ng]({{% ref "lateral-movement.md" %}}) for Windows on the Windows pivot host.
    - [(If needed) ensure proxy is setup]({{% ref "lateral-movement.md#step-0-pre-requisites" %}})

2. [ ] Check AGAIN [BloodHound]({{% ref "bloodhound.md" %}}) for CanRDP, CanPSRemote, or SQLAdmin abilities to move laterally onto other machines.

---

### Exploitation

1. [ ] Look for kerberoastable accounts through [BloodHound]({{% ref "bloodhound.md" %}}), PowerView, [`GetUserSPNs.py`]({{% ref "active-directory.md#impacket-getuserspns" %}}).

2. [ ] Grab all TGS tickets with [`GetUserSPNs.py`]({{% ref "active-directory.md#impacket-getuserspns" %}}) (or Windows equivalent) and save to a file. Attempt to crack with [Hashcat]({{% ref "offline-hash-cracking.md" %}}) (on a GPU rig preferably).

3. [ ] [Abuse any over-permissive ACL entries to gain control of more users and move laterally throughout the network.]({{% ref "active-directory.md#access-control-list-acl" %}})
    - ForceChangePassword to change a user's password to one we know
    - AddMember to add a member we control to a privileged group
    - GenericAll/GenericWrite to create an SPN for account and Kerberoast their password hash (to potentially crack)
    - GenericAll to change the user's password
    - DS-Replication-Get-Changes-All to perform a [DCSync attack]({{% ref "active-directory.md#dcsync" %}})
    - AddKeyCredentialLink to get user's NTLM Hash
    - [ACL Abuse from Linux]({{% ref "active-directory.md" %}})

4. [ ] Check [BloodHound]({{% ref "bloodhound.md" %}}) for CanRDP, CanPSRemote, or SQLAdmin abilities to move laterally onto other machines. Abuse these rights and look for sensitive info on the new machines.

5. [ ] Check for common vulnerabilities to escalate privileges or move laterally:
    - NoPac
    - PrintNightmare
    - PetitPotam

6. [ ] Check for common misconfigurations to escalate privileges or move laterally:
    - [Exchange group permissions]({{% ref "active-directory.md#exchange-privilege-escalation" %}})
    - [MS-RPRN Printer bug]({{% ref "active-directory.md#printer-bug-enumeration-spooler-service" %}})
    - MS14-068
    - Sniff for LDAP credentials
    - Enumerate DNS records for interesting servers
    - [Look for user passwords and other notes in AD user descriptions]({{% ref "active-directory.md#user-attributes-mining" %}})
    - [Check for PASSWD_NOTREQD field on users and test for weak/no passwords]({{% ref "active-directory.md#user-attributes-mining" %}})
    - Look for credentials and other interesting files on SMB shares manually or with [Snaffler]({{% ref "finding-creds.md#snaffler" %}})
    - [Check for DONT_REQ_PREAUTH field and AS-REP Roast any discovered users]({{% ref "active-directory.md#as-rep-roasting" %}})
    - Check for GPOs that we have write access over to gain administrator rights or move laterally (can be checked with [BloodHound]({{% ref "bloodhound.md" %}}))
    - Resource Based Constrained Delegation, Constrained Delegation, Unconstrained Delegation
    - [Active Directory Certificate Services Attacks]({{% ref "active-directory.md#adcs-attack-reference" %}})

7. [ ] Check for [Group Policy Preferences (GPP) Passwords]({{% ref "active-directory.md#sysvol--group-policy-passwords" %}}).

8. [ ] Check for [Active Directory Certificate Services (AD CS) attacks]({{% ref "active-directory.md#adcs-attack-reference" %}}).

---

### Additional Auditing

1. [ ] Create a snapshot of the AD database with [AD Explorer]({{% ref "active-directory.md#active-directory-explorer-sysinternals" %}}) for offline analysis.

2. [ ] Use [PingCastle]({{% ref "active-directory.md#pingcastle" %}}) to discover additional AD misconfigurations and vulnerabilities.

3. [ ] Run [Group3r]({{% ref "active-directory.md#group3r" %}}) to uncover vulnerabilities in AD Group Policy.

4. [ ] Run [ADRecon.ps1]({{% ref "active-directory.md#adrecon" %}}) to discover additional AD misconfigurations and vulnerabilities that may have been missed.

### Attacking AD Trusts (Parent Domain)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` (PowerView), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] From a Windows or Linux machine with Domain Admin privileges, attempt an [ExtraSIDs attack]({{% ref "active-directory.md#abusing-access-between-domain-trusts" %}}) to create an Enterprise Admin user in the parent domain.

3. [ ] [Domain Trusts Overview]({{% ref "active-directory.md" %}})

4. [ ] [Child -> Parent Attacks - Windows]({{% ref "active-directory.md" %}})

5. [ ] [Child -> Parent Attacks - Linux]({{% ref "active-directory.md" %}})

### Attacking AD Trusts (Cross Forest)

1. [ ] Discover any current domain trusts with other domains using `Get-ADTrust`, `Get-DomainTrust` (PowerView), or [BloodHound]({{% ref "bloodhound.md" %}}).

2. [ ] Attempt [cross-forest Kerberoasting]({{% ref "active-directory.md#kerberoasting-cracking-tgs" %}}).

3. [ ] If admin accounts share names across domains and one is compromised, try reused credentials.

4. [ ] Check for SIDHistory abuse.

5. [ ] [Cross-Forest Trust Abuse - Windows]({{% ref "active-directory.md" %}})

6. [ ] [Cross-Forest Trust Abuse - Linux]({{% ref "active-directory.md" %}})

### Additional Noteworthy Methods

1. [ ] Access a host via [RDP]({{% ref "rdp.md" %}}) or [WinRM]({{% ref "active-directory.md#winrm" %}}) as a local user or a local admin.

2. [ ] Authenticate to a remote host as an admin using a tool such as [PsExec]({{% ref "netexec.md#command-execution" %}}).

3. [ ] Gain access to a sensitive [file share]({{% ref "smb-cifs-rpc.md" %}}).

4. [ ] Gain [MSSQL access]({{% ref "mssql.md" %}}) to a host as a DBA user, which can then be leveraged to escalate privileges.

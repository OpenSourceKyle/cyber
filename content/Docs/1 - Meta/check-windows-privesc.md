+++
title = "Check - Windows Privilege Escalation"
+++

### If Webserver Exists (Post-Foothold)

1. Check web configuration files and source code for vulnerabilities, hardcoded credentials, etc.
    - [Enumeration: Credential Hunting]({{% ref "finding-creds.md" %}})
    - Check the source code of all pages, including index
    - Potential locations:
        - `C:\xampp\htdocs` (common with Apache)
        - `C:\inetpub`

### Default Methodology

1. Run Windows PrivEsc automation scripts. Save output to a file and transfer to attack box. Examine in text editor.
    
    - [winPEAS]({{% ref "privilege-escalation-windows.md#winpeas" %}}) (Things to check)
    - Seatbelt
    - [PowerUp / SharpUp]({{% ref "privilege-escalation-windows.md#sharpup" %}})
    - JAWS (PowerShell-based; useful if custom executables are blocked)
    - SessionGopher
    - [Bloodhound]({{% ref "bloodhound.md" %}})
2. Perform basic box enumeration once a foothold is established.
    
    - [Gathering Network Information]({{% ref "privilege-escalation-windows.md#manual-survey" %}})
    - [Gathering System Information]({{% ref "privilege-escalation-windows.md#manual-survey" %}})
    - [Gathering Process Enumeration]({{% ref "privilege-escalation-windows.md#manual-survey" %}})
    - [User and Group Enumeration]({{% ref "privilege-escalation-windows.md#manual-survey" %}})
3. Look at access rights of user we have a foothold with (user privileges).
    
    - [Windows Privileges Overview]({{% ref "privilege-escalation-windows.md#privileges-vs-access-rights" %}})
    - `whoami /priv`
    - `whoami /all`
    - SeImpersonate / SeAssignPrimaryToken ([JuicyPotato]({{% ref "privilege-escalation-windows.md#juicypotato" %}}) / [RoguePotato / PrintSpoofer]({{% ref "privilege-escalation-windows.md#roguepotato-godpotato-printspoofer-printnightmare" %}}))
    - [SeDebugPrivilege]({{% ref "privilege-escalation-windows.md#via-sedebug" %}})
    - [SeTakeOwnershipPrivilege]({{% ref "privilege-escalation-windows.md#setakeownershipprivilege" %}})
4. Check if user is a member of privileged groups.
    
    - `whoami /groups`
    - [Backup Operators]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Event Log Readers]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [DnsAdmins]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Hyper-V Admins]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Print Operators]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - [Server Operators]({{% ref "privilege-escalation-windows.md#good-groups" %}})
    - WSUS Administrators
5. Check for Weak File / Service Permissions.
    
    - [Permissive File System ACLs]({{% ref "privilege-escalation-windows.md#filefolder-permissions" %}})
    - [Weak Service Permissions]({{% ref "privilege-escalation-windows.md#weak-service-acls" %}})
    - [Unquoted Service Path]({{% ref "privilege-escalation-windows.md#unquoted-service-paths" %}})
    - Permissive Registry ACLs
    - Modifiable Registry Autorun Binary
6. Check for saved credentials.
    
    - [Cmdkey Saved Credentials]({{% ref "finding-creds.md" %}})
    - `cmdkey /list`
    - If we get access this way, run [Mimikatz]({{% ref "mimikatz-post-exploit.md" %}}) to try to extract their plaintext password
7. Look for services running on internal ports that were not accessible from the outside with netstat.
    
    - Databases we can connect to?
    - `netstat -ano`
    - Vulnerable Services
8. Check for additional NICs using `ipconfig`.
    
9. Look for vulnerable applications and services.
    
    - `wmic product get name`
    - Vulnerable Services
10. Look for interesting files on the server that may have credentials or other sensitive info.
    
    - [Credential Hunting]({{% ref "finding-creds.md" %}})
    - [Credential Hunting Other Files]({{% ref "finding-creds.md#searching" %}})
    - Further Credential Theft
    - [Dumping Hashes / Credentials]({{% ref "authentication-windows.md#secrets-dumping-sam" %}})
    - [Mimikatz]({{% ref "mimikatz-post-exploit.md" %}})
11. Pillage for credentials or other interesting information.
    
    - [Pillaging Overview]({{% ref "finding-creds.md" %}})
    - Pillaging Applications
    - Accessing Instant Messaging Clients Through Cookies
    - Pillaging the Clipboard + Keylogging
    - Roles and Services (pillaging backups)
12. Look for scheduled tasks that we can modify.
    
    - [Scheduled Tasks]({{% ref "privilege-escalation-windows.md#manual-survey" %}})
13. Look for credentials in process command line.
    
    - [Process Command Line]({{% ref "privilege-escalation-windows.md#manual-survey" %}})
14. Check for 'Always Install Elevated' setting and exploit with MSI package.
    
    - [Always Install Elevated]({{% ref "privilege-escalation-windows.md#alwaysinstallelevated" %}})
15. Capture hashes with a Malicious LNK file or SCF file.
    
    - **ESPECIALLY USEFUL IF WE THINK USERS WILL VISIT A SHARE THAT WE HAVE UPLOADED TO**
    - [Capturing Hashes with Malicious .lnk File]({{% ref "protocol-poisoners.md" %}})
    - [Capture hashes with SCF on a File Share]({{% ref "protocol-poisoners.md" %}}) (no longer works on Windows Server 2019 or greater)
16. Look for Kernel / OS exploits.
    
    - Kernel Exploits:
        - Zero Logon
        - PrintNightmare
    - EOL Systems and their exploits (Windows Server 2008, Windows 7, etc.)
17. Attempt to bypass UAC Controls if present.
    
    - [User Account Control (UAC) Attacks]({{% ref "security-products.md" %}})
18. [DLL Injection]({{% ref "privilege-escalation-windows.md#dll-hijacking" %}}).
    
19. Common Vulnerabilities and Vulnerable Programs.
    
    - Docker Desktop Community Edition before 2.1.0.1 (CVE-2019-15752)
    - Windows Certificate Dialog (CVE-2019-1388)
20. Attempt to capture network traffic with Inveigh/Responder, Wireshark, or Snaffler.
    
    - [Traffic Capture]({{% ref "finding-creds.md#creds-in-network-traffic" %}})
    - [Snaffler -- SMB Share Enumeration Tool]({{% ref "finding-creds.md#snaffler" %}})
    - [LLMNR/NBT-NS Poisoning from Windows]({{% ref "protocol-poisoners.md" %}})
    - [LLMNR/NBT-NS Poisoning from Linux]({{% ref "protocol-poisoners.md" %}})
21. Enumerate User/Computer Description Fields for cleartext credentials or other useful information.
    
22. If the system has `.vhd`, `.vhdx`, or `.vmdk` files, mount them to potentially dump machine hashes.
    
    - [Mount VHDX/VMDK]({{% ref "authentication-windows.md" %}})
23. Check for Active Directory Certificate Services (AD CS) attacks.
    
24. If trying to be evasive or if custom executables are locked down, check LOLBAS for alternative methods.
    
    - Living Off The Land Binaries and Scripts (LOLBAS)

### Once We Are Admin

1. Attempt to recover all user passwords or NTLM hashes on the system.
    - [Dump the LSASS process to try and recover more user passwords or NTLM hashes]({{% ref "authentication-windows.md#lsass" %}})
    - [Stealing NTLM Hashes from an LSASS.DMP Memory Dump]({{% ref "authentication-windows.md#lsass" %}})
    - [Dumping the SAM Database to recover password hashes]({{% ref "authentication-windows.md#secrets-dumping-sam" %}})

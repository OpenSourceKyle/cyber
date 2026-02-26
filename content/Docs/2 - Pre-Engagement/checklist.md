+++
title = "Checklist"
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

- [ ] **1. Anonymous Access & Share Listing** (Attempt a null session via `smbclient -L <IP> -N` or `crackmapexec smb <IP> --shares` to list shares without credentials)
- [ ] **2. Comprehensive Enumeration** (Run `enum4linux-ng -A <IP>` to automatically dump users, groups, OS info, and password policies)
- [ ] **3. Share Content Inspection** (Mount accessible shares or use `smbclient` to browse directories for sensitive files, scripts, or backups)
- [ ] **4. Security Posture Check** (Use `nmap --script=smb-security-mode` to verify if SMB signing is required, which is critical for preventing relay attacks)

# Web

- [ ] **1. Technology & Security Fingerprinting** (Use `whatweb` and `nikto` to identify the server, frameworks, and WAF, and `curl` to inspect headers and robots.txt)
- [ ] **2. Content & vHost Discovery** (Run `feroxbuster` or `gobuster dir` to bruteforce directories/files, and `gobuster vhost` to find hidden virtual hosts)
- [ ] **3. Automated Vulnerability Scanning** (Use `nikto` or `wapiti` to scan for common misconfigurations and known vulnerabilities like outdated software)
- [ ] **4. Manual Application Testing (OWASP Top 10)** (After automated scans, manually inspect the application for logical flaws, focusing on Injection, Broken Access Control, and XSS)

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

# Active Directory

- [ ] **1. Domain & Network Identification** (Identify DC IP, Domain Name, Ports 53/88/389/445, `net config workstation`)
- [ ] **2. User Enumeration** (Build target list via Kerbrute, RID Cycling, or `net user /domain`)
- [ ] **3. Initial Credential Acquisition** (Run Responder for LLMNR/NBT-NS poisoning, check AS-REP Roasting)
- [ ] **4. BloodHound Collection & Analysis** (Run SharpHound, upload data, analyze "Shortest Paths" and "High Value Targets")
- [ ] **5. Service & Misconfiguration Hunting** (Kerberoasting TGS, check SYSVOL/GPP for passwords, DNS/Printer Bug checks)
- [ ] **6. ACL & Object Rights Analysis** (Check for "Dangerous Rights" like GenericAll/WriteDACL via PowerView or BloodHound)
- [ ] **7. Certificate Services (ADCS) Check** (Enumerate vulnerable templates, Shadow Credentials/PyWhisker, Pass-the-Certificate)
- [ ] **8. Access & Admin Validation** (Check Local Admin rights, test RDP/WinRM access, verify "Double Hop" status)
- [ ] **9. Lateral Movement** (Execute Pass-the-Hash, Pass-the-Ticket, or Overpass-the-Hash to pivot)
- [ ] **10. Domain Dominance** (Perform DCSync to dump NTDS.dit, create Golden Tickets, enumerate Trusts)

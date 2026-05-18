+++
title = "Check - Initial Enumeration"
+++

## Reconnaissance & Target Discovery

Identify target scope (IP ranges, domains, subnets)

### Passive Recon

1. Gather public info (DNS, WHOIS, certificates, company structure)
2. Search public data leaks ([Google Dorks]({{% ref "search-engine-dorking.md" %}}), GitHub, Pastebin, etc.)

### Active Recon

Discover all active hosts on the target network/IP range/subnet(s). Document all active hosts to Obsidian notes.

1. Host Discovery
    
    - [NMAP Host Discovery Scan]({{% ref "scanning.md#host-discovery--arp" %}})
    - ICMP sweep ([ping or fping]({{% ref "scanning.md#ping-sweeps" %}}))
    - TCP/UDP host discovery (`nmap -sn`, masscan)
    - ARP scanning (if on same subnet)
    - Add discovered hostnames to `/etc/hosts` file
2. For each active host, scan ALL TCP / UDP ports. Document each open port per host in Obsidian.
    
    - [NMAP TCP port scanning]({{% ref "nmap.md" %}})
    - [NMAP UDP port scanning]({{% ref "nmap.md" %}})
3. For each open port, run service version scan with scripts and OS detection.
    
    - [NMAP service enumeration and OS detection]({{% ref "nmap.md" %}})
    - Netcat banner grabbing (manual confirmation)
    - Document services and service versions in Obsidian
4. For each detected service, do individual service enumeration to look for more information and vulnerabilities.
    
5. Check for vulnerabilities in discovered services / service versions.
    
    - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})
    - Search ExploitDB for service exploits with the discovered version
    - Look at NMAP script output for discovered vulnerabilities or misconfigurations (e.g. anonymous login)
    - Look for OS version exploits
    - Search Google for `<Service> <Version> Exploit GitHub`
    - Document discovered vulnerabilities in Obsidian
6. Check file share services (FTP, SMB, etc.) for anonymous logon and credential files.
    
    - [FTP Enumeration]({{% ref "ftp.md" %}})
    - [SMB Enumeration]({{% ref "smb-cifs-rpc.md" %}})
7. Check for write access over a share (SMB, FTP).
    
    - [Capturing Hashes with Malicious .lnk File]({{% ref "protocol-poisoners.md" %}})
    - [Capture hashes with SCF on a File Share]({{% ref "protocol-poisoners.md" %}}) (no longer works on Windows Server 2019 or greater)
8. If webserver(s) exist, see [Webserver Enumeration Methodology]({{% ref "check-web-enumeration.md" %}}).

+++
title = "Check - Initial Enumeration"
+++

## Reconnaissance & Target Discovery

Identify target scope (IP ranges, domains, subnets)

### Passive Recon

1. [ ] Gather public info (DNS, WHOIS, certificates, company structure)
    - [Passive Information Gathering]({{% ref "passive-information-gathering.md" %}})
    - [Search Engine Dorking]({{% ref "search-engine-dorking.md" %}})

2. [ ] Search public data leaks ([Google Dorks]({{% ref "search-engine-dorking.md" %}}), GitHub, Pastebin, etc.)

### Active Recon

1. [ ] Document all active hosts on the target network/IP range/subnet(s) in **Obsidian notes**.

2. [ ] Host Discovery
    - [NMAP Host Discovery Scan]({{% ref "nmap.md#host-discovery" %}})
        - ARP scanning (same subnet only)
    - [ICMP sweep ping or fping]({{% ref "scanning.md#ping-sweep" %}})
    - TCP/UDP host discovery (`nmap -sn`, masscan)
    - **Add discovered hostnames to `/etc/hosts` file**

3. [ ] For each active host, scan ALL TCP/UDP ports. Document each open port per host in Obsidian.
    - [NMAP All Ports (TCP + UDP)]({{% ref "nmap.md#all-ports" %}})

4. [ ] For each open port, run service version scan with scripts and OS detection.
    - [NMAP service enumeration and OS detection]({{% ref "nmap.md" %}})
    - [Netcat banner grabbing (manual confirmation)]({{% ref "scanning.md#manual-scanning" %}})
    - **Document services and service versions in Obsidian**

5. [ ] For each detected service, do individual service enumeration to look for more information and vulnerabilities.
    
6. [ ] Check for vulnerabilities in discovered services / service versions.
    - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})
    - Search ExploitDB for service exploits with the discovered version
    - Look at NMAP script output for discovered vulnerabilities or misconfigurations (e.g. anonymous login)
    - Look for OS version exploits
    - Search Google for `Exploit GitHub <Service> <Version>`
    - **Document discovered vulnerabilities in Obsidian**

7. [ ] Check file share services (FTP, SMB, etc.) for anonymous logon and credential files.
    - [FTP Enumeration]({{% ref "ftp.md" %}})
    - [SMB Enumeration]({{% ref "smb-cifs-rpc.md" %}})

8. [ ] Check for write access over a share (SMB, FTP).    
    - [Capturing Hashes with Malicious .lnk File]({{% ref "protocol-poisoners.md" %}})
    - [Capture hashes with SCF on a File Share]({{% ref "protocol-poisoners.md" %}}) (no longer works on Windows Server 2019 or greater)

9. [ ] If webserver(s) exist, see [Webserver Enumeration Methodology]({{% ref "check-web-enumeration.md" %}}).

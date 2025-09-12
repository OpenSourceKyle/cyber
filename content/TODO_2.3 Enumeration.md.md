```bash

# === NetBIOS Enumeration Cheat Sheet ===

# Type (20) means it's a fileserver
# Share Names with $ need creds
# Null or Anonymous users needs no creds

# --- nbtstat (Windows Tool for NetBIOS over TCP/IP) ---
# The nbtstat utility is used to troubleshoot NetBIOS name resolution problems.

# -A: Lists a remote machine's name table given its IP address.
nbtstat -A <TARGET_IP>


# -a: Lists a remote machine's name table given its name.
nbtstat -a <remote_name>

# -n: Lists local NetBIOS names on your machine.
nbtstat -n

# -c: Lists the contents of the NetBIOS name cache, which contains name-to-IP-address mappings.
nbtstat -c

# -r: Lists names resolved by broadcast and WINS.
nbtstat -r

# -R: Purges the name cache and reloads all #pre-tagged entries from the Lmhosts file.
nbtstat -R

# -S: Lists the NetBIOS session table with destination IP addresses.
nbtstat -S

# -s: Lists the NetBIOS session table, attempting to convert destination IP addresses to hostnames.
nbtstat -s

# -RR: Sends name release packets to WINS and then starts a refresh.
nbtstat -RR


# --- nbtscan (Linux Tool for NetBIOS Scanning) ---
# Scans for open NetBIOS name servers on a local or remote TCP/IP network.

# Scan a single IP address with verbose output.
nbtscan -v <TARGET_IP>

# Scan a full subnet for NetBIOS information.
nbtscan -v 192.168.99.0/24


# --- Net Command (Windows Built-in) ---
# The 'net' command is a versatile tool for managing network resources.

# View shares on a remote computer.
net view <TARGET_IP>

# Map a remote share to a local drive letter (e.g., K:).
net use K: \\<TARGET_IP>\<SHARE_NAME>

# Establish a null session with a target machine to the IPC$ share.
# This uses an empty username ("") and a null password ("").
net use \\<TARGET_IP>\<SHARE_NAME> "" /u:""


# --- SMB/CIFS Tools (Linux) ---

# smbclient: List all available shares on a target host.
smbclient –L \\\\<TARGET_IP>\\

# mount.cifs: Mount a remote Windows share to the local Linux filesystem.
sudo mount.cifs //<TARGET_IP>/<SHARE_NAME> /path/to/local/mountpoint user=,pass=


# --- Null Session Enumeration Tools ---

# winfo (Windows): A simple tool to dump NetBIOS information via a null session.
# The -n flag instructs it to attempt a null session connection.
winfo <TARGET_IP> -n

# enum4linux (Linux): A wrapper for Samba tools to enumerate info from Windows/Samba systems.
enum4linux -a <TARGET_IP>

# rpcclient (Linux): A tool for executing MS-RPC functions, often used with null sessions.
# -N: Do not ask for a password.
# -U "": Use an empty username for anonymous/null session logon.
rpcclient -N -U "" <TARGET_IP>

# -- (Inside the rpcclient prompt) --
# List all available commands within rpcclient.
rpcclient $> help
# Enumerate domain users.
rpcclient $> enumdomusers
# Other useful commands to try: srvinfo, lookupnames, queryuser, enumprivs, enumalsgroups


# === SNMP Enumeration Cheat Sheet ===

# --- Net-SNMP Suite (Linux Tools) ---

# snmpwalk: Uses SNMP GETNEXT requests to query a tree of information.
# -v 2c: Specifies SNMP version 2c.
# -c public: Specifies the community string 'public'.
snmpwalk -v 2c -c public <TARGET_IP>

# snmpwalk with a specific OID to get targeted information (e.g., installed software).
snmpwalk -c public -v1 <TARGET_IP> hrSWInstalledName

# snmpset: Uses an SNMP SET request to modify information on a managed device.
# The 's' specifies the value type is a STRING.
snmpset -v 2c -c public <TARGET_IP> system.sysContact.0 s "new-contact@email.com"


# --- Nmap SNMP Scripts ---

# Find available SNMP scripts in the Nmap script directory.
ls -l /usr/share/nmap/scripts/ | grep -i snmp

# General syntax for running an Nmap SNMP script.
# -sU specifies a UDP scan. -p 161 targets the default SNMP port.
nmap -sU -p 161 --script=<script_name> <TARGET_IP>

# Example: Enumerate Windows services via SNMP.
sudo nmap -sU -p 161 --script=snmp-win32-services <TARGET_IP>

# Example: Enumerate Windows services via SNMP.
sudo nmap -sU -p 161 --script=snmp-win32-users <TARGET_IP>

# Example: Brute-force the SNMP community string using Nmap's default wordlist.
sudo nmap -sU -p 161 --script snmp-brute <TARGET_IP>

# Example: Brute-force the SNMP community string using a custom wordlist.
sudo nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=/path/to/your/wordlist.txt <TARGET_IP>

***

# ==============================================================================
# == NetBIOS and Null Session Enumeration Cheat Sheet (from Video Transcript) ==
# ==============================================================================

# This cheat sheet contains commands and tool usage as demonstrated in the
# "NetBIOS_and_Null_Session.txt" transcript. It covers both Windows and Linux tools.

# --- Initial Discovery & Basic NetBIOS Commands (Windows) ---

# Check if the target is up and if NetBIOS ports are open. The video uses a TCP SYN scan on port 135.
nmap -sS -p 135 <target_IP_Address>

# Use nbtstat to list the remote machine's name table using its IP address.
# The capital -A switch is used when you don't know the machine's name.
# Look for the <20> entry, which indicates a Server Service (file sharing) is active.
nbtstat -A <target_IP_Address>

# Use 'net view' to list the available shares on the target machine.
net view <target_IP_Address>

# Use 'net use' to connect to (map) a shared resource.
# The video shows this establishes a connection but doesn't grant access yet without credentials.
net use \\<target_IP_Address>\<share_name>

# To see the help manual for net use:
net use /?


# --- NetBIOS Auditing & Brute-Forcing (Windows) ---

# NAT (NetBIOS Auditing Tool) - A command-line tool for brute-forcing credentials.
# It uses wordlists for usernames and passwords to attempt logins.
# -u: Specifies the user list file.
# -p: Specifies the password list file.
nat -u UserList.txt -p PassList.txt <target_IP_Address>


# --- GUI Tools for NetBIOS Enumeration (Windows) ---

# Win Fingerprint - A GUI tool for scanning and enumerating NetBIOS information.
# Usage from video:
# 1. Run with administrator privileges.
# 2. Select options like "Null Session" attack.
# 3. Change scan type from "IP Range" to "Single IP".
# 4. Enter the target IP and click "Start".
# 5. The tool can find shares, SIDs (Security Identifiers), and other system info.
echo "GUI Tool: Win Fingerprint - Use the graphical interface to perform scans."


# --- Null Session Exploitation (Windows) ---

# A null session is an anonymous connection to the IPC$ (Inter-Process Communication) share.
# If a system is vulnerable, an attacker can gather significant information without authentication.

# Command to establish a null session connection:
# The double quotes provide an empty username and password.
net use \\<target_IP_Address>\IPC$ "" /user:""

# After a successful null session, you may be able to browse some shares and list files,
# even if you cant execute or access everything.


# --- SID (Security Identifier) Enumeration ---

# SIDs are unique values used to identify users, groups, and computer accounts.
# The last part of a SID (the RID) is unique to the account on the domain.
# Common RIDs: 500 = Administrator, 501 = Guest. RIDs >= 1000 are typically user-created accounts.

# SID to User (Windows Tool) - A tool to find usernames from SIDs.
# The transcript notes you must replace the dashes in the SID with spaces.
sidtouser <target_machine_name> <SID_with_spaces_instead_of_dashes>

# Example of iterating through RIDs:
sidtouser <target_machine_name> <SID_base> 500
sidtouser <target_machine_name> <SID_base> 501
sidtouser <target_machine_name> <SID_base> 1000
sidtouser <target_machine_name> <SID_base> 1001
# ... and so on to discover user accounts.


# --- Automated Information Dumping (Windows) ---

# DumpSec - A GUI security auditing tool for Windows.
# Usage from video:
# 1. Open the GUI tool.
# 2. Go to Report -> Select Computer and enter the target IP (e.g., \\192.168.99.162).
# 3. Go to Report -> Dump Users as column.
# 4. Select the information you want to gather (username, SID, comments, etc.).
# 5. The tool automatically dumps the selected information for all users.
# 6. Its critical to save this output for later phases of a pentest.
echo "GUI Tool: DumpSec - Use the graphical interface to dump system information."


# --- Enumeration from a Linux Host ---

# Enum4linux - A Perl wrapper around Samba tools (smbclient, rpcclient, net, nmblookup)
# to automate enumeration of Windows/Samba systems.

# Dependencies mentioned in the video that may need to be installed:
# polenum (for password policy) and ldap-utils (for ldapsearch).
# Example installation for ldap-utils on Debian/Ubuntu:
sudo apt-get install ldap-utils

# See the help manual for all options.
enum4linux -h

# Perform a full, verbose scan to gather as much information as possible.
# -a: All-in-one scan (runs most checks).
# -v: Verbose mode, shows the underlying commands being run.
enum4linux -a -v <target_IP_Address>

# smbclient - A command-line tool to access SMB/CIFS resources on servers.

# List all available shares on a target.
# -L: List shares.
smbclient -L <target_IP_Address>

# Connect to a specific share. Note the 4 backslashes before the IP.
smbclient \\\\<target_IP_Address>\\<share_name>

# Inside the smbclient prompt, you can use commands like 'ls' or 'dir' to list files.
# To download a file from the share to your local machine:
# smb> get <remote_filename> <local_filename>
# To exit the prompt:
# smb> exit


# =========================================================================
# == SNMP Enumeration Cheat Sheet (from Video Transcript) ==
# =========================================================================

# This cheat sheet contains commands as demonstrated in the "SNMP_Enumeration.txt" transcript.
# SNMP (Simple Network Management Protocol) can reveal a wealth of system information.

# --- SNMP Enumeration with Net-SNMP Tools (Linux) ---

# snmpwalk - A tool that uses SNMP GETNEXT requests to query a network entity for a tree of information.

# See the help manual.
snmpwalk -h

# Perform a basic walk of the target system.
# -v 2c: Specifies SNMP version 2c.
# -c public: Specifies the community string 'public'. This acts like a password.
snmpwalk -v 2c -c public <target_IP_Address>

# Perform a walk starting from a specific OID (Object Identifier) to get targeted info.
# The transcript shows an example to find installed software.
snmpwalk -v 2c -c public <target_IP_Address> <OID_for_installed_software>
# Another example from the video is to get the RAM size.
snmpwalk -v 2c -c public <target_IP_Address> <OID_for_RAM_size>

# snmpset - A tool that uses SNMP SET requests to modify variables on a network entity.
# This requires a community string with write privileges (often 'private').

# First, check a variables current value with snmpwalk. The video uses the 'sysContact' OID.
snmpwalk -v 2c -c <write_community_string> <target_IP_Address> sysContact.0

# Now, use snmpset to change the value.
# 's' specifies the data type is a STRING.
snmpset -v 2c -c <write_community_string> <target_IP_Address> sysContact.0 s "NewValue"

# Verify the change by running the snmpwalk command again.
snmpwalk -v 2c -c <write_community_string> <target_IP_Address> sysContact.0


# --- SNMP Enumeration with Nmap (Linux) ---

# Nmap has a powerful scripting engine (NSE) with many scripts for SNMP.
# General command structure:
# -sU: Specifies a UDP scan.
# -p 161: Targets the default SNMP port.

# List available SNMP scripts in the Nmap scripts folder.
ls -l /usr/share/nmap/scripts/ | grep snmp

# Execute the 'snmp-win32-services' script to enumerate Windows services.
nmap -sU -p 161 --script=snmp-win32-services <target_IP_Address>

# Execute the 'snmp-brute' script to brute-force the community string.
# This will use Nmap's default built-in wordlist.
nmap -sU -p 161 --script=snmp-brute <target_IP_Address>
# Note: You can specify your own wordlist with '--script-args snmp-brute.communitiesdb=/path/to/wordlist.txt'

# Execute the 'snmp-win32-users' script to enumerate local user accounts on a Windows host.
nmap -sU -p 161 --script=snmp-win32-users <target_IP_Address>

```
```
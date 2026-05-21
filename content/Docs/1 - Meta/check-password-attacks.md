+++
title = "Check - Password Attacks"
+++

> **ALWAYS get the password lockout policy before any spraying.** One failed attempt per user per lockout window max. If policy is unknown, one attempt only -- then wait an hour before a second.
> - [Password Policy Enumeration]({{% ref "netexec.md#password-policy-enumeration" %}})

### When to Stop

Password attacks can be frustrating.

- After 3 wordlist attempts with no result: move on and come back after more enumeration reveals a pattern
- If one valid password is found, immediately check it against all discovered users and services
- Check for password reuse across other systems with `nxc --continue-on-success`

### Get Usernames

No usernames = no attack. Don't skip this.

1. [ ] SMB null session or RPC for domain users
    - [User Enumeration via nxc]({{% ref "netexec.md#enumerate-users" %}})

2. [ ] Kerbrute userenum against the DC with a username wordlist
    - [Kerbrute User Enumeration]({{% ref "active-directory.md#user-enumeration" %}})

3. [ ] Anonymous LDAP search if the DC allows it
    - [Anonymous LDAP Search]({{% ref "netexec.md#anonymous-ldap-search" %}})

### Password Spray

| Service                | Tool                                                                                      |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| AD / SMB / WinRM       | `nxc` -- [Password Spraying]({{% ref "netexec.md#password-spraying" %}})                  |
| Kerberos (no auth log) | [Kerbrute's passwordspray]({{% ref "online-credentials-attacks.md#kerberos-spraying" %}}) |
| SSH / FTP / Web form   | `hydra` -- [Brute Force]({{% ref "online-credentials-attacks.md#brute-force-hydra" %}})   |

Try passwords in this order (one per spray run):

1. [ ] Username as the password
2. [ ] `CompanyName` + current year (e.g. `CoolCompany2025`)
3. [ ] `Welcome1` / `Password1` / `ChangeMe123`
4. [ ] Season + year (`Spring2025`, `Fall2024`, `Winter2024`)

### Offline Hash Cracking

| Hash Source | Hashcat Mode |
|-------------|-------------|
| NTLM (SAM/NTDS) | `1000` |
| NTLMv2 (Responder/relay) | `5600` |
| Kerberoast TGS | `13100` |
| AS-REP Roast | `18200` |

Wordlist order:
1. [ ] `rockyou.txt` straight
2. [ ] `rockyou.txt` + `best64.rule`
3. [ ] Custom OSINT list (company name, employees, city, domain keywords)
    - [Wordlist Customization]({{% ref "offline-hash-cracking.md#wordlist-customization" %}})

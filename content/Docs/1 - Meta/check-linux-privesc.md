+++
title = "Check - Linux Privilege Escalation"
+++

### Initial Foothold

1. [ ] Establish identity and orientation: user, hostname, groups
    - [Manual Survey]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

2. [ ] Map the network: interfaces, routes, hosts file -- note any unexpected subnets

3. [ ] Check if the host is domain-joined (`realm list` or `/etc/krb5.conf`)
    - If joined: search for keytab files and list Kerberos tickets

4. [ ] Check sudo privileges immediately -- NOPASSWD entries are instant escalation paths
    - [Checking Sudo Privileges]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

5. [ ] Hunt for credentials in env vars, shell history, and web app config files
    - [Linux Credential Harvesting]({{% ref "authentication-linux.md" %}})

6. [ ] Check ARP table for other hosts and pivot scope

---

### Default Methodology

1. [ ] Run Linux PrivEsc automation scripts. Save output to a file and transfer to attack box to examine in a text editor.
    - [LinPEAS]({{% ref "privilege-escalation-linux.md#linpeas" %}})

2. [ ] Perform basic box enumeration once a foothold is established.
    - [First user checks / network checks]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Checking Sudo Privileges]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Check OS/Kernel Version]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Check `$PATH` variable]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [List processes running as root]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Discover other users on the machine]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Check for SSH keys]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Check current user bash history]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Check if Shadow is readable or Passwd is writable (additionally check for hashes in `/etc/passwd`)]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Enumerate Existing Groups]({{% ref "privilege-escalation-linux.md#groups" %}})
    - [Check for running Cron Jobs]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Check for unmounted file systems and additional drives (Weak NFS Privileges)]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Find writable directories and files]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Enumerate all hidden files and directories]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - Enumerate services, versions, and binaries
    - Check for accessible configuration files
    - Check for accessible scripts

3. [ ] Enumerate for hardcoded / cleartext credentials on the system (quickly check config files).
    - **BE ESPECIALLY ATTENTIVE TO OUT-OF-THE-ORDINARY SERVICES**
    - Look for things in `/opt`
    - Look for web config files
    - [Enumeration: Credential Hunting]({{% ref "finding-creds.md" %}})

4. [ ] Look at access rights of the user we gained a foothold with (Sudo/SUID/GUID).
    - [Checking for Sudo privileges]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Checking SUID/GUID Privileges]({{% ref "privilege-escalation-linux.md#file-permissions" %}})
    - Check these rights in GTFOBins

5. [ ] Check for unique files owned by the user or by the group that the user is in.
    - [Unique Files Owned by User]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

6. [ ] If our user has sudo privileges over a binary not in GTFOBins, try the LD_PRELOAD Privilege Escalation Exploit.
    
7. [ ] If custom binaries exist with the SETUID bit set, try [Shared Object Hacking]({{% ref "privilege-escalation-linux.md#file-permissions" %}}).
    
8. [ ] Check the groups the user is a part of and see if any of them are privileged groups.
    - [Enumerate Existing Groups]({{% ref "privilege-escalation-linux.md#groups" %}})

9. [ ] Check for PATH abuse (unlikely).
    
10. [ ] Check for Wildcard abuse in cron jobs or custom scripts.
    
11. [ ] Look for services running on internal ports that were not accessible from the outside with netstat.
    - [Checking for Internal Listening Ports/Services]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

12. [ ] Check for additional NICs using commands like `ifconfig` to see if there are other sub networks.
    - [Enumerate Network Interfaces]({{% ref "privilege-escalation-linux.md#manual-survey" %}})
    - [Enumerate Other Hostnames]({{% ref "privilege-escalation-linux.md#manual-survey" %}})

13. [ ] Look for cronjobs running writable scripts / services running as root or another privileged user.
    
14. [ ] Look for [abusable Linux capabilities]({{% ref "privilege-escalation-linux.md#capabilities" %}}).
    
15. [ ] Look for vulnerable application / service versions.
    - Vulnerable Services
    - Enumerate Services and Versions
    - Enumerating Binaries

16. [ ] Check for Logrotate exploit.
    
17. [ ] Check for kernel exploits.
    - Search for exploits on GitHub, ExploitDB, and Metasploit

18. [ ] If Python script exists, check for [Python Library Hijacking]({{% ref "privilege-escalation-python.md" %}}).
    
19. [ ] Check for vulnerable versions of Netfilter.
    
20. [ ] Check for hijackable tmux sessions.
    
21. [ ] If `tcpdump` exists on the machine, try capturing cleartext traffic for credentials.
    
22. [ ] Check for recent exploits and zero days.
    - Recent Zero Days

23. [ ] Check `/etc/bash.bashrc` for actions taken on login for any user.
    
24. [ ] Attempt to brute force root user with password file and `sucrack`.

### Linux Container Privilege Escalation

1. [ ] [Linux Containers (LXC/LXD)]({{% ref "privilege-escalation-linux.md#groups" %}})

2. [ ] [Docker Privilege Escalation]({{% ref "privilege-escalation-linux.md#groups" %}})

3. [ ] [Kubernetes Privilege Escalation]({{% ref "privilege-escalation-kubernetes.md" %}})

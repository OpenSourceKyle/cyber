+++
title = "02 - Check - DNS Enumeration"
+++

## DNS Enumeration

### Passive Recon

1. [ ] Gather DNS records from public sources before touching the target
    - [DNS Enumeration via Passive Recon]({{% ref "passive-information-gathering.md#via-dns" %}})
    - Look for A, MX, TXT, NS, SRV records

2. [ ] Enumerate subdomains from certificate transparency logs
    - [Subdomain Discovery]({{% ref "dns.md#subdomains" %}})
    - Use `crt.sh` and similar CT log search

### Active Recon

3. [ ] Identify authoritative nameservers and attempt zone transfer
    - [DNS Zone Transfer & Record Enumeration]({{% ref "dns.md#enumeration" %}})

4. [ ] Enumerate standard record types (A, AAAA, MX, TXT, SRV, NS)
    - Run PTR/reverse lookups against discovered IP ranges
    - [DNS Enumeration]({{% ref "dns.md#enumeration" %}})

5. [ ] Active subdomain brute force
    - [Subdomain Brute Force]({{% ref "ffuf.md#subdomain-search" %}})
    - Use multiple wordlists; combine with passive CT log findings

### Vulnerability Analysis

6. [ ] Check for dangling CNAMEs pointing to unclaimed cloud/SaaS resources (domain takeover)

7. [ ] If internal network -- check LLMNR/NBT-NS exposure
    - [LLMNR & NBT-NS Poisoning]({{% ref "dns.md#llmnr-nbt-ns" %}})
    - If enabled and no SMB signing: run [Responder]({{% ref "protocol-poisoners.md" %}}) to capture hashes

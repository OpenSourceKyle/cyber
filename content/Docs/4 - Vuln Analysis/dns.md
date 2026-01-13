+++
title = "🌐 DNS"
+++

- `UDP 53`: normal name queries
- `TCP 53`: zone transfers and syncs
- Server Config (Bind9)
    - `/etc/bind/named.conf.local`
    - `/etc/bind/named.conf.options`
    - `/etc/bind/named.conf.log`
    - https://wiki.debian.org/BIND9
- https://web.archive.org/web/20250329174745/https://securitytrails.com/blog/most-popular-types-dns-attacks
- Domain Takeover: https://github.com/EdOverflow/can-i-take-over-xyz

{{% details "Dangerous Settings" %}}

| **Option**        | **Description**                                                                |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |
{{% /details %}}

```bash
# Registrar Info
whois <DOMAIN> | whois.txt

# Query Nameserver for domain
dig @<DNS_SERVER> ns <DOMAIN>

# PTR Record or Reverse DNS Query
dig @<DNS_SERVER> -x <IP_ADDRESS>

# OLD: version / all records / zone transfer
dig @<DNS_SERVER> +short CH TXT version.bind <DOMAIN>
dig @<DNS_SERVER> +short ANY <DOMAIN>
dig @<DNS_SERVER> +short AXFR <DOMAIN>

# --- Record Types ---
# ANY: return all records -- sometimes doesnt work!
# A: IPv4 address
# AAAA: IPv6 address
# CNAME: Canonical Name
# MX: Mail Servers
# NS: Name Servers
# PTR: Pointer Record
# SOA: Start of Authority
# TXT: Text Records
# SRV: Service Records
# CAA: Certification Authority Authorization
for type in A AAAA CNAME MX NS SOA SRV TXT CAA; do echo -e "\n--- $type ---"; dig @<DNS_SERVER> +short $type <DOMAIN>; done

# PASSIVE: subdomain enum
# NOTE: requires API keys
subfinder -v -d <DOMAIN>

# ACTIVE: subdomain enum (quick, external)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt <DOMAIN>

# ACTIVE: subdomain enum (slower, internal)
# /usr/share/SecLists/Discovery/DNS/namelist.txt
gobuster dns --threads 64 --output gobuster_dns_top110000 --quiet -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --resolver <DNS_SERVER> --domain <DOMAIN>
```

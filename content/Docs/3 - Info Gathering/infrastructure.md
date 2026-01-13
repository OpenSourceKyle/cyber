+++
title = "🏗️ Infrastructure"
+++

### 🌐 Subdomains

- Certificate Transparency: https://crt.sh/
- https://domain.glass/
- (PAID) https://buckets.grayhatwarfare.com/

```bash
# Domain => Subdomains via Cert Registry
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u | tee subdomainlist.txt
# Full Info 
for i in $(cat subdomainlist.txt) ; do host $i | tee -a hostinfo.txt ; done
# (IPv4) Domain Name => IP Address
for i in $(cat subdomainlist.txt) ; do host $i | grep "has address" | cut -d" " -f1,4 | tee -a domain_ipaddress.txt ; done
# (IPv4) Addresses Only
for i in $(cat domain_ipaddress.txt) ; do host $i | grep "has address" | cut -d" " -f4 | tee -a ip-addresses.txt ; done
# (IPv4) Addresses => Services via Shodan
for i in $(cat ip-addresses.txt) ; do shodan host $i ; done

# DNS: old technique
dig any <DOMAIN>

# Content Search: google.com Dork
inurl:<DOMAIN> intext:<TERM>
```

### **Module: Information Gathering (Footprinting)**

---

### **1. Introduction to Information Gathering**

#### **1.1 Core Concepts**

Penetration Testing (Ethical Hacking) is a methodical, organized, and controlled process. The most critical phase of this process is **Information Gathering**, also known as footprinting. The level of detail gathered during this phase directly determines the effectiveness and success of the entire penetration test.

Testers must be meticulous and utilize a variety of techniques to obtain relevant data. A well-defined scope of engagement is crucial to ensure the right information is pursued.

#### **1.2 Key Aspects of Information Gathering**

The information gathering phase focuses on two essential aspects of a target organization:

1.  **Business:** This involves collecting non-technical information such as the business type, stakeholders, assets, products, services, and employees.
2.  **Infrastructure:** This involves uncovering technical information about the organization's networks, systems, domains, IP addresses, and other operational components.

#### **1.3 Target Information Checklist**

By the end of this process, you should have collected the following types of information:

| Infrastructure          | Business                      |
| ----------------------- | ----------------------------- |
| Network Maps            | Web presence (domains)        |
| Network Blocks          | Physical locations            |
| IP addresses            | Employees / Departments       |
| Ports                   | Emails                        |
| Services                | Partners and third parties    |
| DNS                     | Press / news releases         |
| Operating systems       | Documents                     |
| Alive machines          | Financial information         |
| Systems                 | Job postings                  |

#### **1.4 Passive vs. Active Techniques**

Information gathering techniques are classified into two main disciplines:

*   **Passive (OSINT - Open Source Intelligence):** Gathering information about a target without directly interacting with their systems. This relies on publicly available resources like websites, social media, financial reports, and news articles. It is stealthy and does not expose the investigator's presence.
*   **Active:** Interacting directly with the target's systems to gather information about ports, services, running systems, etc. These techniques can be detected by Intrusion Detection Systems (IDS) or server logs, so caution is required.

---

### **2. Storing and Managing Information**

As you amass a large amount of data, organization is key.

*   **Mind Mapping Tools:** Use tools like FreeMind or Xmind to organize findings visually.
    *   FreeMind: [http://freemind.sourceforge.net/wiki/index.php/Main_Page](http://freemind.sourceforge.net/wiki/index.php/Main_Page)
    *   Xmind: [https://www.xmind.net/](https://www.xmind.net/)

*   **Specialized Frameworks:** For network and vulnerability data, tools designed for penetration testing are highly effective. They facilitate collaboration and can import scans from tools like Nmap, Burp Suite, and Nessus.
    *   Dradis: [https://dradisframework.com/ce/](https://dradisframework.com/ce/)
    *   Faraday: [https://github.com/infobyte/faraday](https://github.com/infobyte/faraday)
    *   MagicTree: [https://www.gremwell.com/what_is_magictree](https://www.gremwell.com/what_is_magictree)

*   **Methodology Guide:** Refer to the "Handling information" guide available in the eLearnSecurity Members area for best practices on collecting and storing data.
    *   Link: [https://members.elearnsecurity.com/course/resources/name/ptp_v5_section_2_module_1_attachment_eLearnSecurity_Handling_Information](https://members.elearnsecurity.com/course/resources/name/ptp_v5_section_2_module_1_attachment_eLearnSecurity_Handling_Information)

---

### **3. Business Information Gathering**

This phase focuses on leveraging search engines and social media to understand the business context of the target.

#### **3.1 Using Search Engines for Business Intelligence**

**A. Analyzing Web Presence**

The company's official website is the primary source of information. Study it to understand:
*   Business purpose and services.
*   Physical and logical locations.
*   Employee information and departments.
*   Email and contact details.
*   Alternative websites, sub-domains, and press releases.

**B. Advanced Search with Google Dorks**

Google's advanced search operators (dorks) can uncover information not easily found through simple searches.

*   **Key Operators:**
    *   `cache:www.website.com`: Shows Google's cached version of the site.
    *   `link:www.website.com`: Displays websites linking to the specified site.
    *   `site:www.website.com`: Restricts the search to a specific website.
    *   `filetype:pdf`: Searches for a specific file extension.

*   **Example Query:** To find all PDF documents related to "elearnsecurity":
    
    ```
    elearnsecurity filetype:pdf
    ```
    
    This can reveal documents that are no longer linked on the live website.

*   **Google Hacking Resources:**
    *   [https://support.google.com/websearch/answer/136861?hl=en&ref_topic=3081620](https://support.google.com/websearch/answer/136861?hl=en&ref_topic=3081620)
    *   [www.googleguide.com/advanced_operators_reference.html](http://www.googleguide.com/advanced_operators_reference.html)
    *   [http://pdf.textfiles.com/security/googlehackers.pdf](http://pdf.textfiles.com/security/googlehackers.pdf)
    *   [https://www.exploit-db.com/google-hacking-database/](https://www.exploit-db.com/google-hacking-database/)

**C. U.S. Government Contractor Information**

Organizations selling to the U.S. government must have DUNS and CAGE codes. These can be searched on the System for Award Management (SAM) website to find contacts, contracts, and product lists.
*   SAM.gov: [https://www.sam.gov/errors/pageIE11Bellow.html](https://www.sam.gov/errors/pageIE11Bellow.html)

**D. Publicly Traded Company Information**

Publicly traded companies file financial documents with the SEC. The EDGAR database is a primary source for this information.
*   EDGAR: [http://www.sec.gov/edgar.shtml](http://www.sec.gov/edgar.shtml)

**E. Mergers, Acquisitions, and Partners**

Investigating a company's partners and acquisition history can reveal the technologies and systems they use internally, which is valuable for later stages of the test and for social engineering.

**F. Job Postings**

Career sections on corporate websites or job boards (Indeed, LinkedIn, Monster, Glassdoor) can reveal:
*   Internal hierarchies and team structures.
*   Technology stacks (e.g., "Requires experience with Cisco firewalls").
*   Financed projects and internal initiatives.
*   Weak or understaffed departments.

**G. Financial Information**

Financial details can reveal investment in specific technologies, potential mergers, and critical business services.
*   Crunchbase: [www.crunchbase.com](https://www.crunchbase.com) (Finds info on companies, people, investors)
*   Inc.com: [www.inc.com](https://www.inc.com) (Focuses on growing companies)
*   Other resources: Google Finance, Yahoo Finance, EDGAR

**H. Document & Metadata Harvesting**

Documents created by an organization often contain metadata (creator, creation date, software used, computer name).

*   **Finding Files:** Use Google Dorks to find specific file types.
    
    ```
    site:elearnsecurity.com filetype:pdf
    ```
    
    (This can be modified for `doc`, `xls`, `txt`, etc.)

*   **Metadata Extraction with FOCA:** FOCA (Fingerprinting Organizations with Collected Archives) is a Windows tool that automates finding, downloading, and extracting metadata from public documents.
    *   FOCA: [https://www.elevenpaths.com/labstools/foca/index.html](https://www.elevenpaths.com/labstools/foca/index.html)

*   **Automated Harvesting with theHarvester:** This tool uses public sources (Google, Bing, LinkedIn) to enumerate email accounts, user names, domains, and hostnames.
    *   theHarvester: [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)
    *   **Example Command:**
        
        ```
        theharvester -d elearnsecurity.com -l 100 -b google
        ```
        
        *   `-d`: domain or company to search
        *   `-l`: limit number of results
        *   `-b`: data source (google, bing, linkedin, etc.)

**I. Cached and Archival Sites**

Older versions of a website can contain information that has since been removed.
*   **The Wayback Machine:** [https://archive.org/](https://archive.org/) allows you to browse historical snapshots of websites.
*   **Google Cache:** Use the `cache:www.website.com` dork to see Google's latest cached version.

#### **3.2 Using Social Media for Business Intelligence**

Social media is a powerful tool for gathering information on employees, which is often the weakest link in security.

*   **Corporate Culture & Hierarchies:** Company pages on LinkedIn reveal employees, events, products, and locations.
*   **Building a People Network Map:**
    *   Use LinkedIn's advanced search to find employees by title, position, and location.
    *   Be aware that viewing profiles on LinkedIn may notify the user unless your privacy settings are configured for stealth.
    *   If a profile is private, use a search engine with a query like:
        
        ```
        site:linkedin.com "President and CEO at Agiliance"
        ```
        
*   **Exploiting Trust Relationships:** Understanding who trusts whom is key for social engineering. Public conversations on Twitter or connections on LinkedIn can reveal these relationships.
*   **Finding Personal Information:**
    *   Pipl: [www.pipl.com](https://www.pipl.com)
    *   Spokeo: [https://www.spokeo.com/](https://www.spokeo.com/)
    *   PeopleFinders: [https://www.peoplefinders.com/](https://www.peoplefinders.com/)
    *   Crunchbase: [https://www.crunchbase.com/](https://www.crunchbase.com/)
*   **Usenet and Newsgroups:** Searching Google Groups or Usenet archives for employee names or emails can uncover sensitive data shared in public forums.

---

### **4. Infrastructure Information Gathering**

This phase moves into more technical reconnaissance. **Authorization is required for any active techniques.**

#### **4.1 Full Scope Engagement (Starting with a Name)**

This approach mimics a real attacker who starts with only the organization's name. The goal is to discover all related hostnames and their IP addresses.

**A. WHOIS Lookup**

WHOIS is a query/response protocol used to look up information on registered domains, IP addresses, and Autonomous Systems (ASNs).
*   **Data Provided:** Domain owner, technical contacts, expiration date, name servers.
*   **RIRs (Regional Internet Registries):** AFRINIC, APNIC, ARIN, LACNIC, RIPE NCC.
*   **Online Tools:**
    *   [http://who.is](http://who.is)
    *   [http://whois.domaintools.com](http://whois.domaintools.com)
    *   [http://bgp.he.net/](http://bgp.he.net/)
*   **Key Information:** The **name servers** found in the WHOIS record are the authoritative source for the domain's DNS information.

**B. DNS Enumeration**

The Domain Name System (DNS) maps human-readable hostnames to machine-readable IP addresses. It's a critical component to investigate.

*   **Common DNS Record Types:**
    *   `SOA` (Start of Authority): Indicates the primary source of information for the zone.
    *   `NS` (Name Server): Defines an authoritative name server for the zone.
    *   `A` (Address): Maps a hostname to an IPv4 address.
    *   `PTR` (Pointer): Maps an IP address to a hostname (for reverse lookups).
    *   `CNAME` (Canonical Name): Maps an alias to an A record.
    *   `MX` (Mail Exchange): Specifies the mail server for the domain.

*   **DNS Query Tools: `nslookup` and `dig`**

| Task                        | `nslookup` (Windows)                                  | `dig` (Linux)                          |
| --------------------------- | ----------------------------------------------------- | -------------------------------------- |
| Basic Lookup                | `nslookup target.com`                                 | `dig target.com +short`                |
| PTR Record                  | `nslookup -type=PTR ip_address`                       | `dig -x ip_address`                    |
| MX Record                   | `nslookup -type=MX target.com`                        | `dig target.com MX`                    |
| NS Record                   | `nslookup -type=NS target.com`                        | `dig target.com NS`                    |
| Zone Transfer (AXFR)        | REMOVED `nslookup`<br>`> server ns.target.com`<br>`> ls -d target.com` | `dig axfr @ns.target.com target.com`   |

*   **Zone Transfers:** A misconfiguration where a DNS server allows anyone to request a full copy of its zone file, revealing all subdomains. This is a high-value finding.

*   **Quick DNS Enumeration Examples:**
    *   **fierce:** A DNS reconnaissance tool for locating non-contiguous IP space.
        
        ```
        fierce --domain target.com
        ```
        
    *   **dnsenum.pl:** Alternative DNS enumeration script.
        
        ```
        dnsenum.pl target.com
        ```
        
    *   **dnsmap:** Tool for subdomain enumeration and brute-forcing.
        
        ```
        dnsmap target.com
        ```
        
    *   **dnsrecon:** All-in-one DNS reconnaissance tool.
        
        ```
        dnsrecon -d target.com
        ```



**C. IP Address Investigation**

Once you have hostnames, you need their IP addresses and to understand who owns them.

*   **Reverse IP Lookup:** Use Bing's `ip:` filter to find all websites hosted on a single IP address.
    
    ```
    ip:199.193.116.231
    ```
    
*   **Online Reverse IP Tools:**
    *   Domain-neighbors: [https://dnslytics.com/reverse-ip](https://dnslytics.com/reverse-ip)
    *   Domaintools: [http://reverseip.domaintools.com/](http://reverseip.domaintools.com/)
    *   Robtex: [https://www.robtex.com/](https://www.robtex.com/)

*   **Netblocks and Autonomous Systems (ASNs):**
    *   A **netblock** is a range of IP addresses (e.g., 192.168.0.0/16).
    *   An **Autonomous System** is a collection of netblocks under a single administrative control (e.g., a large corporation or ISP).
    *   Use a WHOIS tool (like `whois.arin.net`) on an IP address to determine the owner of the netblock. This helps verify if an IP belongs to your target or a hosting provider.

#### **4.2 Narrowed Scope Engagement (Starting with IPs/Netblocks)**

When the client provides a list of IPs or network ranges, the process is more direct.

**A. Live Host Discovery (Ping Sweep)**

The first step is to identify which hosts are online.
*   **ICMP Ping Sweep:** The traditional method, but often blocked by firewalls.
*   **Tools:**
    *   **fping:** A command-line tool for pinging multiple hosts.
        
        ```
        fping --alive --elapsed --retry 0  --generate <IP_ADDR>/24  # ICMP ping (IP addr)
        # --elapsed can be useful to find firewalls or IDS
        ```
        
    *   **hping3:** Advanced network packet analyzer for host discovery.
        
        ```
        hping3 --count 1 --icmp <IP_ADDR>
        hping3 --count 1 --udp <IP_ADDR>  # sends to port 0 which gives a  port unreachable for positive
        hping3 --count 1 --syn <IP_ADDR>  # sends to port 0 which gives RA or RST/ACK for positive
        hping3 --count 1 --syn --destport 3389 <IP_ADDR>  # sends to port 3389 which gives SA or SYN/ACK for positive
        hping3 --icmp --interface eth0  --rand-dest 192.168.1.x
        ```
        
    *   **nmap:** The most popular and powerful network scanner. For host discovery only (no port scan), use the `-sn` flag.
        
        ```
        nmap --disable-arp-ping -sn -PS [NETBLOCK]/24
        # sends ARP by default in same network; otherwise use --disable-arp-ping
        # -sn means skip port scan

        nmap --disable-arp-ping -PS53 <IP_ADDR>  # TCP SYN port 53
        nmap --disable-arp-ping -PU53 <IP_ADDR>  # UDP port 53
        nmap --disable-arp-ping -PY53 <IP_ADDR>  # SCTP INIT port 53
        nmap --disable-arp-ping -PE <IP_ADDR>  # ICMP echo
        nmap --disable-arp-ping -PM <IP_ADDR>  # ICMP mask
        nmap --disable-arp-ping -PP <IP_ADDR>  # ICMP timestamp
        ```
        
*   **Advanced Host Discovery:** When ICMP is blocked, `nmap -sn` automatically uses other probes, including:
    *   TCP SYN to port 443
    *   TCP ACK to port 80
    *   ICMP Timestamp request
    *   If run on the local network, it defaults to an ARP scan.

**B. Further DNS Enumeration on a Network**

Even with a list of IPs, you should scan for DNS servers to potentially find more domains and hosts.
*   DNS runs on TCP/53 and UDP/53.
*   Use Nmap to scan the entire network for these open ports:
```
nmap -sS -p53 [NETBLOCK]  # TCP SYN Scan
nmap -sU -p53 [NETBLOCK]  # UDP Scan
```  
    
*   If new DNS servers are found, perform lookups and attempt zone transfers on them.

---

### **5. Key Tools for Automated Information Gathering**

*   **DNSdumpster:** A free online tool that provides a comprehensive report on a domain, including DNS records, server locations, and a graphical map.
    *   Link: [https://dnsdumpster.com/](https://dnsdumpster.com/)

*  Google Dorking: `site:*.example.com -www`

*   **DNSEnum:** A Perl script that gathers extensive information (host addresses, name servers, MX records), attempts zone transfers, scrapes names from Google, and performs brute-force subdomain discovery from a file.
    *   Link: [https://github.com/fwaeytens/dnsenum](https://github.com/fwaeytens/dnsenum)
    *   **Example Command:**
        
        ```
        dnsenum --subfile elsfoosubs.txt -v -f /usr/share/dnsenum/dns.txt -u a -r elsfoo.com
        ```
        
*   **dnsmap:** A straightforward tool for subdomain enumeration and brute-forcing using a built-in or user-supplied wordlist.
    *   Link: [https://github.com/makefu/dnsmap](https://github.com/makefu/dnsmap)
    *   **Example Command:**
        
        ```
        dnsmap elsfoo.com -w wordlist.txt
        ```
        
*   **Maltego:** A powerful OSINT and forensics application that uses "transforms" to discover and map relationships between pieces of information (domains, people, IPs, etc.).
    *   Link: [https://www.paterva.com/web7/](https://www.paterva.com/web7/)

---

### **6. Practical Lab: eLSFoo Information Gathering**

**Objective:** Apply the learned techniques to perform information gathering on a fictitious company, eLSFoo, created by eLearnSecurity. You are authorized for reconnaissance on this target.

*   **Target Domain:** `www.elsfoo.com`
*   **Goal:** Create a mind map containing information about eLSFoo, including:
    *   Employees and company hierarchy.
    *   Email addresses, phone numbers, and other personal details.
    *   Domains, subdomains, and IP addresses.
    *   DNS records (NS, MX, etc.).
    *   Any other relevant business or infrastructure details.

---

````markdown
# 🧠 Reconnaissance Tools Cheatsheet (Kali Linux)

## 🔹 DNSdumpster (Web-Based)
- Passive DNS and subdomain recon
- **URL**: [https://dnsdumpster.com](https://dnsdumpster.com)

---

## 🔹 DNSEnum
```bash
# Basic DNS enumeration
dnsenum example.com

# Full DNS enum with subdomain brute-force
dnsenum --enum example.com

# Specify nameserver in case of routing issues
dnsenum --dnsserver <IP_ADDR> -enum -f /usr/share/wordlists/dnsmap.txt foocampus.com

# Use a custom subdomain wordlist
dnsenum --enum -f /usr/share/wordlists/dnsmap.txt example.com
````

---

## 🔹 Metagoofil

```bash
# Extract metadata from public documents (PDF, DOC, XLS)
metagoofil -d example.com -t pdf,doc,xls -l 100 -n 20 -o ./downloads -f result.html
```

---

## 🔹 Maltego

```bash
# Launch Maltego GUI (Community Edition)
maltego
```

- Visual OSINT analysis (people, domains, emails, etc.)
    
- Register for free CE license on first run.
    

---

## 🔹 Recon-ng

```bash
# Start Recon-ng
recon-ng

# Inside Recon-ng shell:
marketplace install all

# Use a module (e.g., Bing host discovery)
use recon/domains-hosts/bing_domain_web
set SOURCE example.com
run

# View and export results
show hosts
export csv /tmp/output.csv
```

---

# LAB COMMANDS

```
# TCP Scan
nmap -Pn -n -sS -sV \
  --max-retries 1 \
  --host-timeout 45s \
  --initial-rtt-timeout 300ms \
  --max-rtt-timeout 1000ms \
  -p 21,22,23,25,53,80,110,135,139,443,445,3389 \
  <target>
```
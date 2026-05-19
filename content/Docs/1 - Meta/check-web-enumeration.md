+++
title = "Check - Web Enumeration"
+++

## Webserver Enumeration Methodology

### Passive Recon

1. [ ] Look at public DNS records for domains/subdomains to enumerate.
    - [DNS Enumeration]({{% ref "passive-information-gathering.md#via-dns" %}})

2. [ ] Look at certificates and other public info for domains/subdomains to enumerate.
    - [Public Domain Information]({{% ref "passive-information-gathering.md" %}})

### Active Recon

1. [ ] Add domain to `/etc/hosts` file and [`EyeWitness` all pages from `nmap` results]({{% ref "common-web-applications.md#eyewitness" %}})
    
2. [ ] Run directory/page brute force discovery.
    - [First fuzz for extension]({{% ref "ffuf.md#find-file-extension" %}})
    - [If extension is discovered, fuzz for directories and other pages (with extension appended)]({{% ref "ffuf.md#search-file-extensions" %}})
    - [Directory Brute-Forcing]({{% ref "http.md#directory-brute-forcing" %}})

3. [ ] Look in `robots.txt` or `sitemap.xml` for hidden endpoints.
    - `https://www.example.com/robots.txt`
    - `https://www.example.com/sitemap.xml`

4. [ ] Run subdomain/vhost brute force discovery (**run multiple wordlists**).
    - [Subdomain brute force discovery (external only)]({{% ref "ffuf.md#subdomain-search" %}})
    - [vHost Brute Force (internal & external)]({{% ref "ffuf.md#vhost-brute-force" %}})

5. [ ] Crawl the webpage for all links.
    - [Web Crawling / Robots]({{% ref "http.md" %}})
    - [Crawling with FinalRecon]({{% ref "http.md#directory-brute-forcing" %}})
    - [Crawling with ZAP Proxy]({{% ref "web-proxy-tools-zap-burp.md" %}})

6. [ ] Look for comments in HTML for sensitive information.
    - Check all crawled and discovered pages (EyeWitness)

7. [ ] Capture server errors (e.g. 500, 403) that might leak tech stack info.
    
8. [ ] Look for vulnerabilities in web server technologies being used.
    - Use Wappalyzer to discover web server technologies in browser
    - Use BuiltWith to discover web server technologies (external only)
    - [Use WhatWeb CLI tool to discover web server technologies]({{% ref "http.md" %}})
    - [Scan the webserver with Nikto to discover web technologies and vulnerabilities]({{% ref "http.md" %}})
    - [Scan the webserver with NMAP and web discovery scripts]({{% ref "nmap.md" %}})
    - Banner grab the webserver
    - [Discover Web Application Firewalls (WAFs) with Wafw00f]({{% ref "http.md" %}})

9. [ ] If the webserver is determined to be running NodeJS or MongoDB, look for NoSQL injection vulnerabilities.
    
10. [ ] Look for web service versions on discovered pages (Jenkins, WP, blog platforms, etc.). Use enumeration techniques depending on the technology.
    - Look for CMS or app-specific files (`wp-content`, `.git/`, etc.)
    - [WordPress Enumeration]({{% ref "common-web-applications.md#wordpress" %}})
    - [Joomla Enumeration]({{% ref "common-web-applications.md#joomla" %}})
    - [Drupal Enumeration]({{% ref "common-web-applications.md#drupal" %}})
    - [Tomcat Enumeration]({{% ref "common-web-applications.md#tomcat" %}})
    - [Jenkins Enumeration]({{% ref "common-web-applications.md#jenkins" %}})
    - IIS Tilde Enumeration
    - Other

11. [ ] Look for vulnerabilities in discovered web service versions and/or technologies.
    - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})
    - Search ExploitDB for service exploits with the discovered version
    - Search Google for `<Service> <Version> Exploit GitHub`

12. [ ] Look for login pages to test default or weak credentials.
    - [Default Credential lists]({{% ref "online-credentials-attacks.md#default-creds" %}})
    - [Login Brute Forcing]({{% ref "online-credentials-attacks.md" %}})
    - Check for password reset or recovery mechanisms
    - Review cookies & sessions (flags like Secure, HttpOnly)
    - Test for session fixation or missing CSRF protections

13. [ ] Test submitting data on EVERY user input field and look at interaction with Burp Suite.
    - [Intercepting Web Requests]({{% ref "web-proxy-tools-zap-burp.md" %}})
    - [Test SQL Injection on login pages to try and bypass them]({{% ref "sql-injection.md" %}})

14. [ ] If input appears to be used in a system command, test for [command injection]({{% ref "command-injection.md" %}}).
    
15. [ ] If a file upload functionality exists, test for [file upload vulnerabilities]({{% ref "file-upload.md" %}}).
    
16. [ ] If the webserver appears to be populating data from a database, test for [SQL Injection]({{% ref "sql-injection.md" %}}).
    - Test for SQL UNION Injection separately (`test' UNION select 1-- -`)
    - Any input fields, test with [sqlmap]({{% ref "sqlmap.md" %}})
    - [Test SQL Injection on login pages to try and bypass them]({{% ref "sql-injection.md" %}})

17. [ ] If Accounts, Pages, or other things on the webpage seem sequential and accessible in a GET or POST request, check for [IDOR vulnerabilities]({{% ref "web-exploitation.md#insecure-direct-object-references-idor" %}}).
    
18. [ ] If GET parameters seem to be referencing local files on the system, test for [file inclusion vulnerabilities / path traversal]({{% ref "file-inclusion.md" %}}).
    - Run an LFI automation scan against any parameters that reference a file, especially in GET requests like `http://example.com/index.php?page=goober.html`
    - If LFI exists, look for the following payloads:
        - `/etc/passwd`
        - `/var/mail/<username>` (if we can send emails to user then we can send and access a PHP webshell)
        - `/home/<username>/.ssh/id_rsa`
        - Webserver source code (index page and other interesting pages):
            - `/etc/nginx/nginx.conf`
            - `/etc/nginx/sites-enabled/default`
            - `/etc/nginx/sites-available/default`
            - `/etc/apache2/sites-enabled/default`
            - `/etc/apache2/sites-available/default`
        - `/var/log/apache2/access.log` (for log poisoning)
        - `/var/log/nginx/access.log` (for log poisoning)
        - Any file paths from error pages

19. [ ] Check user input fields for [XSS]({{% ref "xss.md" %}}).
    
20. [ ] Check different [HTTP verbs to bypass access controls]({{% ref "web-exploitation.md#http-verb-tampering" %}}) or injection validations.
    
21. [ ] If XML input is accepted, test for [XML External Entity (XXE) vulnerabilities]({{% ref "ssti-xxe.md" %}}).
    
22. [ ] If the webserver has a web socket or API that is reachable, check if the POST/GET requests are injectable with SQLMAP.
    - [Websocket / API Injection]({{% ref "sqlmap.md" %}})

### Shells and Payloads

1. [ ] [Linux Reverse Shells]({{% ref "shells.md" %}})

2. [ ] Going from webshell to reverse shell on Linux:
    - [Web Shells]({{% ref "shells.md#web" %}})
    - Make sure to URL encode the payload

### On Webserver

1. [ ] Check web configuration files and source code for vulnerabilities, hardcoded credentials, etc.
    - [Enumeration: Credential Hunting]({{% ref "finding-creds.md" %}})
    - Check the source code of all pages, including index
    - Apache (httpd) default locations:
        - `/var/www/html`
        - `/var/www/`
        - `/srv/http/` (Arch Linux)
        - `/usr/share/httpd/` (RHEL/CentOS)
        - `/etc/apache2/sites-available/000-default.conf`
    - Nginx default locations:
        - `/usr/share/nginx/html`
        - `/var/www/html`
        - `/etc/nginx/sites-available/` and `/etc/nginx/sites-enabled/`
    - Other possible locations:
        - `/opt/web/`
        - `/home/user/public_html/`
        - `~/www/` or `~/html/`

---

## Foothold Triage

> Quick-strike decision tree once enumeration surfaces something to work with. Triage by finding type.

### Initial Triage

1. [ ] Fingerprint the server, framework, and WAF
    - [Web Technology Fingerprinting]({{% ref "http.md" %}})
    - Known CVE for detected version: check ExploitDB first -> done
    - No known CVE: continue

2. [ ] Directory and file brute force -- catalog all endpoints, login forms, upload points, and API paths
    - [Directory Brute-Forcing]({{% ref "http.md#directory-brute-forcing" %}})
    - [ffuf -- File Extension & Directory Search]({{% ref "ffuf.md#example-commands" %}})

3. [ ] Run an automated vulnerability scan against discovered paths
    - No template match: continue manual triage below

### By Finding Type

4. [ ] Login form
    - Try default credentials first
    - [Default Credential Lists]({{% ref "online-credentials-attacks.md#default-creds" %}})
    - Test for SQL injection auth bypass
    - [SQL Injection on Login Pages]({{% ref "sql-injection.md" %}})

5. [ ] File upload endpoint
    - [File Upload Exploitation]({{% ref "file-upload.md" %}})
    - Test extension bypass -> Content-Type mismatch -> magic bytes -> SVG XXE -> RCE or LFI

6. [ ] Parameters that reflect user input
    - Template expression (`{{7*7}}`): [SSTI]({{% ref "ssti-xxe.md" %}})
    - HTML injection (`<script>alert(1)</script>`): [XSS]({{% ref "xss.md" %}})
    - OS command (`; id`): [Command Injection]({{% ref "command-injection.md" %}})
    - Path traversal (`../../../etc/passwd`): [File Inclusion / LFI]({{% ref "file-inclusion.md" %}})

7. [ ] XML-accepting endpoint (`Content-Type: application/xml`, SOAP)
    - [XXE Injection]({{% ref "ssti-xxe.md" %}})
    - Probe with entity injection -> reflected: classic XXE | no reflection: try OOB exfil

8. [ ] Admin panel
    - Try default credentials
    - Test auth bypass headers (`X-Forwarded-For: 127.0.0.1`)
    - Test for [IDOR]({{% ref "web-exploitation.md#insecure-direct-object-references-idor" %}}) on user ID parameters

9. [ ] Parameters referencing file paths (`?page=`, `?file=`, `?path=`)
    - [File Inclusion / Path Traversal]({{% ref "file-inclusion.md" %}})

10. [ ] Nothing bites -- check for SSRF and hidden API surface
    - Look for request parameters accepting URLs or destinations (`?url=`, `?dest=`, webhooks)
    - [SSRF]({{% ref "ssrf.md" %}})
    - Review JavaScript source for hidden endpoints, API keys, GraphQL paths

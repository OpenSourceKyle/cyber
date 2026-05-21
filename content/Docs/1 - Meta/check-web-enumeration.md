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

2. [ ] Fingerprint server technology and check for known CVEs.
    - [Web Technology Fingerprinting]({{% ref "http.md" %}})
    - Known CVE for detected version: check ExploitDB first -- if found, exploit and move on

3. [ ] Run directory/page brute force discovery.
    - [First fuzz for extension]({{% ref "ffuf.md#find-file-extension" %}})
        - [If extension is discovered, fuzz for directories and other pages (with extension appended)]({{% ref "ffuf.md#search-file-extensions" %}})
    - [Directory Brute-Forcing]({{% ref "http.md#directory-brute-forcing" %}})

4. [ ] Look in `robots.txt` or `sitemap.xml` for hidden endpoints.
    - `https://www.example.com/robots.txt`
    - `https://www.example.com/sitemap.xml`

5. [ ] Run subdomain/vhost brute force discovery (**run multiple wordlists**).
    - [Subdomain brute force discovery (external only)]({{% ref "ffuf.md#subdomain-search" %}})
    - [vHost Brute Force (internal & external)]({{% ref "ffuf.md#vhost-brute-force" %}})

6. [ ] Fuzz for hidden GET/POST parameters on discovered endpoints.
    - [Parameter Fuzzing]({{% ref "ffuf.md#parameter-fuzzing" %}})

7. [ ] Crawl the webpage for all links.
    - [Web Crawling / Robots]({{% ref "http.md" %}})

8. [ ] Look for comments in HTML for sensitive information.
    - Check all crawled and discovered pages (EyeWitness)

9. [ ] Capture server errors (e.g. 500, 403) that might leak tech stack info.

10. [ ] If the webserver is determined to be running NodeJS or MongoDB, look for NoSQL injection vulnerabilities.

11. [ ] Look for web service versions on discovered pages (Jenkins, WP, blog platforms, etc.). Use enumeration techniques depending on the technology.
    - Look for CMS or app-specific files (`wp-content`, `.git/`, etc.)
    - [WordPress Enumeration]({{% ref "common-web-applications.md#wordpress" %}})
    - [Joomla Enumeration]({{% ref "common-web-applications.md#joomla" %}})
    - [Drupal Enumeration]({{% ref "common-web-applications.md#drupal" %}})
    - [Tomcat Enumeration]({{% ref "common-web-applications.md#tomcat" %}})
    - [Jenkins Enumeration]({{% ref "common-web-applications.md#jenkins" %}})
    - IIS Tilde Enumeration
    - Other

12. [ ] Look for vulnerabilities in discovered web service versions and/or technologies.
    - [Search Metasploit for service exploits with the discovered version]({{% ref "metasploit.md" %}})
    - Search ExploitDB for service exploits with the discovered version
    - Search Google for `<Service> <Version> Exploit GitHub`

### By Finding

13. [ ] **Login form** -- work through in order:
    - Try default credentials first -- [Default Credential Lists]({{% ref "online-credentials-attacks.md#default-creds" %}})
    - [Test for SQL injection auth bypass]({{% ref "sql-injection.md" %}})
    - [Brute force with Hydra if lockout policy permits]({{% ref "online-credentials-attacks.md" %}})
    - Check password reset and recovery mechanisms
    - Review session cookies (Secure, HttpOnly flags) and CSRF protections

14. [ ] **File upload endpoint**
    - [File Upload Exploitation]({{% ref "file-upload.md" %}})
    - Chain: extension bypass → Content-Type mismatch → magic bytes → SVG XXE → RCE or LFI

15. [ ] **Parameters that reflect user input** -- test each payload type:
    - Template expression (`{{7*7}}`): [SSTI]({{% ref "ssti-xxe.md" %}})
    - HTML/JS injection (`<script>alert(1)</script>`): [XSS]({{% ref "xss.md" %}})
    - OS command (`; id`): [Command Injection]({{% ref "command-injection.md" %}})
    - Path traversal (`../../../etc/passwd`): [File Inclusion / LFI]({{% ref "file-inclusion.md" %}})
    - [Intercept and test all input with Burp Suite]({{% ref "web-proxy-tools-zap-burp.md" %}})

16. [ ] **XML-accepting endpoint** (`Content-Type: application/xml`, SOAP)
    - [XXE Injection]({{% ref "ssti-xxe.md" %}})
    - Probe with entity injection → reflected: classic XXE | no reflection: try OOB exfil

17. [ ] **Admin panel**
    - Try default credentials
    - Test auth bypass headers (`X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`)
    - Test for [IDOR]({{% ref "web-exploitation.md#insecure-direct-object-references-idor" %}}) on user ID parameters

18. [ ] **Parameters referencing file paths** (`?page=`, `?file=`, `?path=`)
    - [File Inclusion / Path Traversal]({{% ref "file-inclusion.md" %}})
    - Run an LFI automation scan against any parameters that reference a file
    - If LFI confirmed, try:
        - `/etc/passwd`
        - `/home/<username>/.ssh/id_rsa`
        - `/var/mail/<username>` (PHP webshell via mail poisoning)
        - Webserver config: `/etc/nginx/nginx.conf`, `/etc/apache2/sites-enabled/default`
        - Log poisoning: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`
        - Any file paths leaked from error pages

19. [ ] **Sequential IDs or object references** in GET/POST requests
    - [IDOR]({{% ref "web-exploitation.md#insecure-direct-object-references-idor" %}})

20. [ ] **HTTP verb tampering** -- try alternate verbs to bypass access controls or validation
    - [HTTP Verb Tampering]({{% ref "web-exploitation.md#http-verb-tampering" %}})

21. [ ] **Websocket or API endpoint**
    - [Websocket / API Injection with sqlmap]({{% ref "sqlmap.md" %}})

22. [ ] **Nothing bites** -- check for SSRF and hidden surface
    - Look for parameters accepting URLs or destinations (`?url=`, `?dest=`, webhooks): [SSRF]({{% ref "ssrf.md" %}})
    - Review JavaScript source for hidden endpoints, API keys, GraphQL introspection paths

### Shells and Payloads

1. [ ] [Linux Reverse Shells]({{% ref "shells.md" %}})

2. [ ] Going from webshell to reverse shell:
    - [Web Shells]({{% ref "shells.md#web" %}})
    - Make sure to URL encode the payload as needed

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

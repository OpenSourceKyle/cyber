+++
title = "HTTP"
+++

- `TCP 80`: HTTP unencrypted
- `TCP 443`: HTTPS encrypted
- `PORT` (Web is oftentimes on other ports, especially internal proxies or admin pages on `8080` or `8433`)

{{< embed-section page="Docs/2 - Pre-Engagement/checklist" header="web" >}}

- OWASP Top 10:
    - https://owasp.org/www-project-top-ten/
- HTTP Codes:
    - https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Standard_codes
- Web Page Scanner:
    - https://github.com/RedSiege/EyeWitness
- `/.well-known/` URIs:
    - https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
- User-Agent: https://useragents.io/explore
- Default Web Roots:
    - Linux: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt
    - Windows: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt

```bash
# HTTP Headers + robots.txt
curl -skLI -o curl_http_headers.txt http://<TARGET>
curl -skL -o curl_robots.txt http://<TARGET>/robots.txt

---

# Checks for WAF (wbapp firewall)
wafw00f <TARGET>

# Enum web server + version + OS + frameworks + libraries
whatweb --aggression 3 http://<TARGET> --log-brief=whatweb_scan.txt

# Fingerprint web server
nikto -o nikto_fingerprint_scan.txt -Tuning b -h http://<TARGET>

# Enum web server vulns
nikto -o nikto_vuln_scan.txt -h http://<TARGET>

# Enum web app logic & vulns
wapiti -f txt -o wapiti_scan.txt --url http://<TARGET>

# vHost Brute-force
gobuster --quiet --threads 64 --output gobuster_vhost_top5000 vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320 --domain <DOMAIN> -u "http://<IP_ADDR>"  # uses IP addr

# Webpage Crawler
pip3 install --break-system-packages scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip && unzip ReconSpider.zip
python3 ReconSpider.py <URL> && cat results.json
# !!! CHECK "results.json" !!!

---

# /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Directory brute-force with a common wordlist
gobuster dir --quiet --threads 64 --output gobuster_dir_common --follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --url http://<TARGET>

# w/ file extensions
gobuster dir --quiet --threads 64 --output gobuster_dir_medium ---follow-redirect --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --extensions php,html,txt,bak,zip --url http://<TARGET>

### FEROXBUSTER: faster and recursive
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 2 -o feroxbuster_dir_common --scan-dir-listings -u http://<TARGET>

---

# AUTOMATED Recon
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
chmod +x ./finalrecon.py
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
./finalrecon.py -nb -r -cd final_recon_scan -w /usr/share/wordlists/dirb/common.txt --headers --crawl --ps --dns --sub --dir --url http://<URL>
```


# TODO: cull down AI slop below

## URL Encoding

Do not waste time looking up hex tables manually. Let your CLI do the work.

```bash
# 1. Curl Auto-Encoding (GET Requests)
# -G converts --data into a GET query string. --data-urlencode handles the special chars.
curl -G -i "http://<TARGET>/cgi/welcome.bat" --data-urlencode "cmd=C:\windows\system32\whoami.exe & id"

# 2. Python One-Liner (For generating payloads for Burp/Browser)
python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" 'cat /etc/passwd & id'

# 3. The "Slicker Way" (Add this to your ~/.zshrc or ~/.bashrc)
alias urlencode='python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))"'
# Usage: urlencode "payload&goes=here"
```

URL Encoding (Percent-Encoding) is not an obfuscation technique; it is a mechanical requirement of the HTTP protocol. You must encode characters to stop the Web Server from confusing your **Payload Data** with **HTTP Syntax**.

| Character | HTTP Syntax Meaning | Why it breaks exploits if unencoded |
| :--- | :--- | :--- |
| **`&`** | Parameter Separator | Server splits your payload. `?cmd=id & whoami` becomes Param 1: `cmd=id`, Param 2: `whoami`. |
| **`#`** | URL Fragment | Browser stops sending data after `#`. The backend never sees it. |
| **`+`** / **` `** | Space | Raw spaces break the HTTP header structure (`GET /page HTTP/1.1`). |
| **`?`** | Query String Start | Truncates or confuses path traversal payloads. |

**The CGI / Command Injection Rule:** 
When exploiting CGI scripts (`.sh`, `.bat`, `.cgi`), the web server unwraps the URL and hands the raw string directly to the OS shell (`/bin/bash` or `cmd.exe`). If you do not URL-encode your shell operators (`&`, `|`, `;`), the web server strips them out during the HTTP parsing phase, and the OS shell never executes them.

*   **Double Encoding (WAF Bypass):** If a WAF blocks `%5C` (`\`), encode the `%` symbol itself (`%` = `%25`). The payload becomes `%255C`. The WAF sees `%255C` (Allowed), passes it to the backend, which decodes it once to `%5C`, and the application decodes it again to `\`.
*   **Space Variants:** 
    *   In the **URL Path** (`GET /path%20here`), use `%20`.
    *   In the **Query String / Body** (`?cmd=id+whoami`), `+` is historically interpreted as a space (`application/x-www-form-urlencoded`), but `%20` is universally safer to avoid parsing desyncs. Default to `%20`.
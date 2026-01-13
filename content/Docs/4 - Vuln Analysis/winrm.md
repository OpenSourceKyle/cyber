+++
title = "🔌 Win: WinRM"
+++

- `TCP 5985/5986`: via HTTP/HTTPS respectively

```bash
# Enum via nmap
sudo nmap --disable-arp-ping -n -Pn -sV -sC -p5985,5986 <TARGET>

# Connect via WinRM
# https://github.com/Hackplayers/evil-winrm
evil-winrm -u <USER> -p <PASSWORD> -i <HOST>
evil-winrm -u <USER> -H <PASS_HASH> -i <HOST>
```

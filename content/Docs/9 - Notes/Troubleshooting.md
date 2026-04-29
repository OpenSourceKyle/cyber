+++
title = "Troubleshooting & Snippets"
+++

Random fixes, one-liners, and useful commands for lab machines and general fuckery.

## Fix Go

When system Go is broken or missing (HTB / online lab VMs)...

```bash
go: github.com/hahwul/dalfox/v2@latest (in github.com/hahwul/dalfox/v2@v2.12.0): go.mod:3: invalid go version '1.23.0': must match format 1.23
```

...Install a local Go and wire it into `PATH`:

```bash
wget https://go.dev/dl/go1.23.6.linux-amd64.tar.gz
mkdir -p ~/go_bin
tar -C ~/go_bin -xzf go1.23.6.linux-amd64.tar.gz
export PATH=$HOME/go_bin/go/bin:$HOME/go/bin/:$PATH
echo -e '\nexport PATH=$HOME/go_bin/go/bin:$HOME/go/bin/:$PATH' | tee -a ~/.bashrc ~/.zshrc
go version
```

## DNS Server Reconfig

```bash
sudo rm -f /etc/resolv.conf && \
echo -e "nameserver <DNS_SERVER>" | sudo tee /etc/resolv.conf && \
sudo chattr +i /etc/resolv.conf

dig +short <TARGET>
```

+++
title = "Troubleshooting & Snippets"
+++

Random fixes, one-liners, and useful commands for lab machines and general fuckery.

## Fix Go

When system Go is broken or missing (HTB / online lab VMs), install a local Go and wire it into `PATH`:

```bash
wget https://go.dev/dl/go1.23.6.linux-amd64.tar.gz
mkdir -p ~/go_bin
tar -C ~/go_bin -xzf go1.23.6.linux-amd64.tar.gz
export PATH=$HOME/go_bin/go/bin:$HOME/go/bin/:$PATH
echo 'export PATH=$HOME/go_bin/go/bin:$HOME/go/bin/:$PATH' | tee -a ~/.bashrc ~/.zshrc
go version
```

## DNS Server Reconfig

```bash
sudo rm -f /etc/resolv.conf && \
echo -e "nameserver <DNS_SERVER>" | sudo tee /etc/resolv.conf && \
sudo chattr +i /etc/resolv.conf

dig +short <TARGET>
```

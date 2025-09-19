#!/bin/bash
set -e

### FULL SYSTEM UPDATE/UPGRADE
export DEBIAN_FRONTEND=noninteractive
echo "[i] Updating package lists..."
until sudo apt-get update; do
  echo "APT update failed, retrying in 5 seconds..."
  sleep 5
done

### INSTALL MAIN PACKAGES
echo "[i] Installing packages..."
sudo apt-get -y --no-install-recommends install \
  kali-desktop-xfce \
  qemu-guest-agent \
  spice-vdagent \
  xserver-xorg-video-qxl \
  lightdm \
  gedit \
  curl \
  seclists \
  python2 \
  sshpass \
  rlwrap

### INSTALL DOCKER
# https://www.kali.org/docs/containers/installing-docker-on-kali/
sudo apt install -y docker.io
sudo systemctl enable docker --nowA
sudo usermod -aG docker $USER

### INSTALL ZELLIJ (TMUX ALTERNATIVE)
curl -L https://github.com/zellij-org/zellij/releases/latest/download/zellij-x86_64-unknown-linux-musl.tar.gz -o zellij.tar.gz
tar -xvf zellij.tar.gz
sudo mv zellij /usr/local/bin/
rm -f zellij.tar.gz
zellij --version

### PYTHON2 VENV FOR OLD EXPLOITS
echo "[i] Setting up Python 2 virtual environment..."
# Install pip for Python 2
echo "  -> Installing pip for Python 2..."
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py
sudo python2 /tmp/get-pip.py > /dev/null 2>&1
rm /tmp/get-pip.py
# Upgrade core Python 2 packages
echo "  -> Upgrading pip and setuptools..."
sudo python2 -m pip install --upgrade pip setuptools > /dev/null 2>&1
# Install virtualenv
echo "  -> Installing virtualenv..."
sudo python2 -m pip install virtualenv > /dev/null 2>&1
python2 -m virtualenv $HOME/py2-env

### CONFIGURE AUTOLOGIN
echo "[i] Configuring LightDM for autologin..."
sudo mkdir -p /etc/lightdm/lightdm.conf.d
sudo bash -c 'cat >/etc/lightdm/lightdm.conf.d/20-autologin.conf <<EOF
[Seat:*]
autologin-user=vagrant
autologin-session=xfce
EOF'

### DISABLE SCREENSAVER AND LOCK SCREEN
# Define the target configuration directory for the vagrant user
XFCE_CONFIG_DIR="/home/vagrant/.config/xfce4/xfconf/xfce-perchannel-xml"
sudo mkdir -p "$XFCE_CONFIG_DIR"
# Configure XFCE Power Manager to disable screen blanking, DPMS, and locking
sudo bash -c "cat > '$XFCE_CONFIG_DIR/xfce4-power-manager.xml' <<EOF
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<channel name=\"xfce4-power-manager\" version=\"1.0\">
  <property name=\"xfce4-power-manager\" type=\"empty\">
    <property name=\"presentation-mode\" type=\"bool\" value=\"true\"/>
    <property name=\"dpms-enabled\" type=\"bool\" value=\"false\"/>
    <property name=\"blank-on-ac\" type=\"int\" value=\"0\"/>
    <property name=\"lock-screen-suspend-hibernate\" type=\"bool\" value=\"false\"/>
  </property>
</channel>
EOF"
# Configure the XFCE session to have an empty lock command
sudo bash -c "cat > '$XFCE_CONFIG_DIR/xfce4-session.xml' <<EOF
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<channel name=\"xfce4-session\" version=\"1.0\">
  <property name=\"general\" type=\"empty\">
    <property name=\"LockCommand\" type=\"string\" value=\"\"/>
  </property>
</channel>
EOF"
# Ensure the vagrant user owns all their configuration files, which is critical
sudo chown -R vagrant:vagrant /home/vagrant/.config
# Enabling SPICE vdagent for guest display auto-resizing
sudo bash -c "cat > /etc/xdg/autostart/spice-vdagent.desktop <<EOF
[Desktop Entry]
Name=SPICE VDAgent
Comment=SPICE guest agent for desktop integration
Exec=spice-vdagent
Terminal=false
Type=Application
X-GNOME-Autostart-enabled=true
EOF"
echo "[i] Removing light-locker package as a fallback..."
sudo apt-get remove -y light-locker || true

### ZSH CUSTOMIZATIONS
echo "[i] Appending custom Zsh configuration..."
ZSH_CUSTOMIZATIONS_FILE="/tmp/zsh_customizations.zshrc"
if [ -f "$ZSH_CUSTOMIZATIONS_FILE" ]; then
  cat "$ZSH_CUSTOMIZATIONS_FILE" >> /home/vagrant/.zshrc
  sudo chown vagrant:vagrant /home/vagrant/.zshrc
  echo "  -> Successfully appended zsh_customizations.zshrc."
else
  echo "  -> WARNING: zsh_customizations.zshrc not found. Skipping."
fi

### Extras
{
# Extract Rockyou passwords
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
# Update searchsploit
sudo searchsploit --update
# Metasploit DB
sudo systemctl enable --now postgresql
sudo msfdb init
} || true

### Cleanup
echo "[i] Cleaning up packages..."
sudo apt-get autoremove -y
sudo apt-get clean

echo "[✓] Provisioning complete. System will boot straight to XFCE with no screensaver or lock screen."

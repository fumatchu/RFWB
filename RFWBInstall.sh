#!/bin/bash
#Bootstrap to GIT REPO
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')

# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "${GREEN}Running as root user.${RESET}"
else
  echo -e "${RED}This program must be run as root.${RESET}"
  echo "Exiting..."
  exit 1
fi

# Extract the major OS version from /etc/redhat-release
if [ -f /etc/redhat-release ]; then
  MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
else
  echo -e "${RED}/etc/redhat-release file not found. Cannot determine OS version.${RESET}"
  echo "Exiting the installer..."
  exit 1
fi

# Checking for version information
if [ "$MAJOROS" -ge 9 ]; then
  echo -e "${GREEN}Detected compatible OS version: Rocky 9.x or greater${RESET}"
else
  echo -e "${RED}Sorry, but this installer only works on Rocky 9.X or greater${RESET}"
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${RESET} or later"
  echo "Exiting the installer..."
  exit 1
fi


cat <<EOF
${GREEN}**************************
Please wait while we gather some files
**************************${TEXTRESET}


${YELLOW}Installing wget and git${TEXTRESET}
EOF
sleep 1

dnf -y install wget git dialog

cat <<EOF
${YELLOW}*****************************
Retrieving Files from GitHub
*****************************${TEXTRESET}
EOF

sleep 1
#Clone RFWB
mkdir /root/RFWB

git clone https://github.com/fumatchu/RFWB.git /root/RFWB

chmod 700 /root/RFWB/*


clear
echo ${RED}"Removing Git${TEXTRESET}"
dnf -y remove git
clear
cat <<EOF
 *********************************************

 This script was created for ${GREEN}Rocky 9.x${TEXTRESET}
 This will install 
 1. The Rocky Firewall Builder based on nftables
 
 What this script does:
 1. Validates and upgrades the system
 2. Sets internal Interfaces with zones and (vlans)
 3. Configures and locks down external interface with user preferences
 4. Provides a set of applications that can be installed:
     -Bind
     -ISC-KEA
     -Webmin
     -Cockpit
     -DDNS Client 
     -Suricata (Standalone)
     -Suricata with Elastic/Kibana/Filebeat for events and alerts
     -ntop-ng

 *********************************************
 

EOF

read -p "Press Any Key to Continue"

items=(1 "Install RFWB Setup"
)

while choice=$(dialog --title "$TITLE" \
  --backtitle "RFWB Installer" \
  --menu "Please select the install type" 15 65 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
  1) /root/RFWB/rfwb_install.sh ;;
  esac
done
clear # clear after user pressed Cancel

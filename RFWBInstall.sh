#!/bin/bash
#DC-Installer.sh #Bootstrap to GIT REPO
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')

#Checking for user permissions
if [ "$USER" = "root" ]; then
  echo " "
else
  echo ${RED}"This program must be run as root ${TEXTRESET}"
  echo "Exiting"
fi
#Checking for version Information
if [ "$MAJOROS" = "9" ]; then
  echo " "
else
  echo ${RED}"Sorry, but this installer only works on Rocky 9.X ${TEXTRESET}"
  echo "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET}"
  echo "Exiting the installer..."
  exit
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
cat <<EOF
 *********************************************

 This script was created for ${GREEN}Rocky 9.x${TEXTRESET}
 This will install 
 1. The Rocky Firewall Builder based on firewalld
 
 What this script does:
 1. Nothing yet

 *********************************************
 

EOF

read -p "Press Any Key to Continue"

items=(1 "Install RFWB Setup"
)

while choice=$(dialog --title "$TITLE" \
  --backtitle "Server Installer" \
  --menu "Please select the install type" 15 65 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
  1) /root/RFWB/install.sh ;;
  esac
done
clear # clear after user pressed Cancel

#!/bin/bash
#Bootstrap to GIT REPO
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
clear
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rocky FirewallBuilder Bootstrap"
# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user."
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Exiting..."
  exit 1
fi

# Extract the major OS version from /etc/redhat-release
if [ -f /etc/redhat-release ]; then
  MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
else
  echo -e "[${RED}ERROR${TEXTRESET}] /etc/redhat-release file not found. Cannot determine OS version."
  echo "Exiting the installer..."
  exit 1
fi

# Checking for version information
if [ "$MAJOROS" -ge 9 ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected compatible OS version: Rocky 9.x or greater"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Sorry, but this installer only works on Rocky 9.X or greater"
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET} or later"
  echo "Exiting the installer..."
  exit 1
fi

echo -e "${CYAN}==>Retrieving requirements for the installer...${TEXTRESET}"

# Function to show an animated spinner
spinner() {
  local pid=$1
  local delay=0.1
  local spinstr='|/-\'

  while ps -p $pid > /dev/null; do
    for i in $(seq 0 3); do
      printf "\r[${YELLOW}INFO${TEXTRESET}] Installing... ${spinstr:$i:1}"
      sleep $delay
    done
  done
  printf "\r[${GREEN}SUCCESS${TEXTRESET}] Installation complete!  \n"
}

# Run dnf in the background
dnf -y install wget git ipcalc dialog >/dev/null 2>&1 &

# Get the PID of the last background process
dnf_pid=$!

# Start the spinner while waiting for dnf to complete
spinner $dnf_pid

echo -e "${CYAN}==>Retrieving files from Github...${TEXTRESET}"

sleep 1
#Clone RFWB
mkdir -p /root/RFWB

rm -rf /root/RFWB && git clone https://github.com/fumatchu/RFWB.git /root/RFWB

chmod 700 /root/RFWB/*

echo -e "[${YELLOW}INFO${TEXTRESET}] Removing Git"
dnf -y remove git >/dev/null 2>&1

 clear
  echo -e "${GREEN}
                               .*((((((((((((((((*
                         .(((((((((((((((((((((((((((/
                      ,((((((((((((((((((((((((((((((((((.
                    (((((((((((((((((((((((((((((((((((((((/
                  (((((((((((((((((((((((((((((((((((((((((((/
                .(((((((((((((((((((((((((((((((((((((((((((((
               ,((((((((((((((((((((((((((((((((((((((((((((((((.
               ((((((((((((((((((((((((((((((/   ,(((((((((((((((
              /((((((((((((((((((((((((((((.        /((((((((((((*
              ((((((((((((((((((((((((((/              ((((((((((
              ((((((((((((((((((((((((                   *((((((/
              /((((((((((((((((((((*                        (((((*
               ((((((((((((((((((             (((*            ,((
               .((((((((((((((.            /(((((((
                 ((((((((((/             (((((((((((((/
                  *((((((.            /((((((((((((((((((.
                    *(*)            ,(((((((((((((((((((((((,
                                 (((((((((((((((((((((((/
                              /((((((((((((((((((((((.
                                ,((((((((((((((,
${RESET}"
  echo -e "                         ${GREEN}Rocky Linux${RESET} ${RED}Firewall${RESET} ${YELLOW}Builder${TEXTRESET}"

  sleep 2

echo " "
echo -e "Make sure you have at least ${YELLOW}two physical interfaces${TEXTRESET} (inside-outside) before proceeding
Also make sure you only have ONE interface connected all other interfaces should be disconnected
Install time is about 20 min"


read -p "Press Any Key to Continue"
PROFILE="/root/.bash_profile"
BACKUP="/root/.bash_profile.bak.$(date +%Y%m%d%H%M%S)"
INSTALLER="/root/RFWB/RFWB-main-install.sh"

cat << 'EOF' >> "$PROFILE"

## Run RFWB installer on every interactive login ##
if [[ $- == *i* ]]; then
  /root/RFWB/RFWB-main-install.sh
fi
EOF
if [[ -f "$INSTALLER" ]]; then
  chmod +x "$INSTALLER"
else
  echo "WARNING: Installer not found at $INSTALLER"
fi
/root/RFWB/RFWB-main-install.sh

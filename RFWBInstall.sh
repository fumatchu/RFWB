#!/bin/bash
#Bootstrap to GIT REPO
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
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

cat <<EOF

${GREEN}**************************${TEXTRESET}
Please wait while we gather some files
${GREEN}**************************${TEXTRESET}

EOF

echo -e "[${YELLOW}INFO${TEXTRESET}] Installing wget and git..."

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

cat <<EOF
${YELLOW}*****************************${TEXTRESET}
Retrieving Files from GitHub
${YELLOW}*****************************${TEXTRESET}
EOF

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
  echo -e "                         ${GREEN}Rocky Linux${RESET} ${RED}Firewall${RESET} ${YELLOW}Builder${RESET}"

  sleep 2

cat <<EOF
Make sure you have at least two interfaces (inside-outside) before proceeding
Install time is about 20 min 
EOF

read -p "Press Any Key to Continue"
/root/RFWB/RFWB-Main-install.sh

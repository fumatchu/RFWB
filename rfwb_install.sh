#!/bin/bash
# Define color codes for formatting output
RESET="\033[0m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
USER=$(whoami)

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

clear
echo -e "${GREEN}
                               .*((((((((((((((((*
                         .(((((((((((((((((((((((((((/
                      ,((((((((((((((((((((((((((((((((((.
                    (((((((((((((((((((((((((((((((((((((((/
                  (((((((((((((((((((((((((((((((((((((((((((/
                .((((((((((((((((((((((((((((((((((((((((((((((
               ,((((((((((((((((((((((((((((((((((((((((((((((((.
               ((((((((((((((((((((((((((((((/   ,(((((((((((((((
              /((((((((((((((((((((((((((((.        /((((((((((((*
              ((((((((((((((((((((((((((/              (((((((((((
              ((((((((((((((((((((((((                   *(((((((/
              /((((((((((((((((((((*                        (((((*
               ((((((((((((((((((             (((*            ,((
               .((((((((((((((.            /((((((((
                 ((((((((((/             (((((((((((((/
                  *((((((.            /((((((((((((((((((.
                    *(*            ,(((((((((((((((((((((((,
                                 (((((((((((((((((((((((/
                              /((((((((((((((((((((((.
                                ,((((((((((((((,
${RESET}"
echo -e ${GREEN}Rocky Linux${RESET} ${RED}Firewall${RESET} ${YELLOW}Builder${RESET}

# Use echo to interpret colors correctly
echo -e "
This script can be used to create a SOHO firewall implementation on Rocky Linux with IPS/IDS and other network processes:
-BIND
-ISC-KEA (DHCP)
-Webmin
-Cockpit
-ntopng
-DDNS for DDNS registration
-Suricata (stand alone)
-Suricata with Elastic/Kibana/Filebeat for Dashboard analytics of Alerts and Events (2CPU 8GB of RAM)

The process of this program is the following:
#1-Make sure you have ${YELLOW}two HARDWARE/VIRTUAL interfaces${RESET} on your system that are detected by nmcli
#2-The ${YELLOW}FIRST, connected interface${RESET} will be designated as your inside interface (This interface you are probably SSH'd into)
Your Internet facing interface ${YELLOW}SHOULD BE UNPLUGGED${RESET} right now

We prep the inside interface then proceed to install the applications of your choice
All downloads and configuration will happen through the inside interface
After your applications have been installed and configured to listen on the inside interface, we will then configure the outside interface
This is when you will plug the outside (internet facing) interface into the external connection, Cable modem, etc that you want to use.
We will configure that outside interface and harden all communications on that outside interface.
After that, the system will prompt you to reboot and you will be ready to go!
"

read -p "Press Enter to start the installer"

#Update the system
dnf -y update 

#Configure the ZONE for the inside interface
# Ensure necessary commands are installed
if ! command -v nmcli &> /dev/null; then
  echo -e "${RED}nmcli is not installed. Please install it and try again.${TEXTRESET}"
  exit 1
fi

if ! systemctl is-active --quiet firewalld; then
  echo -e "${RED}firewalld is not running. Please start it and try again.${TEXTRESET}"
  exit 1
fi

# Get all active connections managed by NetworkManager
active_connection=$(nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active | grep ":802-3-ethernet:" | grep ":activated")

if [ -z "$active_connection" ]; then
  echo -e "${RED}No active ethernet connections found. Exiting...${TEXTRESET}"
  exit 1
fi

# Parse the active connection details
IFS=: read -r name device type state <<< "$active_connection"

echo -e "${GREEN}Active internal network connection found:${TEXTRESET} $device ($name)"

# Update the connection profile name to include '-inside'
new_profile_name="${name}-inside"
echo -e "${YELLOW}Updating connection profile name to: $new_profile_name${TEXTRESET}"
nmcli connection modify "$name" connection.id "$new_profile_name"
nmcli connection reload

# Display initial ASCII representation of the connection
echo -e "${GREEN}Initial Connection Diagram:${TEXTRESET}"
echo "  +-------------------+"
echo "  |  Internal Network |"
echo "  +-------------------+"
echo "           |"
echo "           |"
echo "       +--------+"
echo "       | $device |"
echo "       +--------+"
echo "           |"
echo "           |"
echo "       +---------+"
echo "       | Firewall |"
echo "       +---------+"
echo



# Ask user if they want to set this connection to the 'Internal' zone
echo -e "It's HIGHLY suggested this interface be in the Firewall zone \"internal\""
read -p "Do you want to set this connection to the 'Internal' zone in firewalld? (y/n): " user_confirm

selected_zone=""

if [[ "$user_confirm" == "y" ]]; then
  selected_zone="internal"
  echo -e "${GREEN}Setting $device to the 'internal' zone...${TEXTRESET}"
  firewall-cmd --zone=internal --change-interface="$device" --permanent
else
  echo -e "${YELLOW}Available firewalld zones:${TEXTRESET}"
  available_zones=$(firewall-cmd --get-zones)

  # List available zones
  for zone in $available_zones; do
    echo -e "${YELLOW}- $zone${TEXTRESET}"
  done

  # Ask user to choose a different zone
  read -p "Please enter the zone you would like to use for $device: " selected_zone

  # Apply the chosen zone
  if echo "$available_zones" | grep -qw "$selected_zone"; then
    echo -e "${GREEN}Setting $device to the '$selected_zone' zone...${TEXTRESET}"
    firewall-cmd --zone="$selected_zone" --change-interface="$device" --permanent
  else
    echo -e "${RED}Invalid zone selected. No changes were made.${TEXTRESET}"
    exit 1
  fi
fi

firewall-cmd --reload
systemctl restart NetworkManager

# Display current zone configuration for the interface
echo -e "${YELLOW}Current firewalld zone configuration for $device:${TEXTRESET}"
firewall-cmd --get-active-zones | grep -A1 "$device"

echo -e "${GREEN}Completed configuration of network zones.${TEXTRESET}"

# Display the updated ASCII representation of the connection with the zone applied
echo -e "${GREEN}Updated Connection Diagram with Zone Applied:${TEXTRESET}"
echo "  +-------------------+"
echo "  |  Internal Network |"
echo "  +-------------------+"
echo "           |"
echo "           |"
echo "   +-----------------+"
echo "   | $selected_zone Zone |"
echo "   +-----------------+"
echo "           |"
echo "           |"
echo "       +--------+"
echo "       | $device |"
echo "       +--------+"
echo "           |"
echo "           |"
echo "       +---------+"
echo "       | Firewall |"
echo "       +---------+"
echo
echo -e "${GREEN}The Inside interface has been configured.${TEXTRESET}"

cat <<EOF
Your inside interface can still be set to DHCP or if you have alrady statically assigend the interface, that's OK.
We will come back later and setup vlans, and routing if needed. For now we will use the inside interface to deploy applications
and update the system.
EOF

read -p "Press Enter to install applications and services"
/root/RFWB.pkg_installgui.sh

echo -e "Continue script"

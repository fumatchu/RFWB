#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

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

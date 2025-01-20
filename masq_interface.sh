#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Ensure firewalld is running
if ! systemctl is-active --quiet firewalld; then
  echo -e "${RED}Firewalld is not running. Please start it and try again.${TEXTRESET}"
  exit 1
fi

# Get active connections using nmcli
inside_interface=""
outside_interface=""

while IFS=: read -r name device; do
  if [[ $name == *"-inside" ]]; then
    inside_interface="$device"
  elif [[ $name == *"-outside" ]]; then
    outside_interface="$device"
  fi
done < <(nmcli -t -f NAME,DEVICE connection show --active)

# Validate that we have found both interfaces
if [ -z "$inside_interface" ] || [ -z "$outside_interface" ]; then
  echo -e "${RED}Could not determine both inside and outside interfaces. Exiting...${TEXTRESET}"
  exit 1
fi

echo -e "${GREEN}Inside interface: $inside_interface${TEXTRESET}"
echo -e "${GREEN}Outside interface: $outside_interface${TEXTRESET}"

# Construct the firewall commands
cmd1="firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o $outside_interface -j MASQUERADE"
cmd2="firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i $inside_interface -o $outside_interface -j ACCEPT"
cmd3="firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i $outside_interface -o $inside_interface -m state --state RE
LATED,ESTABLISHED -j ACCEPT"

# Present the commands to the user
echo -e "${YELLOW}The following commands will be executed:${TEXTRESET}"
echo -e "${GREEN}$cmd1${TEXTRESET}"
echo -e "${GREEN}$cmd2${TEXTRESET}"
echo -e "${GREEN}$cmd3${TEXTRESET}"

# Ask for user confirmation
read -p "Do you want to apply these changes? (y/n): " confirm

if [[ "$confirm" == "y" ]]; then
  # Apply the commands
  echo -e "${YELLOW}Applying changes...${TEXTRESET}"
  eval $cmd1
  eval $cmd2
  eval $cmd3
  echo -e "${GREEN}Changes applied successfully.${TEXTRESET}"
else
  echo -e "${RED}No changes were made.${TEXTRESET}"
fi

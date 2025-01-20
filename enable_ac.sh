#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Ensure nmcli is installed
if ! command -v nmcli &> /dev/null; then
  echo -e "${RED}nmcli is not installed. Please install it and try again.${TEXTRESET}"
  exit 1
fi

# Get all connections managed by NetworkManager
connections=$(nmcli -t -f NAME,DEVICE,TYPE connection show)

# Display all interfaces that will be checked
echo -e "${YELLOW}Checking the following network interfaces for autoconnect settings:${TEXTRESET}"

while IFS=: read -r name device type; do
  # Only show valid ethernet or wifi connections
  if [ "$type" == "802-3-ethernet" ] || [ "$type" == "wifi" ]; then
    echo -e "${YELLOW}- $device ($name): Type $type${TEXTRESET}"
  fi
done <<< "$connections"

# Check and modify autoconnect settings
echo -e "\n${YELLOW}Modifying interfaces that are not set to autoconnect...${TEXTRESET}"

while IFS=: read -r name device type; do
  # Process valid ethernet or wifi connections
  if [ "$type" == "802-3-ethernet" ] || [ "$type" == "wifi" ]; then
    # Check if the connection is set to autoconnect
    autoconnect=$(nmcli -g connection.autoconnect connection show "$name")

    if [ "$autoconnect" != "yes" ]; then
      echo -e "${RED}Connection $name (Device: $device) is not set to autoconnect. Enabling autoconnect...${TEXTRESET}"
      nmcli connection modify "$name" connection.autoconnect yes

      if [ $? -eq 0 ]; then
        echo -e "${GREEN}Autoconnect enabled for $name (Device: $device).${TEXTRESET}"
      else
        echo -e "${RED}Failed to enable autoconnect for $name (Device: $device).${TEXTRESET}"
      fi
    else
      echo -e "${GREEN}Connection $name (Device: $device) is already set to autoconnect.${TEXTRESET}"
    fi
  fi
done <<< "$connections"

echo -e "${GREEN}Completed checking and updating autoconnect settings.${TEXTRESET}"

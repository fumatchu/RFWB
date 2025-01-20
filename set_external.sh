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

# Get currently connected interfaces
existing_connections=$(nmcli -t -f DEVICE,STATE dev status | grep ":connected" | cut -d: -f1)
echo -e "${YELLOW}Existing connected interfaces:${TEXTRESET}"
echo "$existing_connections"

echo -e "${YELLOW}Please plug in your Internet connection into the firewall. It should be in a separate subnet.${TEXTRESET}"
echo -e "${YELLOW}Waiting for a new interface to come up...${TEXTRESET}"

# Monitor for a new connection
while true; do
  # Get current connected devices
  current_connections=$(nmcli -t -f DEVICE,STATE dev status | grep ":connected" | cut -d: -f1)

  # Find the new connection, excluding 'lo'
  new_connection=$(comm -13 <(echo "$existing_connections" | sort) <(echo "$current_connections" | sort) | grep -v "^lo$")

  if [ -n "$new_connection" ]; then
    echo -e "${GREEN}Detected a new connection: $new_connection${TEXTRESET}"

    # Get the current profile name associated with the new connection
    current_profile=$(nmcli -t -f NAME,DEVICE connection show --active | grep ":${new_connection}$" | cut -d: -f1)

    if [ -n "$current_profile" ]; then
      # Update the connection profile name to include '-outside'
      new_profile_name="${new_connection}-outside"
      echo -e "${YELLOW}Updating connection profile name to: $new_profile_name${TEXTRESET}"
      nmcli connection modify "$current_profile" connection.id "$new_profile_name"
      nmcli connection reload
    else
      echo -e "${RED}Error: Could not find an active profile for $new_connection.${TEXTRESET}"
    fi

    # Ask the user about applying the 'drop' zone
    read -p "We suggest applying the 'drop' zone to this interface. Is this acceptable? (y/n): " user_confirm

    if [[ "$user_confirm" == "y" ]]; then
      echo -e "${GREEN}You have chosen to apply the 'drop' zone.${TEXTRESET}"
      # Note: The zone is not actually applied in this version.
    else
      echo -e "${YELLOW}Available firewalld zones:${TEXTRESET}"
      available_zones=$(firewall-cmd --get-zones)

      # List available zones
      for zone in $available_zones; do
        echo -e "${YELLOW}- $zone${TEXTRESET}"
      done

      # Ask user to choose a different zone
      read -p "Please enter the zone you would like to use for $new_connection: " selected_zone

      # Validate the chosen zone
      if echo "$available_zones" | grep -qw "$selected_zone"; then
        echo -e "${GREEN}You have chosen the '$selected_zone' zone for $new_connection.${TEXTRESET}"
        # Note: The zone is not actually applied in this version.
      else
        echo -e "${RED}Invalid zone selected. No changes were made.${TEXTRESET}"
      fi
    fi
    break
  fi

  sleep 0.5  # Check every 0.5 seconds
done

# Display a graphical representation of the configured interfaces
echo -e "${GREEN}Connection Diagram:${TEXTRESET}"

# Get all active zones with associated interfaces
active_zones=$(firewall-cmd --get-active-zones)

while read -r zone; do
  if [[ -n "$zone" && "$zone" != "--" ]]; then
    # Read the interfaces line associated with the zone
    read -r interfaces_line

    # Extract interfaces from the line
    interfaces=$(echo "$interfaces_line" | awk '{for (i=2; i<=NF; i++) print $i}')

    for iface in $interfaces; do
      if [ -n "$iface" ]; then
        echo "  +-------------------+"
        echo "  |  $zone Network  |"
        echo "  +-------------------+"
        echo "           |"
        echo "           |"
        echo "       +--------+"
        echo "       | $iface |"
        echo "       +--------+"
        echo "           |"
        echo "           |"
        echo "       +---------+"
        echo "       | Firewall |"
        echo "       +---------+"
        echo
      fi
    done
  fi
done <<< "$active_zones"

echo -e "${GREEN}Completed configuration of network zones.${TEXTRESET}"

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

# Get the list of active interfaces managed by NetworkManager
active_interfaces=$(nmcli -t -f DEVICE,STATE device status | grep ":connected" | cut -d: -f1)

# Count the number of active interfaces
interface_count=$(echo "$active_interfaces" | wc -l)

# Check if there are at least two active interfaces
if [ "$interface_count" -lt 2 ]; then
  echo -e "${RED}Less than two active interfaces found. Exiting...${TEXTRESET}"
  exit 1
fi

# Get the first two active interfaces
interfaces=($(echo "$active_interfaces" | head -n 2))

echo -e "${GREEN}Found active interfaces: ${interfaces[0]} and ${interfaces[1]}${TEXTRESET}"

# Determine the zones for each interface by parsing the output of `firewall-cmd --list-all-zones`
zones=()
while IFS= read -r line; do
  if [[ $line =~ ^([a-zA-Z0-9_-]+) ]]; then
    current_zone="${BASH_REMATCH[1]}"
  fi

  if [[ $line == *"interfaces: "* ]]; then
    for interface in "${interfaces[@]}"; do
      if [[ $line == *" $interface"* ]]; then
        zones+=("$current_zone")
      fi
    done
  fi
done < <(firewall-cmd --list-all-zones)

# Validate we have found zones for both interfaces
if [ "${#zones[@]}" -ne 2 ]; then
  echo -e "${RED}Could not determine zones for both interfaces. Exiting...${TEXTRESET}"
  exit 1
fi

echo -e "${GREEN}Zones associated with interfaces: ${interfaces[0]} is in zone ${zones[0]}, ${interfaces[1]} is in zone ${zones[1]}${TE
XTRESET}"

# Enable masquerade for each zone
for zone in "${zones[@]}"; do
  echo -e "${YELLOW}Enabling masquerade for zone $zone...${TEXTRESET}"
  if firewall-cmd --permanent --zone="$zone" --add-masquerade; then
    echo -e "${GREEN}Masquerade enabled for zone $zone.${TEXTRESET}"
  else
    echo -e "${RED}Failed to enable masquerade for zone $zone.${TEXTRESET}"
    exit 1
  fi
done

# Reload firewall to apply changes
firewall-cmd --reload

# Validate masquerade configuration for each zone
for zone in "${zones[@]}"; do
  echo -e "${YELLOW}Validating masquerade for zone $zone...${TEXTRESET}"
  if firewall-cmd --zone="$zone" --query-masquerade; then
    echo -e "${GREEN}Masquerade is enabled for zone $zone.${TEXTRESET}"
  else
    echo -e "${RED}Masquerade is NOT enabled for zone $zone.${TEXTRESET}"
  fi
done

# Check if IP forwarding is enabled
ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$ip_forward" -ne 1 ]; then
  echo -e "${RED}IP forwarding is not enabled. Please enable it by running 'echo 1 > /proc/sys/net/ipv4/ip_forward' and try again.${TEX
TRESET}"
  exit 1
else
  echo -e "${GREEN}IP forwarding is enabled.${TEXTRESET}"
fi

echo -e "${GREEN}Completed masquerade configuration for zones.${TEXTRESET}"

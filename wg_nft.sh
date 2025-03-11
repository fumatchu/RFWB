#!/bin/bash
#This adds POST UP and POST DOWN for Wireguard to nftables 

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
TEXTRESET='\033[0m'

# Function to find the network interface based on connection name ending
find_interface() {
  local suffix="$1"
  nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Function to find sub-interfaces based on main interface
find_sub_interfaces() {
  local main_interface="$1"
  nmcli -t -f DEVICE device status | grep -E "^${main_interface}\.[0-9]+" | awk '{print $1}'
}

# Find inside and outside interfaces
INSIDE_INTERFACE=$(find_interface "-inside")
OUTSIDE_INTERFACE=$(find_interface "-outside")

echo -e "${GREEN}Inside interface:${TEXTRESET} $INSIDE_INTERFACE"
echo -e "${GREEN}Outside interface:${TEXTRESET} $OUTSIDE_INTERFACE"

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# Combine main and sub-interfaces into an array
interfaces=("$INSIDE_INTERFACE" $SUB_INTERFACES)

# Check if there are any interfaces
if [[ -z "$INSIDE_INTERFACE" ]]; then
  echo -e "${RED}Error: No inside interface found.${TEXTRESET}"
  exit 1
fi

# Prompt user for WireGuard port number with a default suggestion
read -rp "Enter the WireGuard port number [51820]: " wg_port
wg_port=${wg_port:-51820} # Use 51820 if no input is provided

wg_conf="/etc/wireguard/wg0.conf" # WireGuard config path
selected_interfaces=() # Array to store selected interfaces

while [[ ${#interfaces[@]} -gt 0 ]]; do
  echo -e "${GREEN}Select an interface to forward to wg0 (or type '0' to finish):${TEXTRESET}"
  for ((i=0; i<${#interfaces[@]}; i++)); do
    echo "$((i+1)). ${interfaces[i]}"
  done
  echo "0. Exit interface selection"

  read -r -p "Enter the number of the interface or '0': " choice

  if [[ "$choice" == "0" ]]; then
    break
  elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#interfaces[@]} ]]; then
    index=$((choice-1))
    selected_interface="${interfaces[index]}"
    selected_interfaces+=("$selected_interface")
    # Remove the selected interface from the list
    interfaces=("${interfaces[@]:0:$index}" "${interfaces[@]:$((index+1))}")
    echo -e "${YELLOW}Selected interface: ${selected_interface}${TEXTRESET}"
  else
    echo -e "${RED}Invalid choice. Please enter a valid number.${TEXTRESET}"
  fi
done

if [[ ${#selected_interfaces[@]} -gt 0 ]]; then
  # Ensure the WireGuard config file exists
  if [[ ! -f "$wg_conf" ]]; then
    echo -e "${RED}Error: WireGuard config file $wg_conf not found.${TEXTRESET}"
    exit 1
  fi

  # Generate PostUp commands
  post_up_commands=""
  for interface_to_forward in "${selected_interfaces[@]}"; do
    post_up_commands+="nft add rule inet filter forward iif ${interface_to_forward} oif %i accept; "
    post_up_commands+="nft add rule inet filter forward iif %i oif ${interface_to_forward} accept; "
  done
  post_up_commands+="nft add rule inet nat postrouting oif ${OUTSIDE_INTERFACE} masquerade; "
  post_up_commands+="nft add rule inet nat postrouting oif %i masquerade; "
  post_up_commands+="nft add rule inet filter input iif %i udp dport ${wg_port} accept; "
  post_up_commands+="nft add rule inet filter input iif ${OUTSIDE_INTERFACE} udp dport ${wg_port} accept; "

  # Generate PostDown commands
  post_down_commands=""
  for interface_to_forward in "${selected_interfaces[@]}"; do
    post_down_commands+="nft delete rule inet filter forward iif ${interface_to_forward} oif %i; "
    post_down_commands+="nft delete rule inet filter forward iif %i oif ${interface_to_forward}; "
  done
  post_down_commands+="nft delete rule inet nat postrouting oif ${OUTSIDE_INTERFACE} masquerade; "
  post_down_commands+="nft delete rule inet nat postrouting oif %i masquerade; "
  post_down_commands+="nft delete rule inet filter input iif %i udp dport ${wg_port}; "
  post_down_commands+="nft delete rule inet filter input iif ${OUTSIDE_INTERFACE} udp dport ${wg_port}; "

  # Add PostUp and PostDown to wg0.conf
  sed -i "/\[Interface\]/a PostUp = ${post_up_commands}" "$wg_conf"
  sed -i "/\[Interface\]/a PostDown = ${post_down_commands}" "$wg_conf"
  echo -e "${GREEN}nftables rules added to ${wg_conf} for selected interfaces and port ${wg_port}.${TEXTRESET}"
else
  echo -e "${YELLOW}No interfaces selected.${TEXTRESET}"
fi

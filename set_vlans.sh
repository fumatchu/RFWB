#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to validate IP address format and ensure it's not a network or broadcast address
function validate_ip() {
  local ip="$1"
  local cidr_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
  if [[ $ip =~ $cidr_regex ]]; then
    # Split IP and CIDR parts
    local ip_part="${ip%/*}"
    local cidr_part="${ip#*/}"
    # Validate each octet is between 0-255 and CIDR is between 0-32
    IFS='.' read -r -a octets <<< "$ip_part"
    if [[ ${octets[0]} -le 255 && ${octets[1]} -le 255 && ${octets[2]} -le 255 && ${octets[3]} -le 255 && $cidr_part -le 32 ]]; then
      # Calculate network and broadcast addresses
      local mask=$(( 0xFFFFFFFF << (32 - cidr_part) & 0xFFFFFFFF ))
      local ip_num=$(( (${octets[0]} << 24) + (${octets[1]} << 16) + (${octets[2]} << 8) + ${octets[3]} ))
      local network=$(( ip_num & mask ))
      local broadcast=$(( network | ~mask & 0xFFFFFFFF ))
      if [[ $ip_num -ne $network && $ip_num -ne $broadcast ]]; then
        return 0
      fi
    fi
  fi
  return 1
}

# Function to display a graphical representation of mapped VLANs
function display_vlan_map() {
  echo -e "${GREEN}Existing VLAN Mappings:${TEXTRESET}"
  nmcli -t -f NAME,TYPE,DEVICE connection show --active | grep ":vlan:" | while IFS=: read -r con_name con_type con_iface; do
    vlan_id=$(nmcli connection show "$con_name" | grep "802-1Q.id:" | awk '{print $2}')
    ip_address=$(nmcli connection show "$con_name" | grep "ipv4.addresses:" | awk '{print $2}')
    zone=$(firewall-cmd --get-zone-of-interface="$con_iface")
    echo "  +-------------------+"
    echo "  |  Interface: $con_iface  |"
    echo "  |  VLAN ID: $vlan_id     |"
    echo "  |  IP: $ip_address  |"
    echo "  |  Zone: $zone  |"
    echo "  +-------------------+"
    echo
  done
}

# Start the VLAN configuration loop
while true; do
  # Display current VLAN mappings
  display_vlan_map

  # Prompt the user for VLAN usage
  read -p "Would you like to configure a VLAN? (y/n): " use_vlan

  if [[ "$use_vlan" == "y" ]]; then
    # List network interfaces with connection profile names
    echo -e "${YELLOW}Available network interfaces:${TEXTRESET}"
    interfaces=()
    index=1
    while IFS=: read -r profile device; do
      if [ -n "$device" ]; then
        interfaces+=("$device")
        echo "$index) $device ($profile)"
        ((index++))
      fi
    done < <(nmcli -t -f NAME,DEVICE connection show --active)

    # Prompt user to select an interface by number
    while true; do
      read -p "Please select an interface by number: " selected_number
      if [[ "$selected_number" =~ ^[0-9]+$ && "$selected_number" -ge 1 && "$selected_number" -le "${#interfaces[@]}" ]]; then
        selected_interface="${interfaces[$((selected_number - 1))]}"
        break
      else
        echo -e "${RED}Invalid selection. Please enter a valid number corresponding to an interface.${TEXTRESET}"
      fi
    done

    # Prompt for VLAN ID
    while true; do
      read -p "Enter VLAN ID (1-4094): " vlan_id
      if [[ "$vlan_id" -ge 1 && "$vlan_id" -le 4094 ]]; then
        break
      else
        echo -e "${RED}Invalid VLAN ID. Please enter a number between 1 and 4094.${TEXTRESET}"
      fi
    done

    # Prompt for IP address and subnet
    while true; do
      read -p "Enter the IP address in CIDR format (e.g., 192.168.21.1/24): " ip_address
      if validate_ip "$ip_address"; then
        break
      else
        echo -e "${RED}Invalid IP address format or it's a network/broadcast address. Please enter a valid host IP in CIDR format.${TEXTRESET}"
      fi
    done

    # Review selections
    echo -e "${YELLOW}You have selected:${TEXTRESET}"
    echo -e "${GREEN}Interface: $selected_interface"
    echo "VLAN ID: $vlan_id"
    echo "IP Address: $ip_address${TEXTRESET}"

    # Confirm changes
    read -p "Would you like to apply these changes? (y/n): " apply_changes

    if [[ "$apply_changes" == "y" ]]; then
      # Apply VLAN and IP configuration
      vlan_connection="${selected_interface}.${vlan_id}"
      nmcli connection add type vlan con-name "$vlan_connection" dev "$selected_interface" id "$vlan_id" ip4 "$ip_address"
      nmcli connection up "$vlan_connection"
      echo -e "${GREEN}VLAN $vlan_id configured on $selected_interface with IP $ip_address.${TEXTRESET}"

      # Determine the current firewall zone of the selected interface
      current_zone=$(firewall-cmd --get-zone-of-interface="$selected_interface")
      echo -e "${YELLOW}Current firewall zone for $selected_interface is: $current_zone${TEXTRESET}"

      # Ask if the user wants to modify the firewall zone
      read -p "Do you want to modify the firewall zone for this VLAN? (y/n): " modify_zone

      if [[ "$modify_zone" == "y" ]]; then
        # List available zones
        zones=($(firewall-cmd --get-zones))
        echo -e "${YELLOW}Available firewall zones:${TEXTRESET}"
        for i in "${!zones[@]}"; do
          echo "$((i + 1))) ${zones[$i]}"
        done

        # Allow user to select a zone by number
        while true; do
          read -p "Select a firewall zone by number: " zone_number
          if [[ "$zone_number" =~ ^[0-9]+$ && "$zone_number" -ge 1 && "$zone_number" -le "${#zones[@]}" ]]; then
            selected_zone="${zones[$((zone_number - 1))]}"
            break
          else
            echo -e "${RED}Invalid selection. Please enter a valid number corresponding to a zone.${TEXTRESET}"
          fi
        done
      else
        selected_zone="$current_zone"
      fi

      # Apply the selected zone to the VLAN interface
      vlan_interface="${selected_interface}.${vlan_id}"
      firewall-cmd --permanent --change-zone="$vlan_interface" --zone="$selected_zone"
      firewall-cmd --reload
      echo -e "${GREEN}Firewall zone $selected_zone applied to $vlan_interface.${TEXTRESET}"

    else
      echo -e "${YELLOW}Configuration cancelled by user.${TEXTRESET}"
    fi

    # Display updated VLAN mappings
    display_vlan_map

    # Ask if the user wants to add another VLAN
    read -p "Would you like to configure another VLAN? (y/n): " continue_vlan
    if [[ "$continue_vlan" != "y" ]]; then
      break
    fi
  else
    echo -e "${YELLOW}VLAN configuration not selected.${TEXTRESET}"
    break
  fi
done

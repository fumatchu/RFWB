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

    # Ask the user about applying the 'external' zone
    read -p "It's HIGHLY suggested applying the 'external' zone to this interface. Is this acceptable? (y/n): " user_confirm

    if [[ "$user_confirm" == "y" ]]; then
      echo -e "${GREEN}You have chosen to apply the 'external' zone.${TEXTRESET}"
      firewall-cmd --zone=external --change-interface="$new_connection" --permanent
      firewall-cmd --reload
      systemctl restart NetworkManager
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
        firewall-cmd --zone="$selected_zone" --change-interface="$new_connection" --permanent
        firewall-cmd --reload
        systemctl restart NetworkManager
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

# Variables to store interface and zone information
outside_iface=""
inside_iface=""
outside_zone=""
inside_zone=""

# Determine interfaces and zones
while read -r zone; do
  if [[ -n "$zone" && "$zone" != "--" ]]; then
    read -r interfaces_line
    interfaces=$(echo "$interfaces_line" | awk '{for (i=2; i<=NF; i++) print $i}')

    for iface in $interfaces; do
      if [ -n "$iface" ]; then
        profile_name=$(nmcli -t -f NAME,DEVICE connection show --active | grep ":${iface}$" | cut -d: -f1)

        if [[ "$profile_name" == *"-inside" ]]; then
          inside_iface="$iface"
          inside_zone="$zone"
        elif [[ "$profile_name" == *"-outside" ]]; then
          outside_iface="$iface"
          outside_zone="$zone"
        fi
      fi
    done
  fi
done <<< "$active_zones"

# Print the inverted ASCII diagram
if [ -n "$outside_iface" ] && [ -n "$inside_iface" ]; then
  echo "  +--------------------+"
  echo "  | Unprotected Network |"
  echo "  +--------------------+"
  echo "           |"
  echo "           |"
  echo "   +-----------------+"
  echo "   | $outside_zone Zone |"
  echo "   +-----------------+"
  echo "           |"
  echo "           |"
  echo "       +--------+"
  echo "       | $outside_iface |"
  echo "       +--------+"
  echo "           |"
  echo "           |"
  echo "       +---------+"
  echo "       | Firewall |"
  echo "       +---------+"
  echo "           |"
  echo "           |"
  echo "       +--------+"
  echo "       | $inside_iface |"
  echo "       +--------+"
  echo "           |"
  echo "           |"
  echo "   +-----------------+"
  echo "   | $inside_zone Zone |"
  echo "   +-----------------+"
  echo "           |"
  echo "           |"
  echo "  +--------------------+"
  echo "  | Protected Network |"
  echo "  +--------------------+"
  echo
fi

echo -e "${GREEN}Completed configuration of network zones.${TEXTRESET}"
# Set the default zone to 'drop' first
echo -e "${YELLOW}Changing the default zone to 'drop'...${TEXTRESET}"
firewall-cmd --set-default-zone=drop

# Validate the default zone has been changed
current_default_zone=$(firewall-cmd --get-default-zone)
if [ "$current_default_zone" == "drop" ]; then
  echo -e "${GREEN}Default zone successfully changed to 'drop'.${TEXTRESET}"
else
  echo -e "${RED}Failed to change the default zone to 'drop'. Current default zone: $current_default_zone${TEXTRESET}"
  exit 1
fi

firewall-cmd --reload
# Ask user if they want to apply outbound policy for internet connections
read -p "Do you want to apply the outbound policy for internet connectivity now? (y/n): " policy_confirm

if [[ "$policy_confirm" == "y" ]]; then
  echo -e "${GREEN}Applying outbound policy...${TEXTRESET}"

  # Apply the outbound policy
  firewall-cmd --new-policy=internal-external --permanent
  firewall-cmd --reload
  firewall-cmd --policy=internal-external --add-ingress-zone=internal --permanent
  firewall-cmd --policy=internal-external --add-egress-zone=external --permanent
  firewall-cmd --policy=internal-external --set-target=ACCEPT --permanent
  firewall-cmd --reload
  firewall-cmd --runtime-to-permanent

  # Restart firewalld service
  systemctl restart firewalld

  # Validate that firewalld is running
  if systemctl is-active --quiet firewalld; then
    echo -e "${GREEN}firewalld is running with the outbound policy applied.${TEXTRESET}"
  else
    echo -e "${RED}firewalld failed to start. Please check the configuration.${TEXTRESET}"
  fi
else
  echo -e "${YELLOW}Outbound policy not applied.${TEXTRESET}"
fi
#Lockdown the external interface by user service preference 
# Function to find the outside interface
find_outside_interface() {
    # Find the interface with a connection ending in -outside
    interface=$(nmcli device status | awk '/-outside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '-outside' found.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Function to find the zone associated with the interface
find_zone() {
    local interface="$1"
    # Get the active zones and find the one associated with the interface
    zone=$(sudo firewall-cmd --get-active-zones | awk -v iface="$interface" '
        {
            if ($1 != "" && $1 !~ /interfaces:/) { current_zone = $1 }
        }
        /^  interfaces:/ {
            if ($0 ~ iface) { print current_zone }
        }
    ')

    if [ -z "$zone" ]; then
        echo -e "${RED}Error: No zone associated with interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$zone"
}

# Function to list services for a given zone
list_services() {
    local zone="$1"
    echo -e "${YELLOW}Services open in zone '$zone':${TEXTRESET}"
    services=$(sudo firewall-cmd --zone="$zone" --list-services)

    if [ -z "$services" ]; then
        echo -e "${GREEN}No open services.${TEXTRESET}"
        return 1
    else
        echo "$services"
        return 0
    fi
}

# Function to remove a service from the zone
remove_service() {
    local zone="$1"
    while true; do
        list_services "$zone"
        if [ $? -ne 0 ]; then
            break
        fi

        echo -e "${YELLOW}Would you like to remove any of these services? (yes/no)${TEXTRESET}"
        read -r answer

        if [[ "$answer" =~ ^[Yy][Ee][Ss]$ || "$answer" =~ ^[Yy]$ ]]; then
            services=($(sudo firewall-cmd --zone="$zone" --list-services))
            echo -e "${YELLOW}Select a service to remove:${TEXTRESET}"

            for i in "${!services[@]}"; do
                echo "$i) ${services[$i]}"
            done

            read -p "Enter the number of the service to remove: " service_number

            if [[ "$service_number" =~ ^[0-9]+$ ]] && (( service_number >= 0 && service_number < ${#services[@]} )); then
                service_to_remove="${services[$service_number]}"
                sudo firewall-cmd --zone="$zone" --remove-service="$service_to_remove" --permanent
                sudo firewall-cmd --reload
                echo -e "${GREEN}Service '$service_to_remove' removed.${TEXTRESET}"
            else
                echo -e "${RED}Invalid selection.${TEXTRESET}"
            fi
        else
            break
        fi
    done
}

# Main execution block
outside_interface=$(find_outside_interface)
zone=$(find_zone "$outside_interface")
remove_service "$zone"
## disable icmp?
# Function to find the outside interface
find_outside_interface() {
    # Find the interface with a connection ending in -outside
    interface=$(nmcli device status | awk '/-outside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '-outside' found.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Function to find the zone associated with the interface
find_zone() {
    local interface="$1"
    # Get the active zones and find the one associated with the interface
    zone=$(sudo firewall-cmd --get-active-zones | awk -v iface="$interface" '
        {
            if ($1 != "" && $1 !~ /interfaces:/) { current_zone = $1 }
        }
        /^  interfaces:/ {
            if ($0 ~ iface) { print current_zone }
        }
    ')

    if [ -z "$zone" ]; then
        echo -e "${RED}Error: No zone associated with interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$zone"
}

# Function to disable ICMP in the specified zone
disable_icmp() {
    local zone="$1"
    echo -e "${YELLOW}Would you like to disable ICMP on the zone '$zone'? (yes/no)${TEXTRESET}"
    read -r answer

    if [[ "$answer" =~ ^[Yy][Ee][Ss]$ || "$answer" =~ ^[Yy]$ ]]; then
        sudo firewall-cmd --zone="$zone" --add-icmp-block=echo-request --permanent
        sudo firewall-cmd --reload
        echo -e "${GREEN}ICMP has been disabled on the zone '$zone'.${TEXTRESET}"
    else
        echo -e "${GREEN}ICMP remains enabled on the zone '$zone'.${TEXTRESET}"
    fi
}

# Main execution block
outside_interface=$(find_outside_interface)
zone=$(find_zone "$outside_interface")
disable_icmp "$zone"

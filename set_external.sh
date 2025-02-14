#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Ensure nmcli is installed
if ! command -v nmcli &> /dev/null; then
    echo -e "${RED}nmcli is not installed. Please install it and try again.${TEXTRESET}"
    exit 1
fi

# Ensure nftables is installed and running
if ! command -v nft &> /dev/null; then
    echo -e "${RED}nftables is not installed. Please install it and try again.${TEXTRESET}"
    exit 1
fi

if ! systemctl is-active --quiet nftables; then
    echo -e "${RED}nftables is not running. Please start it and try again.${TEXTRESET}"
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
        break
    fi

    sleep 0.5  # Check every 0.5 seconds
done

# Function to find the outside interface
find_outside_interface() {
    # Find the interface with a connection ending in -outside
    outside_interface=$(nmcli device status | awk '/-outside/ {print $1}')

    if [ -z "$outside_interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '-outside' found.${TEXTRESET}"
        exit 1
    fi

    echo "$outside_interface"
}


# Function to manage inside interfaces and remove gateway entries
manage_inside_interfaces() {
    # Find the main interface with a connection name ending in '-inside'
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$main_interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Main inside interface found: $main_interface${TEXTRESET}"

    # Get all connections and identify those associated with the inside interface
    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')

    if [ -z "$connection_names" ]; then
        echo -e "${RED}No connections found for interface: $main_interface and its sub-interfaces.${TEXTRESET}"
        exit 1
    fi

    # Loop through each connection and remove any gateway settings
    for connection_name in $connection_names; do
        echo -e "${GREEN}Processing connection: $connection_name${TEXTRESET}"
        # Remove the gateway for this connection
        nmcli connection modify "$connection_name" ipv4.gateway ""
        echo -e "${GREEN}Removed gateway for connection: $connection_name${TEXTRESET}"
    done
}

# Execute the function
manage_inside_interfaces

#!/bin/bash

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
TEXTRESET="\033[0m"

# Function to manage inside interfaces and update DNS settings
manage_inside_interfaces() {
    # Find the main interface with a connection name ending in '-inside'
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$main_interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Main inside interface found: $main_interface${TEXTRESET}"

    # Get all connections and identify those associated with the inside interface
    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')

    if [ -z "$connection_names" ]; then
        echo -e "${RED}No connections found for interface: $main_interface and its sub-interfaces.${TEXTRESET}"
        exit 1
    fi

    # Loop through each connection and update DNS settings
    for connection_name in $connection_names; do
        echo -e "${GREEN}Processing connection: $connection_name${TEXTRESET}"

        # Remove any existing DNS settings
        nmcli connection modify "$connection_name" ipv4.dns ""
        echo -e "${GREEN}Cleared existing DNS settings for connection: $connection_name${TEXTRESET}"

        # Add new DNS servers
        nmcli connection modify "$connection_name" ipv4.dns "127.0.0.1 208.67.222.222 208.67.220.220"
        echo -e "${GREEN}Set new DNS servers for connection: $connection_name${TEXTRESET}"
    done
}

# Execute the function
manage_inside_interfaces





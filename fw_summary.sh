#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to list active zones, their interfaces, open services, ports, and firewall policies
list_active_zones_and_policies() {
    echo -e "${YELLOW}Active Zones, Interfaces, Services, Ports, and Policies:${TEXTRESET}"

    # Get active zones and their interfaces
    active_zones_info=$(sudo firewall-cmd --get-active-zones)

    # Initialize variables
    current_zone=""
    interfaces=()

    # Parse active zones information
    while IFS= read -r line; do
        if [[ $line != "  interfaces:"* ]]; then
            if [[ -n $current_zone ]]; then
                # Print current zone, interfaces, services, and ports
                echo -e "${GREEN}Zone: $current_zone${TEXTRESET}"
                for iface in "${interfaces[@]}"; do
                    suffix=""
                    # Determine suffix based on interface naming
                    if [[ "$iface" == *"-inside" ]]; then
                        suffix=" (Inside)"
                    elif [[ "$iface" == *"-outside" ]]; then
                        suffix=" (Outside)"
                    fi
                    echo -e "  |-- Interface: $iface$suffix"
                done

                # Retrieve and display services
                services=$(sudo firewall-cmd --zone="$current_zone" --list-services)
                echo -e "  |-- Services: ${services:-None}"

                # Retrieve and display ports
                ports=$(sudo firewall-cmd --zone="$current_zone" --list-ports)
                echo -e "  |-- Ports: ${ports:-None}"
                echo ""
            fi
            # Start new zone entry
            current_zone=$line
            interfaces=()
        else
            # Extract interfaces
            iface_line=${line#"  interfaces: "}
            IFS=' ' read -r -a ifaces <<<"$iface_line"
            interfaces=("${ifaces[@]}")
        fi
    done <<<"$active_zones_info"

    # Print last zone and details
    if [[ -n $current_zone ]]; then
        echo -e "${GREEN}Zone: $current_zone${TEXTRESET}"
        for iface in "${interfaces[@]}"; do
            suffix=""
            # Determine suffix based on interface naming
            if [[ "$iface" == *"-inside" ]]; then
                suffix=" (Inside)"
            elif [[ "$iface" == *"-outside" ]]; then
                suffix=" (Outside)"
            fi
            echo -e "  |-- Interface: $iface$suffix"
        done

        # Retrieve and display services
        services=$(sudo firewall-cmd --zone="$current_zone" --list-services)
        echo -e "  |-- Services: ${services:-None}"

        # Retrieve and display ports
        ports=$(sudo firewall-cmd --zone="$current_zone" --list-ports)
        echo -e "  |-- Ports: ${ports:-None}"
        echo ""
    fi

    # List policies
    echo -e "${YELLOW}Active Policies:${TEXTRESET}"
    policies=$(sudo firewall-cmd --get-policies)

    if [ -z "$policies" ]; then
        echo -e "${YELLOW}No active policies found.${TEXTRESET}"
    else
        for policy in $policies; do
            echo -e "${GREEN}Policy: $policy${TEXTRESET}"
            policy_info=$(sudo firewall-cmd --info-policy="$policy")
            echo -e "$policy_info" | while IFS= read -r policy_line; do
                echo -e "  |-- $policy_line"
            done
            echo ""
        done
    fi
}

# Main execution block
list_active_zones_and_policies

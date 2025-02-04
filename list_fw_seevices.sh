#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to list active zones, their interfaces, open services, ports, masquerading status, and firewall policies
list_active_zones_and_policies() {
    echo -e "${YELLOW}Active Zones, Interfaces, Services, Ports, Masquerading, and Policies:${TEXTRESET}"

    # Get active zones and their interfaces
    active_zones_info=$(sudo firewall-cmd --get-active-zones)

    # Parse active zones information
    while IFS= read -r line; do
        if [[ ! $line =~ ^[[:space:]] ]]; then
            current_zone="$line"
            echo -e "${GREEN}Zone: $current_zone${TEXTRESET}"

            # Retrieve and display interfaces
            interfaces=$(sudo firewall-cmd --zone="$current_zone" --list-interfaces)
            if [[ -n "$interfaces" ]]; then
                for iface in $interfaces; do
                    suffix=""
                    # Determine suffix based on interface naming
                    if [[ "$iface" == *"-inside" ]]; then
                        suffix=" (Inside)"
                    elif [[ "$iface" == *"-outside" ]]; then
                        suffix=" (Outside)"
                    fi
                    echo -e "  |-- Interface: $iface$suffix"
                done
            else
                echo -e "  |-- Interfaces: None"
            fi

            # Retrieve and display services
            services=$(sudo firewall-cmd --zone="$current_zone" --list-services)
[root@firewall ~]# more test6
#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to list active zones, their interfaces, open services, ports, masquerading status, and firewall policies
list_active_zones_and_policies() {
    echo -e "${YELLOW}Active Zones, Interfaces, Services, Ports, Masquerading, and Policies:${TEXTRESET}"

    # Get active zones and their interfaces
    active_zones_info=$(sudo firewall-cmd --get-active-zones)

    # Parse active zones information
    while IFS= read -r line; do
        if [[ ! $line =~ ^[[:space:]] ]]; then
            current_zone="$line"
            echo -e "${GREEN}Zone: $current_zone${TEXTRESET}"

            # Retrieve and display interfaces
            interfaces=$(sudo firewall-cmd --zone="$current_zone" --list-interfaces)
            if [[ -n "$interfaces" ]]; then
                for iface in $interfaces; do
                    suffix=""
                    # Determine suffix based on interface naming
                    if [[ "$iface" == *"-inside" ]]; then
                        suffix=" (Inside)"
                    elif [[ "$iface" == *"-outside" ]]; then
                        suffix=" (Outside)"
                    fi
                    echo -e "  |-- Interface: $iface$suffix"
                done
            else
                echo -e "  |-- Interfaces: None"
            fi

            # Retrieve and display services
            services=$(sudo firewall-cmd --zone="$current_zone" --list-services)
            echo -e "  |-- Services: ${services:-None}"

            # Retrieve and display ports
            ports=$(sudo firewall-cmd --zone="$current_zone" --list-ports)
            echo -e "  |-- Ports: ${ports:-None}"

            # Check and display masquerading status
            masquerading=$(sudo firewall-cmd --zone="$current_zone" --query-masquerade)
            if $masquerading; then
                echo -e "  |-- Masquerading: Enabled"
            else
                echo -e "  |-- Masquerading: Disabled"
            fi
            echo ""
        fi
    done <<< "$active_zones_info"

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

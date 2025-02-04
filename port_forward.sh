#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to find the interface ending with a specific suffix
find_interface() {
    local suffix="$1"
    interface=$(nmcli device status | awk -v suffix="$suffix" '$0 ~ suffix {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '$suffix' found.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Function to find the zone associated with an interface
find_zone() {
    local interface="$1"
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

# Function to get the primary service name or port information
get_service_or_port_info() {
    local port="$1"
    local protocol="$2"
    local service_name=""
    local spinner="/-\|"

    # Start background search and spinner
    (
        # Priority list of common services
        local priority_services=("http" "https" "ftp" "ssh" "telnet" "smtp" "pop3" "imap" "dns")

        # Check priority services first
        for service in "${priority_services[@]}"; do
            if sudo firewall-cmd --info-service="$service" 2>/dev/null | grep -q "ports:.*\b$port/$protocol\b"; then
                service_name="$service"
                break
            fi
        done

        # If not found in priority list, check all services
        if [ -z "$service_name" ]; then
            service_name=$(sudo firewall-cmd --get-services | tr ' ' '\n' | while read -r service; do
                if sudo firewall-cmd --info-service="$service" 2>/dev/null | grep -q "ports:.*\b$port/$protocol\b"; then
                    echo "$service"
                    break
                fi
            done)
        fi
        echo "$service_name" > /tmp/service_name_result.txt
    ) &

    local search_pid=$!
    local delay=0.1
    local elapsed=0
    local timeout=2

    echo -ne "${YELLOW}Please wait while we attempt to find the service... ${TEXTRESET}"
    while kill -0 $search_pid 2>/dev/null; do
        printf "\b${spinner:elapsed%4:1}"
        elapsed=$((elapsed + 1))
        sleep $delay
    done
    wait $search_pid

    service_name=$(< /tmp/service_name_result.txt)

    if [ -n "$service_name" ]; then
        echo -e "\n${GREEN}Port $port/$protocol is associated with the '$service_name' protocol.${TEXTRESET}"
        return 0
    else
        echo -e "\n${RED}Port $port/$protocol is not associated with a known service.${TEXTRESET}"
        return 1
    fi
}

# Function to create a new service
create_new_service() {
    local port="$1"
    local protocol="$2"

    echo -e "${YELLOW}Enter the name for the new service:${TEXTRESET}"
    read -r service_name
    service_name=$(echo "$service_name" | tr '[:upper:]' '[:lower:]')

    echo -e "${YELLOW}Enter the description for the new service:${TEXTRESET}"
    read -r service_description

    sudo firewall-cmd --permanent --new-service="$service_name"
    sudo firewall-cmd --permanent --service="$service_name" --set-description="$service_description"
    sudo firewall-cmd --permanent --service="$service_name" --add-port="$port/$protocol"
    sudo firewall-cmd --reload

    echo -e "${GREEN}New service '$service_name' created with port $port/$protocol.${TEXTRESET}"
}

# Main execution block
outside_interface=$(find_interface "-outside")
inside_interface=$(find_interface "-inside")

outside_zone=$(find_zone "$outside_interface")
inside_zone=$(find_zone "$inside_interface")

echo -e "${YELLOW}Outside Interface: $outside_interface, Zone: $outside_zone${TEXTRESET}"
echo -e "${YELLOW}Inside Interface: $inside_interface, Zone: $inside_zone${TEXTRESET}"

# Ask the user if they want to set up port forwarding
echo -e "${YELLOW}Would you like to set up port forwarding? (yes/no)${TEXTRESET}"
read -r setup_forwarding

if [[ "$setup_forwarding" =~ ^[Yy][Ee][Ss]$ || "$setup_forwarding" =~ ^[Yy]$ ]]; then
    # Ask for the external port/service
    echo -e "${YELLOW}Enter the external port to open on the outside zone:${TEXTRESET}"
    read -r external_port

    echo -e "${YELLOW}Enter the protocol (tcp/udp) for the external port:${TEXTRESET}"
    read -r external_protocol
    external_protocol=$(echo "$external_protocol" | tr '[:upper:]' '[:lower:]')

    # Provide information about the entered port and protocol
    if ! get_service_or_port_info "$external_port" "$external_protocol"; then
        create_new_service "$external_port" "$external_protocol"
    fi

    # Ask for the internal port/service
    echo -e "${YELLOW}Enter the internal port to bind on the inside zone:${TEXTRESET}"
    read -r internal_port

    echo -e "${YELLOW}Enter the protocol (tcp/udp) for the internal port:${TEXTRESET}"
    read -r internal_protocol
    internal_protocol=$(echo "$internal_protocol" | tr '[:upper:]' '[:lower:]')

    # Provide information about the entered port and protocol
    if ! get_service_or_port_info "$internal_port" "$internal_protocol"; then
        create_new_service "$internal_port" "$internal_protocol"
    fi

    # Ask for the internal IP address
    echo -e "${YELLOW}Enter the IP address of the device hosting the service internally:${TEXTRESET}"
    read -r internal_ip

    # Set up port forwarding using firewall-cmd
    sudo firewall-cmd --zone="$outside_zone" --add-forward-port=port="$external_port":proto="$external_protocol":toaddr="$internal_ip":toport="$internal_port" --permanent
    sudo firewall-cmd --zone="$inside_zone" --add-forward-port=port="$internal_port":proto="$internal_protocol":toaddr="$internal_ip" --permanent
    sudo firewall-cmd --reload

    echo -e "${GREEN}Port forwarding set up successfully from $external_port/$external_protocol on $outside_zone to $internal_port/$internal_protocol on $inside_zone at $internal_ip.${TEXTRESET}"
else
    echo -e "${GREEN}No port forwarding configured.${TEXTRESET}"
fi

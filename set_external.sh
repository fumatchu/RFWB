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

# Function to set up nftables rules (SSH rule removed)
setup_nftables() {
    # Create a filter table if it doesn't exist
    if ! sudo nft list tables | grep -q 'inet filter'; then
        sudo nft add table inet filter
    fi

    # Create an input chain if it doesn't exist
    if ! sudo nft list chain inet filter input &>/dev/null; then
        sudo nft add chain inet filter input { type filter hook input priority 0 \; }
    fi

    # Display rules in a table format
    list_interfaces_and_ports
}

# Function to save the current nftables configuration
save_nftables_config() {
    sudo nft list ruleset > /etc/nftables.conf
    echo -e "${GREEN}Configuration saved to /etc/nftables.conf${TEXTRESET}"
}

# Function to prompt for additional ports
add_additional_ports() {
    while true; do
        read -p "Do you want to open additional ports on the outside interface? (yes/no): " answer
        if [[ "$answer" != "yes" ]]; then
            break
        fi

        read -p "Enter the port numbers (e.g., 80,82 or 80-89): " port_input
        read -p "Will all ports use the same protocol? (yes/no): " same_protocol

        if [[ "$same_protocol" == "yes" ]]; then
            protocol=""
            while [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; do
                read -p "Enter the protocol (tcp/udp): " protocol
                if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
                    echo -e "${RED}Invalid protocol. Please enter 'tcp' or 'udp'.${TEXTRESET}"
                fi
            done
        fi

        # Process each port or range of ports
        IFS=',' read -ra PORTS <<< "$port_input"
        for port in "${PORTS[@]}"; do
            if [[ $port == *"-"* ]]; then
                # Handle range of ports
                IFS='-' read start_port end_port <<< "$port"
                for (( p=start_port; p<=end_port; p++ )); do
                    if [[ $p -ge 0 && $p -le 65535 ]]; then
                        if [[ "$same_protocol" == "no" ]]; then
                            protocol=""
                            while [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; do
                                read -p "Enter the protocol for port $p (tcp/udp): " protocol
                                if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
                                    echo -e "${RED}Invalid protocol. Please enter 'tcp' or 'udp'.${TEXTRESET}"
                                fi
                            done
                        fi
                        add_nft_rule "$protocol" "$p"
                    else
                        echo -e "${RED}Invalid port number $p. Please enter a port between 0 and 65535.${TEXTRESET}"
                    fi
                done
            else
                # Handle single port
                if [[ $port -ge 0 && $port -le 65535 ]]; then
                    if [[ "$same_protocol" == "no" ]]; then
                        protocol=""
                        while [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; do
                            read -p "Enter the protocol for port $port (tcp/udp): " protocol
                            if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
                                echo -e "${RED}Invalid protocol. Please enter 'tcp' or 'udp'.${TEXTRESET}"
                            fi
                        done
                    fi
                    add_nft_rule "$protocol" "$port"
                else
                    echo -e "${RED}Invalid port number $port. Please enter a port between 0 and 65535.${TEXTRESET}"
                 fi
            fi
        done

        # Display updated rules in a table format
        list_interfaces_and_ports
    done
}

# Function to add a rule to nftables
add_nft_rule() {
    local protocol=$1
    local port=$2
    local outside_interface=$(find_outside_interface)

    if ! sudo nft list chain inet filter input | grep -q "iifname \"$outside_interface\" $protocol dport $port accept"; then
        sudo nft add rule inet filter input iifname "$outside_interface" $protocol dport $port accept
        echo -e "${GREEN}Rule added: Allow $protocol on port $port for interface $outside_interface${TEXTRESET}"
        save_nftables_config
    else
        echo -e "${YELLOW}Rule already exists: Allow $protocol on port $port for interface $outside_interface${TEXTRESET}"
    fi
}

# Function to list all interfaces and open ports in a table format
list_interfaces_and_ports() {
    echo -e "${YELLOW}Listing all network interfaces and open ports:${TEXTRESET}"
    echo "-------------------------------------------------------------"
    echo "| Interface             | Connection Name       | Ports      |"
    echo "-------------------------------------------------------------"

    # Get all interfaces and associated connection names
    nmcli device status | awk 'NR>1 {print $1}' | while read -r iface; do
        # Get the connection name associated with the interface
        connection_name=$(nmcli -t -f DEVICE,NAME connection show --active | grep "^$iface:" | cut -d':' -f2)
        if [ -z "$connection_name" ]; then
            connection_name="No active connection"
        fi

        # Extract open ports for the specified interface
        ports=$(sudo nft list chain inet filter input | grep "iifname \"$iface\"" | awk '{print $3, $5}' | sort -u)

        # Print the interface and connection name
        printf "| %-22s | %-20s |\n" "$iface" "$connection_name"

        if [ -z "$ports" ]; then
            echo "|                        |                      | No open ports"
        else
            echo "$ports" | while read -r protocol port; do
                printf "|                        |                      | %-10s |\n" "$protocol $port"
            done
         fi
    done

    # Close table
    echo "-------------------------------------------------------------"
}

# Main script execution
find_outside_interface
setup_nftables
add_additional_ports
list_interfaces_and_ports

# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    interface=$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '$suffix' found.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Find inside and outside interfaces
INSIDE_INTERFACE=$(find_interface "-inside")
OUTSIDE_INTERFACE=$(find_interface "-outside")

echo -e "${GREEN}Inside interface: $INSIDE_INTERFACE${TEXTRESET}"
echo -e "${GREEN}Outside interface: $OUTSIDE_INTERFACE${TEXTRESET}"

# Enable IP forwarding
echo -e "${YELLOW}Enabling IP forwarding...${TEXTRESET}"
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Apply nftables ruleset directly
echo -e "${YELLOW}Applying nftables ruleset...${TEXTRESET}"

# Create and configure the inet filter table
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; }
sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
sudo nft add rule inet filter forward ct state established,related accept
sudo nft add rule inet filter forward iif "$INSIDE_INTERFACE" oif "$OUTSIDE_INTERFACE" accept
sudo nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }

# Create and configure the ip nat table
sudo nft add table ip nat
sudo nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
sudo nft add rule ip nat postrouting oif "$OUTSIDE_INTERFACE" masquerade

# Log and block all incoming traffic on the outside interface
echo -e "${YELLOW}Logging and blocking all incoming traffic on the outside interface...${TEXTRESET}"
sudo nft add rule inet filter input iifname "$OUTSIDE_INTERFACE" log prefix "Dropped: " drop

echo -e "${GREEN}nftables ruleset applied successfully.${TEXTRESET}"
# Save the current ruleset
echo -e "${YELLOW}Saving the current nftables ruleset...${TEXTRESET}"
sudo nft list ruleset > /etc/sysconfig/nftables.conf

# Enable and start nftables service to ensure configuration is loaded on boot
echo -e "${YELLOW}Enabling nftables service...${TEXTRESET}"
sudo systemctl enable nftables
sudo systemctl start nftables

echo -e "${GREEN}nftables ruleset applied and saved successfully.${TEXTRESET}"

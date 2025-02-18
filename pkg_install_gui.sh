#!/bin/bash
# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
RESET='\033[0m'
#Function to install rfwb-portscan detection
install_portscan() {
# Script to set up nftables for detecting and blocking port scans on Red Hat systems
 clear
 echo -e "${GREEN}Installing RFWB-Portscan Detection engine...${TEXTRESET}"
 sleep 2
# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Install nftables if not already installed
if ! command -v nft &> /dev/null; then
    echo "Installing nftables..."
    yum install -y nftables
fi

# Ensure the hosts.blocked file exists
BLOCKED_FILE="/etc/nftables/hosts.blocked"
if [ ! -f "$BLOCKED_FILE" ]; then
    touch "$BLOCKED_FILE"
fi

# Ensure the ignore networks configuration file exists and populate with RFC 1918 networks
IGNORE_NETWORKS_FILE="/etc/nftables/ignore_networks.conf"
if [ ! -f "$IGNORE_NETWORKS_FILE" ]; then
    echo "Creating ignore networks configuration file with RFC 1918 networks."
    cat <<EOF > "$IGNORE_NETWORKS_FILE"
# Ignore file for rfwb-nft-portscan
# The port scan detection will ignore any ip addresses or networks placed into this file
# Network example
# 192.168.210.0/24
# Host example 192.168.210.10/32
# Entries must be one per line
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
EOF

    # Verify if the file was created and populated correctly
    if [ -f "$IGNORE_NETWORKS_FILE" ]; then
        echo "Ignore networks configuration file created successfully."
    else
        echo "Failed to create ignore networks configuration file."
        exit 1
    fi
else
    echo "Ignore networks configuration file already exists."
fi

# Verify file content
echo "Current contents of $IGNORE_NETWORKS_FILE:"
cat "$IGNORE_NETWORKS_FILE"

# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Determine the outside interface
OUTSIDE_INTERFACE=$(find_interface "-outside")

if [[ -z "$OUTSIDE_INTERFACE" ]]; then
    echo "Error: Could not determine the outside interface. Please check your connection names."
    exit 1
fi

# Determine the external IP address
EXTERNAL_IP=$(ip -4 addr show "$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
if [[ -z "$EXTERNAL_IP" ]]; then
    echo "Error: Could not determine the external IP address for interface $OUTSIDE_INTERFACE."
    exit 1
fi

echo "Protecting outside interface: $OUTSIDE_INTERFACE with IP: $EXTERNAL_IP"

# Load ignore networks from the configuration file
IGNORE_NETWORKS=$(cat "$IGNORE_NETWORKS_FILE")
echo "Using ignore networks: $IGNORE_NETWORKS"

# Prepare elements string for blocked IPs set if not empty
ELEMENTS=""
if [ -s "$BLOCKED_FILE" ]; then
    ELEMENTS=$(sed ':a;N;$!ba;s/\n/, /g' "$BLOCKED_FILE")
fi

# Create nftables configuration directory
NFT_CONF_DIR="/etc/nftables"
mkdir -p "$NFT_CONF_DIR"

# Create nftables configuration file
NFT_CONF_FILE="$NFT_CONF_DIR/portscan.conf"

# Clear the configuration file before writing new rules
cat <<EOL > "$NFT_CONF_FILE"
table inet portscan {
  set dynamic_block {
    type ipv4_addr
    flags timeout
    timeout 1h
EOL

# Only add elements if there are IPs
if [ -n "$ELEMENTS" ]; then
cat <<EOL >> "$NFT_CONF_FILE"
    elements = { $ELEMENTS }
EOL
fi

cat <<EOL >> "$NFT_CONF_FILE"
  }

  chain input {
    type filter hook input priority 0; policy accept;

    # Allow established and related connections
    ct state established,related accept

    # Drop packets from dynamically blocked IPs
    ip saddr @dynamic_block drop

    # Detect SYN packets from untrusted sources on the outside interface
    iifname $OUTSIDE_INTERFACE tcp flags syn limit rate 10/minute log prefix "Port Scan Detected: " counter
EOL

# Add rules for the external IP, including common service ports 1-1000
cat <<EOL >> "$NFT_CONF_FILE"
    ip daddr $EXTERNAL_IP tcp dport { 20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995 } ct
state new limit rate 3/minute log prefix "Port Scan Detected: " counter
EOL

cat <<EOL >> "$NFT_CONF_FILE"
  }
}
EOL

# Create a pre-start script to log the outside interface and IP
PRE_START_SCRIPT="/usr/local/bin/rfwb-portscan-prestart.sh"
cat <<'EOF' > "$PRE_START_SCRIPT"
#!/bin/bash

OUTSIDE_INTERFACE=$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="-outside" '$2 ~ suffix {print $1}')
EXTERNAL_IP=$(ip -4 addr show "$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

echo "Starting service: Protecting outside interface: $OUTSIDE_INTERFACE with IP: $EXTERNAL_IP"
EOF

# Make the pre-start script executable
chmod +x "$PRE_START_SCRIPT"

# Create a stop script to clean up nftables configuration
STOP_SCRIPT="/usr/local/bin/rfwb-portscan-stop.sh"
cat <<'EOF' > "$STOP_SCRIPT"
#!/bin/bash
echo "Flushing and removing dynamic block set, and resetting hosts.blocked file."

# Flush all rules in the input chain to remove references to the set
nft flush chain inet portscan input

# Delete the dynamic block set
nft delete set inet portscan dynamic_block

# Delete the table to remove all configurations
nft delete table inet portscan

# Reset the hosts.blocked file
truncate -s 0 /etc/nftables/hosts.blocked

echo "Dynamic block and configurations have been removed."
EOF

# Make the stop script executable
chmod +x "$STOP_SCRIPT"

# Create systemd service file
SYSTEMD_SERVICE_FILE="/etc/systemd/system/rfwb-portscan.service"
cat <<EOL > "$SYSTEMD_SERVICE_FILE"
[Unit]
Description=Port Scan Detection Service
After=network.target

[Service]
ExecStartPre=$PRE_START_SCRIPT
ExecStart=/usr/sbin/nft -f /etc/nftables/portscan.conf
ExecStop=$STOP_SCRIPT
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable rfwb-portscan.service
systemctl start rfwb-portscan.service

# Function to append unique IPs to the blocked file, ignoring networks from ignore_networks.conf
append_blocked_ip() {
    local ip="$1"
    for ignore_network in $IGNORE_NETWORKS; do
        if ipcalc -c "$ip" "$ignore_network" >/dev/null 2>&1; then
            echo "Ignoring IP $ip from scanning"
            return
        fi
    done
    if ! grep -q "^$ip$" "$BLOCKED_FILE"; then
        echo "$ip" >> "$BLOCKED_FILE"
        echo "Blocked IP $ip added to $BLOCKED_FILE"
        nft add element inet portscan dynamic_block { $ip }
    fi
}

# Monitor logs and update dynamic block
journalctl -kf | while read -r line; do
    if [[ "$line" == *"Port Scan Detected:"* ]]; then
        ip=$(echo "$line" | grep -oP '(?<=SRC=)\d+\.\d+\.\d+\.\d+')
        if [[ -n "$ip" ]]; then
            append_blocked_ip "$ip"
        fi
    fi
done &
systemctl stop rfwb-portscan
systemctl start rfwb-portscan
echo "nftables port scan detection and blocking service has been installed and started for the outside interface."
echo "Blocked IPs are logged to $BLOCKED_FILE."

# Setup logging notifications
echo "Port scan events will be logged with the prefix 'Port Scan Detected:' in the system logs."
echo "To view these logs, you can use a command such as: journalctl -xe | grep 'Port Scan Detected'"

sleep 2
}
# Function to install REQUIRED
install_required() {
    clear
    echo -e "${GREEN}Installing Required OS packages...${TEXTRESET}"
    sleep 2
    dnf -y config-manager --set-enabled crb
    dnf -y install epel-release
    dnf -y clean all
    dnf -y update
    dnf -y install ntsysv iptraf fail2ban tuned
    echo -e "${GREEN}Required Package installation complete.${TEXTRESET}"
    sleep 2
}
# Function to install ddns
install_ddclient() {
    clear
    echo -e "${GREEN}Installing ddns client (ddclient)...${TEXTRESET}"
    sleep 2
    dnf -y install ddclient
    echo -e "${GREEN}ddns client (ddclient) installation complete.${TEXTRESET}"
    sleep 2
}
# Function to install BIND
install_bind() {
    clear
    echo -e "${GREEN}Installing BIND...${TEXTRESET}"
    sleep 2
    dnf -y install bind
    echo -e "${GREEN}BIND installation complete.${TEXTRESET}"

    # Function to locate the inside interface and its sub-interfaces
    find_inside_interfaces() {
        # Find the main interface with a connection name ending in '-inside'
        main_interface=$(nmcli device status | awk '/-inside/ {print $1}')

        if [ -z "$main_interface" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        # Find all sub-interfaces (e.g., VLANs) associated with the main interface
        sub_interfaces=$(nmcli device status | awk -v main_intf="$main_interface" '$1 ~ main_intf "\\." {print $1}')

        # Combine main interface and sub-interfaces into a single list
        inside_interfaces="$main_interface $sub_interfaces"

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for DNS on the inside interfaces
    setup_nftables_for_dns() {
        # Ensure the nftables service is enabled and started
        sudo systemctl enable nftables
        sudo systemctl start nftables

        # Create a filter table if it doesn't exist
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        # Create an input chain if it doesn't exist
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        # Add rules to allow DNS on the inside interfaces
        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 53 accept"; then
                sudo nft add rule inet filter input iifname "$iface" udp dport 53 accept
                echo -e "${GREEN}Rule added: Allow DNS (UDP) on interface $iface${TEXTRESET}"
            else
                echo -e "${YELLOW}Rule already exists: Allow DNS (UDP) on interface $iface${TEXTRESET}"
            fi
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 53 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 53 accept
                echo -e "${GREEN}Rule added: Allow DNS (TCP) on interface $iface${TEXTRESET}"
            else
                echo -e "${YELLOW}Rule already exists: Allow DNS (TCP) on interface $iface${TEXTRESET}"
            fi
        done
        # Save the current nftables configuration
        sudo nft list ruleset > /etc/sysconfig/nftables.conf
        # Restart the nftables service to apply changes
        echo -e "${YELLOW}Restarting nftables service to apply changes...${TEXTRESET}"
        sudo systemctl restart nftables
        # Show the added rules in the input chain
        echo -e "${YELLOW}Current rules in the input chain:${TEXTRESET}"
        sudo nft list chain inet filter input
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_dns

    # Continue with the rest of the script
    echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"
    sleep 2
}
# Function to install ISC KEA
install_isc_kea() {
    clear
    echo -e "${GREEN}Installing ISC KEA...${TEXTRESET}"
    sleep 2
    dnf -y install epel-release
    curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-2-6/cfg/setup/bash.rpm.sh' | sudo bash
    sudo dnf -y update
    dnf -y install isc-kea
    echo -e "${GREEN}ISC KEA installation complete.${TEXTRESET}"

    # Function to locate the inside interfaces
    find_inside_interfaces() {
        # Find the main interface with a connection name ending in '-inside'
        main_interface=$(nmcli device status | awk '/-inside/ {print $1}')

        if [ -z "$main_interface" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        # Find all sub-interfaces (e.g., VLANs) associated with the main interface
        sub_interfaces=$(nmcli device status | awk -v main_intf="$main_interface" '$1 ~ main_intf "\\." {print $1}')

        # Combine main interface and sub-interfaces into a single list
        inside_interfaces="$main_interface $sub_interfaces"

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for DHCP on the inside interfaces
    setup_nftables_for_dhcp() {
        # Ensure the nftables service is enabled and started
        sudo systemctl enable nftables
        sudo systemctl start nftables

        # Create a filter table if it doesn't exist
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        # Create an input chain if it doesn't exist
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        # Add rules to allow DHCP on the inside interfaces
        for iface in $inside_interfaces; do
            # Allow DHCP for IPv4 (UDP port 67)
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 67 accept"; then
                sudo nft add rule inet filter input iifname "$iface" udp dport 67 accept
                echo -e "${GREEN}Rule added: Allow DHCP (IPv4) on interface $iface${TEXTRESET}"
            else
                echo -e "${YELLOW}Rule already exists: Allow DHCP (IPv4) on interface $iface${TEXTRESET}"
            fi
            # Allow DHCP for IPv6 (UDP port 547)
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 547 accept"; then
                sudo nft add rule inet filter input iifname "$iface" udp dport 547 accept
                echo -e "${GREEN}Rule added: Allow DHCP (IPv6) on interface $iface${TEXTRESET}"
            else
                echo -e "${YELLOW}Rule already exists: Allow DHCP (IPv6) on interface $iface${TEXTRESET}"
            fi
        done
        # Save the current nftables configuration
        sudo nft list ruleset > /etc/sysconfig/nftables.conf
        # Restart the nftables service to apply changes
        echo -e "${YELLOW}Restarting nftables service to apply changes...${TEXTRESET}"
        sudo systemctl restart nftables
        # Show the added rules in the input chain
        echo -e "${YELLOW}Current rules in the input chain:${TEXTRESET}"
        sudo nft list chain inet filter input
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_dhcp

    # Continue with the rest of the script
    echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"
    sleep 2
}
# Function to install COCKPIT
install_cockpit() {
    clear
    echo -e "${GREEN}Installing Cockpit...${TEXTRESET}"
    sleep 2
    dnf -y install cockpit cockpit-storaged cockpit-files tuned
    echo -e "${GREEN}Cockpit installation complete.${TEXTRESET}"

    # Function to locate the inside interfaces
    find_inside_interfaces() {
        # Find all active interfaces with a name ending in '-inside'
        inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

        if [ -z "$inside_interfaces" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for Cockpit on the inside interfaces
    setup_nftables_for_cockpit() {
        # Ensure the nftables service is enabled and started
        sudo systemctl enable nftables
        sudo systemctl start nftables

        # Create a filter table if it doesn't exist
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        # Create an input chain if it doesn't exist
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        # Add rules to allow Cockpit on the inside interfaces using port 9090
        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 9090 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 9090 accept
                echo -e "${GREEN}Rule added: Allow Cockpit on port 9090 for interface $iface${TEXTRESET}"
            else
                echo -e "${YELLOW}Rule already exists: Allow Cockpit on port 9090 for interface $iface${TEXTRESET}"
            fi
        done
        # Save the current nftables configuration
        sudo nft list ruleset > /etc/sysconfig/nftables.conf
        # Restart the nftables service to apply changes
        echo -e "${YELLOW}Restarting nftables service to apply changes...${TEXTRESET}"
        sudo systemctl restart nftables
        # Show the added rules in the input chain
        echo -e "${YELLOW}Current rules in the input chain:${TEXTRESET}"
        sudo nft list chain inet filter input
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_cockpit

    # Enable and start cockpit.socket
    systemctl enable --now cockpit.socket
    systemctl start cockpit.socket

    # Continue with the rest of the script
    echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"
    sleep 2
}
# Function to install WEBMIN
install_webmin() {
    clear
    echo -e "${GREEN}Installing Webmin...${TEXTRESET}"
    sleep 2
    curl -o webmin-setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/webmin-setup-repos.sh
    yes y | sh webmin-setup-repos.sh
    dnf -y install webmin
    echo -e "${GREEN}Enabling Webmin at boot up${TEXTRESET}"
    systemctl enable webmin

    # Function to locate the inside interfaces
    find_inside_interfaces() {
        # Find all active interfaces with a name ending in '-inside'
        inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

        if [ -z "$inside_interfaces" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for Webmin on the inside interfaces
    setup_nftables_for_webmin() {
        # Ensure the nftables service is enabled and started
        sudo systemctl enable nftables
        sudo systemctl start nftables

        # Create a filter table if it doesn't exist
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        # Create an input chain if it doesn't exist
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        # Add rules to allow Webmin on the inside interfaces using port 10000
        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 10000 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 10000 accept
                echo -e "${GREEN}Rule added: Allow Webmin on port 10000 for interface $iface${TEXTRESET}"
            else
                echo -e "${YELLOW}Rule already exists: Allow Webmin on port 10000 for interface $iface${TEXTRESET}"
            fi
        done
        # Save the current nftables configuration
        sudo nft list ruleset > /etc/sysconfig/nftables.conf
        # Restart the nftables service to apply changes
        echo -e "${YELLOW}Restarting nftables service to apply changes...${TEXTRESET}"
        sudo systemctl restart nftables
        # Show the added rules in the input chain
        echo -e "${YELLOW}Current rules in the input chain:${TEXTRESET}"
        sudo nft list chain inet filter input
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_webmin

    # Continue with the rest of the script
    echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"
    sleep 2
}
# Function to install NTOPNG
install_ntopng() {
    clear
    echo -e "${GREEN}Installing ntopng...${TEXTRESET}"
    sleep 2
    curl https://packages.ntop.org/centos-stable/ntop.repo > /etc/yum.repos.d/ntop.repo
    dnf -y config-manager --set-enabled crb
    dnf -y install epel-release
    dnf -y clean all
    dnf -y update
    dnf -y install pfring-dkms n2disk nprobe ntopng cento ntap
    echo -e "${GREEN}Enabling ntopng at boot up${TEXTRESET}"
    systemctl enable ntopng

    # Path to the configuration file
    CONFIG_FILE="/etc/ntopng/ntopng.conf"

    # Check if the configuration file exists
    if [ ! -f "$CONFIG_FILE" ]; then
      echo -e "${RED}Configuration file $CONFIG_FILE does not exist. Exiting...${TEXTRESET}"
      exit 1
    fi

    # Modify the line in the configuration file
    echo -e "${GREEN}Modifying $CONFIG_FILE...${TEXTRESET}"
    sed -i 's|^-G=/var/run/ntopng.pid|-G=/var/tmp/ntopng.pid --community|' "$CONFIG_FILE"

    # Verify the change
    if grep -q "^-G=/var/tmp/ntopng.pid --community" "$CONFIG_FILE"; then
      echo -e "${GREEN}Modification successful: -G=/var/tmp/ntopng.pid --community${TEXTRESET}"
    else
      echo -e "${RED}Modification failed. Please check the file manually.${TEXTRESET}"
      exit 1
    fi

    # Enable ntopng service
    echo -e "${GREEN}Enabling ntopng service...${TEXTRESET}"
    systemctl enable ntopng

    # Start ntopng service
    echo -e "${GREEN}Starting ntopng service...${TEXTRESET}"
    systemctl start ntopng

    # Validate ntopng service is running
    if systemctl is-active --quiet ntopng; then
      echo -e "${GREEN}ntopng service is running.${TEXTRESET}"
    else
      echo -e "${RED}Failed to start ntopng service. Please check the service status manually.${TEXTRESET}"
      exit 1
    fi

    # Function to locate the inside interfaces
    find_inside_interfaces() {
        # Find all active interfaces with a name ending in '-inside'
        inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

        if [ -z "$inside_interfaces" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for ntopng on the inside interfaces
    setup_nftables_for_ntopng() {
        # Ensure the nftables service is enabled and started
        sudo systemctl enable nftables
        sudo systemctl start nftables

        # Create a filter table if it doesn't exist
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        # Create an input chain if it doesn't exist
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        # Add rules to allow ntopng on the inside interfaces using port 3000
        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 3000 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 3000 accept
                echo -e "${GREEN}Rule added: Allow ntopng on port 3000 for interface $iface${TEXTRESET}"
            else
                echo -e "${YELLOW}Rule already exists: Allow ntopng on port 3000 for interface $iface${TEXTRESET}"
            fi
        done
        # Save the current nftables configuration
        sudo nft list ruleset > /etc/sysconfig/nftables.conf
        # Restart the nftables service to apply changes
        echo -e "${YELLOW}Restarting nftables service to apply changes...${TEXTRESET}"
        sudo systemctl restart nftables
        # Show the added rules in the input chain
        echo -e "${YELLOW}Current rules in the input chain:${TEXTRESET}"
        sudo nft list chain inet filter input
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_ntopng

    # Continue with the rest of the script
    echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"
    sleep 2
}
# Function to install NTOPNG
install_suricata() {
clear
echo -e "${YELLOW}Installing Suricata Engine${RESET}"
sleep 2
dnf -y install bc
# Function to check if the system has at least 8 GB of RAM
check_ram() {
    # Get the total memory in KB
    total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    # Convert the memory to GB and round up
    total_mem_gb=$(echo "$total_mem_kb / 1024 / 1024" | bc -l | awk '{print ($1 == int($1)) ? $1 : int($1) + 1}')

    # Check if the memory is at least 8 GB
    if (( total_mem_gb >= 8 )); then
        echo -e "${GREEN}RAM Check: Passed (Total RAM: ${total_mem_gb} GB)${RESET}"
        return 0
    else
        needed_ram=$((8 - total_mem_gb))
        echo -e "${RED}RAM Check: Failed (Total RAM: ${total_mem_gb} GB)${RESET}"
        echo -e "${YELLOW}Additional RAM needed: ${needed_ram} GB${RESET}"
        return 1
    fi
}

# Function to check if the system has at least 2 CPUs
check_cpus() {
    # Get the number of CPUs
    cpu_count=$(grep -c ^processor /proc/cpuinfo)

    # Check if the CPU count is at least 2
    if [ "$cpu_count" -ge 2 ]; then
        echo -e "${GREEN}CPU Check: Passed (Total CPUs: ${cpu_count})${RESET}"
        return 0
    else
        needed_cpus=$((2 - cpu_count))
        echo -e "${RED}CPU Check: Failed (Total CPUs: ${cpu_count})${RESET}"
        echo -e "${YELLOW}Additional CPUs needed: ${needed_cpus}${RESET}"
        return 1
    fi
}

# Run checks
check_ram
ram_status=$?

check_cpus
cpu_status=$?

# Evaluate results
echo -e "${CYAN}\nSummary:${RESET}"
if [ "$ram_status" -eq 0 ] && [ "$cpu_status" -eq 0 ]; then
    echo -e "${GREEN}System meets the minimum requirements.${RESET}"
    sleep 2
else
    echo -e "${RED}System does not meet the minimum requirements (8GB of RAM 2 CPU).${RESET}"
    [ "$ram_status" -ne 0 ] && echo -e "${YELLOW}Please add more RAM.${RESET}"
    [ "$cpu_status" -ne 0 ] && echo -e "${YELLOW}Please add more CPUs.${RESET}"
    sleep 2
    exit 1
fi

# Update the server
echo -e "${YELLOW}Updating the server...${TEXTRESET}"
if sudo dnf update -y; then
    echo -e "${GREEN}Server updated successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to update the server.${TEXTRESET}"
    exit 1
fi

# Install essential packages
clear
echo -e "${YELLOW}Installing essential suricata packages...${TEXTRESET}"
sleep 2
if sudo dnf install -y yum-utils bc nano curl wget policycoreutils-python-utils; then
    echo -e "${GREEN}Essential packages installed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to install essential packages.${TEXTRESET}"
    exit 1
fi

# Install Suricata
clear
echo -e "${YELLOW}Installing Suricata...${TEXTRESET}"
sleep 2
# Enable copr command for dnf
echo -e "${YELLOW}Enabling dnf copr command...${TEXTRESET}"
if sudo dnf install -y 'dnf-command(copr)'; then
    echo -e "${GREEN}dnf copr command enabled.${TEXTRESET}"
else
    echo -e "${RED}Failed to enable dnf copr command.${TEXTRESET}"
    exit 1
fi

# Enable the OISF repository for Suricata
echo -e "${YELLOW}Enabling OISF Suricata repository...${TEXTRESET}"
if echo 'y' | sudo dnf copr enable @oisf/suricata-7.0; then
    echo -e "${GREEN}OISF Suricata repository enabled.${TEXTRESET}"
else
    echo -e "${RED}Failed to enable OISF Suricata repository.${TEXTRESET}"
    exit 1
fi

# Add the EPEL repository
echo -e "${YELLOW}Adding EPEL repository...${TEXTRESET}"
if sudo dnf install -y epel-release dnf-plugins-core; then
    echo -e "${GREEN}EPEL repository added successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to add EPEL repository.${TEXTRESET}"
    exit 1
fi

# Install Suricata
echo -e "${YELLOW}Installing Suricata package...${TEXTRESET}"
if sudo dnf install -y suricata; then
    echo -e "${GREEN}Suricata installed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to install Suricata.${TEXTRESET}"
    exit 1
fi

# Enable Suricata service
echo -e "${YELLOW}Enabling Suricata service...${TEXTRESET}"
if sudo systemctl enable suricata; then
    echo -e "${GREEN}Suricata service enabled.${TEXTRESET}"
else
    echo -e "${RED}Failed to enable Suricata service.${TEXTRESET}"
    exit 1
fi

# Configure Suricata
echo -e "${YELLOW}Configuring Suricata...${TEXTRESET}"

# Backup the original Suricata configuration file
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

# Enable Community ID in suricata.yaml
echo -e "${YELLOW}Enabling Community ID feature in Suricata...${TEXTRESET}"
sudo sed -i 's/# \(community-id:\) false/\1 true/' /etc/suricata/suricata.yaml

# Detect the inside network interface using nmcli and awk
INSIDE_INTERFACE=$(nmcli connection show --active | awk '/-inside/ {print $4}')

if [ -z "$INSIDE_INTERFACE" ]; then
    echo -e "${RED}No inside interface found. Please ensure your interface names follow the expected pattern.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}Detected inside interface: $INSIDE_INTERFACE${TEXTRESET}"

# Update the pcap interface in suricata.yaml
echo -e "${YELLOW}Updating pcap interface to use $INSIDE_INTERFACE...${TEXTRESET}"
sudo sed -i "/# Cross platform libpcap capture support/,/interface:/ s/interface: eth0/interface: $INSIDE_INTERFACE/" /etc/suricata/suricata.yaml

# Update the af-packet interface in suricata.yaml
echo -e "${YELLOW}Updating af-packet interface to use $INSIDE_INTERFACE...${TEXTRESET}"
sudo sed -i "/# Linux high speed capture support/,/af-packet:/ {n; s/interface: eth0/interface: $INSIDE_INTERFACE/}" /etc/suricata/suricata.yaml

# Update the inside interface in /etc/sysconfig/suricata
echo -e "${YELLOW}Updating inside interface in /etc/sysconfig/suricata...${TEXTRESET}"
sudo sed -i "s/eth0/$INSIDE_INTERFACE/g" /etc/sysconfig/suricata

# Configure directory permissions for Suricata
echo -e "${YELLOW}Configuring directory permissions for Suricata...${TEXTRESET}"
sudo chgrp -R suricata /etc/suricata
sudo chgrp -R suricata /var/lib/suricata
sudo chgrp -R suricata /var/log/suricata
sudo chmod -R g+r /etc/suricata/
sudo chmod -R g+rw /var/lib/suricata
sudo chmod -R g+rw /var/log/suricata

# Add current user to the suricata group
echo -e "${YELLOW}Adding current user to the suricata group...${TEXTRESET}"
sudo usermod -a -G suricata $USER

# Validate that the user was added to the suricata group
echo -e "${YELLOW}Validating user group membership...${TEXTRESET}"
if id -nG "$USER" | grep -qw "suricata"; then
    echo -e "${GREEN}User $USER is successfully added to the suricata group.${TEXTRESET}"
else
    echo -e "${RED}Failed to add user $USER to the suricata group.${TEXTRESET}"
    exit 1
fi

# Run suricata-update
echo -e "${YELLOW}Running suricata-update...${TEXTRESET}"
if sudo suricata-update; then
    echo -e "${GREEN}suricata-update completed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to run suricata-update.${TEXTRESET}"
    exit 1
fi

# Loop to allow adding additional rule sources
while true; do
    echo -e "${YELLOW}Do you want to add additional rule sources? (y/n)${TEXTRESET}"
    read -p "Your choice: " add_rules

    if [[ "$add_rules" == "y" || "$add_rules" == "Y" ]]; then
        echo -e "${YELLOW}Listing available rule sources...${TEXTRESET}"
        sudo suricata-update list-sources

        echo -e "${YELLOW}Please enter the source names you want to add, separated by spaces:${TEXTRESET}"
        read -r rule_sources

        for source in $rule_sources; do
            echo -e "${YELLOW}Adding source $source...${TEXTRESET}"
            sudo suricata-update enable-source "$source"
        done

    else
        break
    fi
done

# Run suricata-update after the loop
echo -e "${YELLOW}Running suricata-update...${TEXTRESET}"
if sudo suricata-update; then
    echo -e "${GREEN}suricata-update completed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to run suricata-update.${TEXTRESET}"
fi

echo -e "${GREEN}Suricata has been configured with the inside interface $INSIDE_INTERFACE and proper permissions.${TEXTRESET}"
# Inform the user that the configuration validation is starting
echo -e "${YELLOW}Validating Suricata configuration...${TEXTRESET}"

# Define the command to run Suricata with the test configuration
COMMAND="suricata -T -c /etc/suricata/suricata.yaml -v"

# Execute the command and capture the output
OUTPUT=$($COMMAND 2>&1)

# Define the success message to look for
SUCCESS_MESSAGE="Notice: suricata: Configuration provided was successfully loaded. Exiting."

# Check if the output contains the success message
if echo "$OUTPUT" | grep -q "$SUCCESS_MESSAGE"; then
    echo -e "${GREEN}Success: Suricata configuration was loaded successfully.${TEXTRESET}"

else
    echo -e "${RED}Error: Suricata configuration test failed.${TEXTRESET}"
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi
# Start the Suricata service
echo -e "${YELLOW}Starting Suricata service...${TEXTRESET}"
sudo systemctl start suricata

# Show the status of the Suricata service
echo -e "${YELLOW}Checking Suricata service status...${TEXTRESET}"
status_output=$(sudo systemctl status suricata --no-pager)

# Display the status output
echo "$status_output"

#Delay checking the log file for xseconds
sleep 10

# Function to check for permission errors and fix them
check_and_fix_permissions() {
    # Capture the status output from the Suricata service
    status_output=$(sudo systemctl status suricata --no-pager)

    # Check for permission denied errors in the status output
    if echo "$status_output" | grep -qE "E: logopenfile: Error opening file: \"/var/log/suricata/fast.log\": Permission denied|W: runmodes: output
 module \"fast\": s
etup failed|E: logopenfile: Error opening file: \"/var/log/suricata/eve.json\": Permission denied|W: runmodes: output module \"eve-log\": setup fa
iled|E: logopenfile
: Error opening file: \"/var/log/suricata/stats.log\": Permission denied|W: runmodes: output module \"stats\": setup failed"; then
        # Display the specific lines indicating permission errors
        echo -e "${RED}Detected permission issues in the following log entries:${TEXTRESET}"
        echo "$status_output" | grep -E "E: logopenfile: Error opening file: \"/var/log/suricata/fast.log\": Permission denied|W: runmodes: output
 module \"fast\": s
etup failed|E: logopenfile: Error opening file: \"/var/log/suricata/eve.json\": Permission denied|W: runmodes: output module \"eve-log\": setup fa
iled|E: logopenfile
: Error opening file: \"/var/log/suricata/stats.log\": Permission denied|W: runmodes: output module \"stats\": setup failed"
        return 1
    else
        return 0
    fi
}

# Initialize attempt counter
attempts=0

# Define the maximum number of attempts
max_attempts=3

while [ $attempts -lt $max_attempts ]; do
    check_and_fix_permissions
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}Suricata service is running without permission issues.${TEXTRESET}"
        # Proceed without exiting to continue the script
        break
    else
        echo -e "\n${RED}Warning: There are permission issues with Suricata log files.${TEXTRESET}"
        echo -e "${YELLOW}Attempting to fix permissions (Attempt $((attempts + 1)) of $max_attempts)...${TEXTRESET}"
        sudo chown -R suricata:suricata /var/log/suricata
        echo -e "${YELLOW}Permissions have been reset. Restarting Suricata service...${TEXTRESET}"
        sudo systemctl restart suricata
        sleep 10
        # Check again after attempting to fix permissions
        echo -e "${YELLOW}Re-checking Suricata service status...${TEXTRESET}"
        check_and_fix_permissions
        if [ $? -eq 0 ]; then
            echo -e "\n${GREEN}Permissions successfully fixed. Suricata service is running without issues.${TEXTRESET}"
            break
        else
            echo -e "\n${RED}Permission issues still exist after attempting to fix them.${TEXTRESET}"
        fi
    fi
    attempts=$((attempts + 1))
done

if [ $attempts -eq $max_attempts ]; then
    echo -e "\n${RED}Failed to resolve permission issues after $max_attempts attempts. Please check the system configuration manually.${TEXTRESET}
"
    exit 1
fi


# Inform the user about the test
echo -e "${YELLOW}Testing Suricata rule...${TEXTRESET}"
echo -e "${YELLOW}Waiting for the engine to start...${TEXTRESET}"
# Total duration for the progress bar
duration=15

# Total number of steps in the progress bar
steps=30

# Calculate the sleep duration between each step
sleep_duration=$(echo "$duration/$steps" | bc -l)

# Initialize the progress bar
progress=""

echo -e "Progress:"

# Loop to update the progress bar
for ((i=0; i<=steps; i++)); do
    # Calculate percentage
    percent=$((i * 100 / steps))

    # Add a '#' to the progress bar for each step
    progress+="#"

    # Print the progress bar
    printf "\r[%-30s] %d%%" "$progress" "$percent"

    # Sleep for the calculated duration
    sleep "$sleep_duration"
done

# Move to the next line after completion
echo -e "\nDone!"
# Run the curl command and capture the response
response=$(curl -s http://testmynids.org/uid/index.html)


# Run the curl command and capture the response
response=$(curl -s http://testmynids.org/uid/index.html)
# Validate the response
expected_response="uid=0(root) gid=0(root) groups=0(root)"
if [ "$response" == "$expected_response" ]; then
    echo -e "${GREEN}Curl command was successful. Expected response received:${TEXTRESET}"
    echo -e "${GREEN}$response${TEXTRESET}"
    sleep 5
    # Capture the last line of the fast.log containing the specified ID
    last_log_line=$(grep 2100498 /var/log/suricata/fast.log | tail -n 1)
    echo -e "${YELLOW}Last log line with ID 2100498: ${last_log_line}${TEXTRESET}"  # Debug: Print the last line for verification

    # Check the log line for the classification
    if echo "$last_log_line" | grep -q "\[Classification: Potentially Bad Traffic\]"; then
        echo -e "${GREEN}Suricata rule was successful. The classification '[Classification: Potentially Bad Traffic]' was found in the log entry with ID 2100498.${TEXTRESET}"
    else
        echo -e "${RED}Suricata rule failed. The expected classification was not found in the log entry with ID 2100498.${TEXTRESET}"
        exit 1
    fi
else
    echo -e "${RED}Curl command failed. The expected response was not received.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}suricata completed successfully.${TEXTRESET}"
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"
sleep 2
}

# Function to install REQUIRED
install_elastic() {
# Inform the user that the process is starting
clear
echo -e "${YELLOW}Starting the installation of Elasticsearch and Kibana...${TEXTRESET}"
sleep 2
# Step 1: Import the Elastic GPG key
echo -e "${YELLOW}Importing the Elastic GPG key...${TEXTRESET}"
if sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch; then
    echo -e "${GREEN}Elastic GPG key imported successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to import Elastic GPG key.${TEXTRESET}"
    exit 1
fi

# Step 2: Create the Elasticsearch repository file
echo -e "${YELLOW}Creating the Elasticsearch repository file...${TEXTRESET}"
repo_file="/etc/yum.repos.d/elasticsearch.repo"
sudo bash -c "cat > $repo_file" << EOF
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0
autorefresh=1
type=rpm-md
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Elasticsearch repository file created successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to create Elasticsearch repository file.${TEXTRESET}"
    exit 1
fi

# Step 3: Install Elasticsearch and Kibana
clear
echo -e "${GREEN}Installing Elasticsearch and Kibana...${TEXTRESET}"
sleep 2
if sudo dnf install --enablerepo=elasticsearch elasticsearch kibana -y; then
    echo -e "${GREEN}Elasticsearch and Kibana installed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to install Elasticsearch and Kibana.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}Installation download completed successfully.${TEXTRESET}"
sleep 2
clear
# Define the Elasticsearch configuration paths
ELASTIC_YML="/etc/elasticsearch/elasticsearch.yml"
JVM_OPTIONS_DIR="/etc/elasticsearch/jvm.options.d"
JVM_HEAP_OPTIONS="$JVM_OPTIONS_DIR/jvm-heap.options"

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    # Find the interface ending with -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi

    # Extract the private IP address for the found interface
    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

    if [ -z "$ip" ]; then
        echo -e "${RED}Error: No IP address found for the interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$ip"
}

# Function to configure Elasticsearch
configure_elasticsearch() {
    local private_ip="$1"

    echo -e "${YELLOW}Backing up the original Elasticsearch configuration...${TEXTRESET}"
    # Backup the original Elasticsearch configuration file
    sudo cp "$ELASTIC_YML" "${ELASTIC_YML}.bak"

    echo -e "${YELLOW}Updating the Elasticsearch configuration...${TEXTRESET}"
    # Use awk to insert the network.bind_host line below the specified comments
    sudo awk -v ip="$private_ip" '
    BEGIN {inserted=0}
    {
        print $0
        if (!inserted && $0 ~ /^#network.host: 192.168.0.1$/) {
            print "network.bind_host: [\"127.0.0.1\", \"" ip "\"]"
            inserted=1
        }
    }
    ' "$ELASTIC_YML" > /tmp/elasticsearch.yml && sudo mv /tmp/elasticsearch.yml "$ELASTIC_YML"

    # Check if discovery.type: single-node is present, if not, append it
    if ! grep -q "^discovery.type: single-node" "$ELASTIC_YML"; then
        echo "discovery.type: single-node" | sudo tee -a "$ELASTIC_YML" > /dev/null
    fi

    # Comment out the initial master nodes setting if present
    sudo sed -i 's/^cluster.initial_master_nodes:.*$/#&/' "$ELASTIC_YML" || {
        echo -e "${RED}Error: Failed to comment out initial master nodes setting.${TEXTRESET}"
        exit 1
    }
}

# Function to set JVM heap size
configure_jvm_heap() {
    echo -e "${YELLOW}Configuring JVM heap size...${TEXTRESET}"
    # Create the JVM options directory if it doesn't exist
    sudo mkdir -p "$JVM_OPTIONS_DIR"

    # Write the JVM heap configuration
    echo "-Xms3g" | sudo tee "$JVM_HEAP_OPTIONS" > /dev/null
    echo "-Xmx3g" | sudo tee -a "$JVM_HEAP_OPTIONS" > /dev/null
}

# Main script execution
main() {
    echo -e "${YELLOW}Locating the server's private IP address...${TEXTRESET}"
    private_ip=$(find_private_ip)

    if [ -z "$private_ip" ]; then
        echo -e "${RED}Error: Unable to determine the private IP address.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Private IP identified as: $private_ip${TEXTRESET}"

    echo -e "${YELLOW}Configuring Elasticsearch...${TEXTRESET}"
    configure_elasticsearch "$private_ip"

    echo -e "${YELLOW}Configuring JVM heap size...${TEXTRESET}"
    configure_jvm_heap

    echo -e "${GREEN}Configuration complete. Please restart the Elasticsearch service to apply changes.${TEXTRESET}"
}

# Run the main function
main
# Function to find the network interface
find_interface() {
    # Find the interface with a connection ending in -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '-inside' found.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Function to configure nftables rules
configure_nftables() {
    local interface="$1"

    echo -e "${YELLOW}Configuring nftables for interface: $interface...${TEXTRESET}"

    # Ensure the nftables service is enabled and started
    sudo systemctl enable nftables
    sudo systemctl start nftables

    # Create a filter table if it doesn't exist
    if ! sudo nft list tables | grep -q 'inet filter'; then
        sudo nft add table inet filter
    fi

    # Create an input chain if it doesn't exist
    if ! sudo nft list chain inet filter input &>/dev/null; then
        sudo nft add chain inet filter input { type filter hook input priority 0 \; }
    fi

    # Add rules to allow traffic on port 5601 for Kibana
    if ! sudo nft list chain inet filter input | grep -q "iifname \"$interface\" tcp dport 5601 accept"; then
        sudo nft add rule inet filter input iifname "$interface" tcp dport 5601 accept
        echo -e "${GREEN}Rule added: Allow TCP traffic on port 5601 for interface $interface${TEXTRESET}"
    else
        echo -e "${YELLOW}Rule already exists: Allow TCP traffic on port 5601 for interface $interface${TEXTRESET}"
    fi
    # Save the current nftables configuration
    sudo nft list ruleset > /etc/sysconfig/nftables.conf
    # Restart the nftables service to apply changes
    echo -e "${YELLOW}Restarting nftables service to apply changes...${TEXTRESET}"
    sudo systemctl restart nftables
    # Show the added rules in the input chain
    echo -e "${YELLOW}Current rules in the input chain:${TEXTRESET}"
    sudo nft list chain inet filter input
}

# Main script execution
interface=$(find_interface)
configure_nftables "$interface"

echo -e "${GREEN}Firewall configuration for port 5601 complete.${TEXTRESET}"

# Main script execution
main() {
    echo -e "${YELLOW}Locating the network interface...${TEXTRESET}"
    interface=$(find_interface)

    echo -e "${GREEN}Firewall configuration complete.${TEXTRESET}"
}

# Run the main function
main

# Function to reload systemd daemon
reload_daemon() {
    echo -e "${YELLOW}Reloading systemd daemon...${TEXTRESET}"
    if sudo systemctl daemon-reload; then
        echo -e "${GREEN}Systemd daemon reloaded successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to reload systemd daemon.${TEXTRESET}"
        exit 1
    fi
}

# Function to enable and start Elasticsearch service
enable_start_elasticsearch() {
    echo -e "${YELLOW}Enabling and starting Elasticsearch service...${TEXTRESET}"
    if sudo systemctl enable elasticsearch --now; then
        echo -e "${GREEN}Elasticsearch service enabled and start command issued.${TEXTRESET}"
    else
        echo -e "${RED}Failed to enable and start Elasticsearch service.${TEXTRESET}"
        exit 1
    fi
}

# Function to check the status of Elasticsearch service
check_status() {
    echo -e "${YELLOW}Checking Elasticsearch service status...${TEXTRESET}"
    while true; do
        status=$(sudo systemctl is-active elasticsearch)
        if [ "$status" == "active" ]; then
            echo -e "${GREEN}Elasticsearch service is active and running.${TEXTRESET}"
            break
        else
            echo -e "${YELLOW}Waiting for Elasticsearch service to start...${TEXTRESET}"
            sleep 5
        fi
    done
}

# Main script execution
main() {
    reload_daemon
    enable_start_elasticsearch
    check_status

    # Continue with further steps if needed
    echo -e "${GREEN}Elasticsearch is running. Proceeding...${TEXTRESET}"
    # Add additional script actions here
}

# Run the main function
main
clear
echo -e "${GREEN}Generating Password for the elastic account.${TEXTRESET}"
echo -e "${Yellow}This will be forced to reset when first logging in.${TEXTRESET}"
# Function to generate a random password
generate_password() {
    # Generate a 6-character password with upper and lowercase letters
    tr -dc 'A-Za-z' </dev/urandom | head -c 6
}

# Function to reset the password for the elastic user
reset_elastic_password() {
    local password="$1"
    echo -e "${YELLOW}Resetting password for the elastic user...${TEXTRESET}"

    # Use here-document to provide input to the password reset command
    sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i <<EOF
y
$password
$password
EOF

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Password for the elastic user successfully reset.${TEXTRESET}"
        echo -e "${YELLOW}The Password is:${TEXTRESET}"
        echo -e "$password"
        echo -e "${RED}You will need this password for the next step.${TEXTRESET}"
        read -p "Press Enter Once you have it written down"
    else
        echo -e "${RED}Failed to reset password for the elastic user.${TEXTRESET}"
        exit 1
    fi
}

# Main script execution
main() {
    # Generate a password
    password=$(generate_password)
    echo -e "${GREEN}Generated password: $password${TEXTRESET}"

    # Reset the password
    reset_elastic_password "$password"

    # Store the password in a file
    echo "$password" | sudo tee /root/elastic_password > /dev/null
    echo -e "${GREEN}Password stored in /root/elastic_password.${TEXTRESET}"
}

# Run the main function
main

# Function to test Elasticsearch response
test_elasticsearch() {
    local cert_path="/etc/elasticsearch/certs/http_ca.crt"
    local url="https://localhost:9200"

    echo -e "${YELLOW}Testing Elasticsearch response...${TEXTRESET}"

    # Prompt for the password of the elastic user
    read -sp "Enter password for elastic user: " password
    echo

    # Perform the query using curl
    response=$(sudo curl --cacert "$cert_path" -u elastic:"$password" "$url" 2>/dev/null)

    # Check if the response contains expected data
    if echo "$response" | grep -q '"tagline" : "You Know, for Search"'; then
        echo -e "${GREEN}Elasticsearch is responding to queries.${TEXTRESET}"
        echo "$response"
    else
        echo -e "${RED}Failed to get a valid response from Elasticsearch.${TEXTRESET}"
        exit 1
    fi
}

# Main script execution
main() {
    test_elasticsearch
}

# Run the main function
main


##INSATLL KIBANA
# Define paths
ELASTIC_CERT_PATH="/etc/elasticsearch/certs/http_ca.crt"
KIBANA_DIR="/etc/kibana"
KIBANA_CONFIG="$KIBANA_DIR/kibana.yml"
KIBANA_BIN_DIR="/usr/share/kibana/bin"

# Function to copy Elasticsearch certificate to Kibana directory
copy_certificate() {
    echo -e "${YELLOW}Copying Elasticsearch certificate to Kibana directory...${TEXTRESET}"
    if sudo cp "$ELASTIC_CERT_PATH" "$KIBANA_DIR/http_ca.crt"; then
        echo -e "${GREEN}Certificate copied successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to copy the certificate. Please check the paths and permissions.${TEXTRESET}"
        exit 1
    fi
}

# Function to generate Kibana encryption keys
generate_encryption_keys() {
    echo -e "${YELLOW}Generating Kibana encryption keys...${TEXTRESET}"

    # Capture only the lines with encryption keys from the output
    keys_output=$(sudo "$KIBANA_BIN_DIR/kibana-encryption-keys" generate -q 2>/dev/null | grep -E '^xpack\.')

    if [ -n "$keys_output" ]; then
        echo -e "${GREEN}Encryption keys generated successfully.${TEXTRESET}"
        echo "$keys_output"
    else
        echo -e "${RED}Failed to generate encryption keys.${TEXTRESET}"
        exit 1
    fi
}

# Function to update Kibana configuration
update_kibana_config() {
    local keys="$1"
    echo -e "${YELLOW}Updating Kibana configuration...${TEXTRESET}"

    # Add encryption keys to the configuration file
    if echo -e "\n$keys" | sudo tee -a "$KIBANA_CONFIG" > /dev/null; then
        echo -e "${GREEN}Kibana configuration updated with encryption keys.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update Kibana configuration with encryption keys.${TEXTRESET}"
        exit 1
    fi

    # Ensure no extraneous lines are left in the file
    sudo sed -i '/Generating Kibana encryption keys.../d' "$KIBANA_CONFIG"
    sudo sed -i '/Encryption keys generated successfully./d' "$KIBANA_CONFIG"

    # Append telemetry settings to the configuration file
    if echo -e "\ntelemetry.optIn: false" | sudo tee -a "$KIBANA_CONFIG" > /dev/null && \
       echo "telemetry.allowChangingOptInStatus: false" | sudo tee -a "$KIBANA_CONFIG" > /dev/null; then
        echo -e "${GREEN}Telemetry settings added to Kibana configuration.${TEXTRESET}"
    else
        echo -e "${RED}Failed to add telemetry settings to Kibana configuration.${TEXTRESET}"
        exit 1
    fi

    # Update the elasticsearch.ssl.certificateAuthorities setting
    if sudo sed -i 's|^#*\(elasticsearch\.ssl\.certificateAuthorities:\).*|\1 [ "/etc/kibana/http_ca.crt" ]|' "$KIBANA_CONFIG"; then
        echo -e "${GREEN}Updated elasticsearch.ssl.certificateAuthorities in Kibana configuration.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update elasticsearch.ssl.certificateAuthorities in Kibana configuration.${TEXTRESET}"
        exit 1
    fi
}

# Function to validate Kibana configuration changes
validate_config_changes() {
    echo -e "${YELLOW}Validating Kibana configuration changes...${TEXTRESET}"

    # Validate encryption keys
    for key in xpack.encryptedSavedObjects.encryptionKey xpack.reporting.encryptionKey xpack.security.encryptionKey; do
        if ! grep -q "$key" "$KIBANA_CONFIG"; then
            echo -e "${RED}Missing $key in Kibana configuration.${TEXTRESET}"
            exit 1
        fi
    done

    # Validate telemetry settings
    if ! grep -q "telemetry.optIn: false" "$KIBANA_CONFIG" || ! grep -q "telemetry.allowChangingOptInStatus: false" "$KIBANA_CONFIG"; then
        echo -e "${RED}Telemetry settings are not properly configured.${TEXTRESET}"
        exit 1
    fi

    # Validate certificate authorities setting
    if ! grep -q 'elasticsearch.ssl.certificateAuthorities: \[ "/etc/kibana/http_ca.crt" \]' "$KIBANA_CONFIG"; then
        echo -e "${RED}elasticsearch.ssl.certificateAuthorities is not properly configured.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}All Kibana configuration changes validated successfully.${TEXTRESET}"
}

# Main script execution
main() {
    copy_certificate
    keys=$(generate_encryption_keys)
    update_kibana_config "$keys"
    validate_config_changes
}

# Run the main function
main

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    # Find the interface ending with -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "Error: No interface ending with '-inside' found."
        exit 1
    fi

    # Extract the private IP address for the found interface
    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

    if [ -z "$ip" ]; then
        echo -e "Error: No IP address found for the interface $interface."
        exit 1
    fi

    echo "$ip"
}

# Function to configure Kibana
configure_kibana() {
    local private_ip="$1"
    local kibana_yml="/etc/kibana/kibana.yml"  # Path to your Kibana config

    echo "Backing up the original Kibana configuration..."
    # Backup the original Kibana configuration file
    sudo cp "$kibana_yml" "${kibana_yml}.bak"

    echo "Updating the Kibana configuration..."
    # Use awk to insert the server.host line below the specified comments
    sudo awk -v ip="$private_ip" '
    BEGIN {inserted=0}
    {
        print $0
        if (!inserted && $0 ~ /^#server.host: "localhost"$/) {
            print "server.host: \"" ip "\""
            inserted=1
        }
    }
    ' "$kibana_yml" > /tmp/kibana.yml && sudo mv /tmp/kibana.yml "$kibana_yml"
}

# Main execution
private_ip=$(find_private_ip)
configure_kibana "$private_ip"

echo "Kibana has been configured to use the private IP address: $private_ip"

# Define the file path
FILE_PATH="/etc/kibana/kibana.yml"

# Function to check and set the group of the file
check_and_set_group() {
    current_group=$(stat -c "%G" "$FILE_PATH")

    if [ "$current_group" != "kibana" ]; then
        echo -e "${YELLOW}Current group of $FILE_PATH is $current_group. Changing it to 'kibana'...${TEXTRESET}"
        sudo chgrp kibana "$FILE_PATH"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Group changed to 'kibana'.${TEXTRESET}"
        else
            echo -e "${RED}Error: Failed to change group to 'kibana'.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${GREEN}Group is already set to 'kibana'.${TEXTRESET}"
    fi
}

# Function to check and set the permissions of the file
check_and_set_permissions() {
    current_permissions=$(stat -c "%a" "$FILE_PATH")

    # Extract the group permissions (second digit in the octal representation)
    group_permissions=$(( (current_permissions / 10) % 10 ))

    if (( group_permissions != 6 )); then
        echo -e "${YELLOW}Current group permissions of $FILE_PATH are not 'rw'. Changing permissions...${TEXTRESET}"
        sudo chmod g+rw "$FILE_PATH"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Permissions changed to allow group 'kibana' read and write access.${TEXTRESET}"
        else
            echo -e "${RED}Error: Failed to change permissions.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${GREEN}Permissions are already correct for group 'kibana'.${TEXTRESET}"
    fi
}

# Main script execution
check_and_set_group
check_and_set_permissions

echo -e "${GREEN}Validation and correction of group and permissions completed successfully.${TEXTRESET}"
# Define the file path to store the enrollment token
TOKEN_FILE="/root/kibana_enrollment_token"

# Function to generate the enrollment token
generate_enrollment_token() {
    echo -e "${YELLOW}Generating Kibana enrollment token...${TEXTRESET}"
    token=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null)

    if [ -z "$token" ]; then
        echo -e "${RED}Error: Failed to generate enrollment token.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Enrollment token generated successfully.${TEXTRESET}"
    echo "$token" > "$TOKEN_FILE"
    echo -e "${GREEN}Enrollment token stored in ${TOKEN_FILE}.${TEXTRESET}"
}

# Function to start and enable the Kibana service
start_kibana_service() {
    echo -e "${YELLOW}Starting and enabling Kibana service...${TEXTRESET}"
    sudo systemctl enable kibana --now

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to start and enable Kibana service.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Kibana service started and enabled.${TEXTRESET}"
}

# Function to check the status of the Kibana service
check_kibana_status() {
    echo -e "${YELLOW}Checking Kibana service status...${TEXTRESET}"
    sudo systemctl status kibana --no-pager

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Kibana service is not running.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Kibana service is running.${TEXTRESET}"
}

# Main script execution
generate_enrollment_token
start_kibana_service
check_kibana_status
clear
echo -e "${GREEN}Kibana setup and startup process completed successfully.${TEXTRESET}"

# Function to display initial instructions
display_instructions() {
    echo -e "${GREEN}The Kibana Service is now running${TEXTRESET}"
    echo -e "${YELLOW}The next step is to enable the Elastic dashboard/services.${TEXTRESET}"
    echo -e "${RED}PLEASE DO NOT LOGIN TO THE DASHBOARD YET${TEXTRESET}"
    echo -e "We are only starting the elasdtic service and we must provide an enrollment token and Verification code"
    echo ""
    echo "#1 - Open a browser (Leave this terminal open)"
    echo ""
    echo -e "#2 - In the address bar of your browser, navigate to ${GREEN}http://${private_ip}:5601${TEXTRESET}"
    echo ""
    echo "#3 - You will be asked for an enrollment token:"
    echo -e "Token: $(cat /root/kibana_enrollment_token)"
    echo ""
    echo "#4 - Once you have input your enrollment token, the webpage will ask you for the verification code:"
    echo ""
}

# Function to generate a new enrollment token
generate_enrollment_token() {
    echo -e "${YELLOW}Generating a new enrollment token...${TEXTRESET}"
    token=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null)
    echo "$token" > /root/kibana_enrollment_token
    echo -e "${GREEN}New token generated and saved to /root/kibana_enrollment_token.${TEXTRESET}"
}

# Function to get a verification code
get_verification_code() {
    echo -e "${YELLOW}Generating a verification code...${TEXTRESET}"
    sudo /usr/share/kibana/bin/kibana-verification-code
}

# Main script execution
display_instructions

# Loop to manage enrollment token generation
while true; do
    read -p "Was the enrollment token successful? If it was you're being asked for a verification code (yes/no): " token_success
    if [[ "$token_success" == "no" ]]; then
        generate_enrollment_token
    else
        break
    fi
done

# Prompt for verification code
while true; do
    read -p "Press Enter to get your Verification Code When Ready: "
    get_verification_code

    read -p "Do you need a new verification code? (yes/no): " code_needed
    if [[ "$code_needed" == "no" ]]; then
        break
    fi
done

echo -e "${GREEN}Kibana Setup completed...${TEXTRESET}"

#INSTALL FILEBEAT
# Paths and file variables
SOURCE_CERT_PATH="/etc/elasticsearch/certs/http_ca.crt"
DEST_CERT_DIR="/etc/filebeat"
DEST_CERT_PATH="$DEST_CERT_DIR/http_ca.crt"
FILEBEAT_YML="/etc/filebeat/filebeat.yml"
SURICATA_MODULE_YML="/etc/filebeat/modules.d/suricata.yml"
ELASTIC_PASSWORD_FILE="/root/elastic_password"

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi

    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

    if [ -z "$ip" ]; then
        echo -e "${RED}Error: No IP address found for the interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$ip"
}

# Install Filebeat
install_filebeat() {
    clear
    echo -e "${GREEN}Installing Filebeat...${TEXTRESET}"
    sleep 2
    sudo dnf install --enablerepo=elasticsearch filebeat -y

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Filebeat installed successfully.${TEXTRESET}"
    else
        echo -e "${RED}Error: Failed to install Filebeat.${TEXTRESET}"
        exit 1
    fi
}

# Copy the http_ca.crt file locally
copy_certificate_locally() {
    if [ -f "$SOURCE_CERT_PATH" ]; then
        echo -e "${YELLOW}Copying http_ca.crt from $SOURCE_CERT_PATH to $DEST_CERT_DIR...${TEXTRESET}"
        sudo cp "$SOURCE_CERT_PATH" "$DEST_CERT_PATH"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Certificate copied successfully to $DEST_CERT_PATH.${TEXTRESET}"
        else
            echo -e "${RED}Error: Failed to copy certificate to $DEST_CERT_PATH.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${RED}Error: Certificate file not found at $SOURCE_CERT_PATH.${TEXTRESET}"
        exit 1
    fi
}

# Configure Filebeat
configure_filebeat() {
    local private_ip="$1"

    if [ ! -f "$ELASTIC_PASSWORD_FILE" ]; then
        echo -e "${RED}Error: Elastic password file not found at $ELASTIC_PASSWORD_FILE.${TEXTRESET}"
        exit 1
    fi

    local elastic_password
    elastic_password=$(cat "$ELASTIC_PASSWORD_FILE")

    echo -e "${YELLOW}Backing up the original Filebeat configuration...${TEXTRESET}"
    sudo cp "$FILEBEAT_YML" "${FILEBEAT_YML}.bak"

    echo -e "${YELLOW}Updating the Filebeat configuration...${TEXTRESET}"
    sudo awk -v ip="$private_ip" -v password="$elastic_password" '
    BEGIN {in_elasticsearch=0; inserted_kibana=0}
    {
        if ($0 ~ /^setup.kibana:/) {
            in_elasticsearch=0
        }
        if ($0 ~ /^output.elasticsearch:/) {
            in_elasticsearch=1
        }
        if (!inserted_kibana && $0 ~ /^  #host: "localhost:5601"$/) {
            print "  host: \"" ip ":5601\""
            print "  protocol: \"http\""
            print "  ssl.enabled: true"
            print "  ssl.certificate_authorities: [\"/etc/filebeat/http_ca.crt\"]"
            inserted_kibana=1
        }
        if (in_elasticsearch) {
            if ($0 ~ /^  hosts:/) {
                print "  hosts: [\"" ip ":9200\"]"
                next
            }
            if ($0 ~ /^  # Protocol/) {
                print "  protocol: \"https\""
            }
            if ($0 ~ /^  #api_key:/) {
                print "  username: \"elastic\""
                print "  password: \"" password "\""
                print "  ssl.certificate_authorities: [\"/etc/filebeat/http_ca.crt\"]"
                print "  ssl.verification_mode: full"
            }
        }
        print $0
    }
    END {
        print "\nsetup.ilm.overwrite: true"
    }
    ' "$FILEBEAT_YML" > /tmp/filebeat.yml && sudo mv /tmp/filebeat.yml "$FILEBEAT_YML"
}

# Modify Suricata module configuration
configure_suricata_module() {
    echo -e "${YELLOW}Configuring Suricata module...${TEXTRESET}"
    sudo awk '
    BEGIN {in_eve=0}
    {
        if ($0 ~ /^- module: suricata$/) {
            in_eve=0
        }
        if ($0 ~ /^  eve:$/) {
            in_eve=1
        }
        if (in_eve && $0 ~ /^    #enabled: false$/) {
            print "    enabled: true"
            next
        }
        if (in_eve && $0 ~ /^    #var.paths:/) {
            print "    var.paths: [\"/var/log/suricata/eve.json\"]"
            next
        }
        print $0
    }
    ' "$SURICATA_MODULE_YML" > /tmp/suricata.yml && sudo mv /tmp/suricata.yml "$SURICATA_MODULE_YML"
}

# Verify Elasticsearch connection and enable Suricata module
verify_and_enable_module() {
    local private_ip="$1"

    if [ ! -f "$ELASTIC_PASSWORD_FILE" ]; then
        echo -e "${RED}Error: Elastic password file not found at $ELASTIC_PASSWORD_FILE.${TEXTRESET}"
        exit 1
    fi

    local elastic_password
    elastic_password=$(cat "$ELASTIC_PASSWORD_FILE")

    echo -e "${YELLOW}Verifying Elasticsearch connection...${TEXTRESET}"
    curl -v --cacert "$DEST_CERT_PATH" "https://$private_ip:9200" -u elastic:"$elastic_password"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Elasticsearch connection verified successfully.${TEXTRESET}"
        echo -e "${YELLOW}Enabling Suricata module in Filebeat...${TEXTRESET}"
        sudo filebeat modules enable suricata

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Suricata module enabled successfully.${TEXTRESET}"
            configure_suricata_module
        else
            echo -e "${RED}Error: Failed to enable Suricata module.${TEXTRESET}"
        fi
    else
        echo -e "${RED}Error: Failed to verify Elasticsearch connection.${TEXTRESET}"
    fi
}

# Main script execution
install_filebeat
copy_certificate_locally
private_ip=$(find_private_ip)
configure_filebeat "$private_ip"
verify_and_enable_module "$private_ip"

# Spinner function for animation
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep "$pid")" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Enable the Filebeat Suricata module
enable_suricata_module() {
    echo -e "${YELLOW}Enabling Filebeat Suricata module...${TEXTRESET}"
    sudo filebeat modules enable suricata

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Suricata module enabled successfully.${TEXTRESET}"
    else
        echo -e "${RED}Error: Failed to enable Suricata module.${TEXTRESET}"
        exit 1
    fi
}

# Edit the Suricata module configuration
edit_suricata_config() {
    local config_file="/etc/filebeat/modules.d/suricata.yml"

    echo -e "${YELLOW}Configuring Suricata module...${TEXTRESET}"
    sudo awk '
    BEGIN {in_eve=0}
    {
        if ($0 ~ /^- module: suricata$/) {
            in_eve=0
        }
        if ($0 ~ /^  eve:$/) {
            in_eve=1
        }
        if (in_eve && $0 ~ /^    enabled: false$/) {
            print "    enabled: true"
            next
        }
        if (in_eve && $0 ~ /^    #var.paths:/) {
            print "    var.paths: [\"/var/log/suricata/eve.json\"]"
            next
        }
        print $0
    }
    ' "$config_file" > /tmp/suricata.yml && sudo mv /tmp/suricata.yml "$config_file"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Suricata module configuration updated successfully.${TEXTRESET}"
    else
        echo -e "${RED}Error: Failed to update Suricata module configuration.${TEXTRESET}"
        exit 1
    fi
    sleep 2
}

# Setup Filebeat (load dashboards and pipelines)
setup_filebeat() {
    clear 
    echo -e "${GREEN}Setting up Filebeat...${TEXTRESET}"

    # Start the spinner in the background
    sudo filebeat setup & spinner $!

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Filebeat setup completed successfully.${TEXTRESET}"
    else
        echo -e "${RED}Error: Filebeat setup failed.${TEXTRESET}"
        exit 1
    fi
}

# Start and enable the Filebeat service
start_filebeat_service() {
    echo -e "${YELLOW}Starting and enabling Filebeat service...${TEXTRESET}"
    sudo systemctl enable filebeat --now

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Filebeat service started and enabled successfully.${TEXTRESET}"
    else
        echo -e "${RED}Error: Failed to start and enable Filebeat service.${TEXTRESET}"
        exit 1
    fi
}

# Check the status of the Filebeat service
check_filebeat_status() {
    echo -e "${YELLOW}Checking Filebeat service status...${TEXTRESET}"
    sudo systemctl status filebeat --no-pager

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Filebeat service is running.${TEXTRESET}"
    else
        echo -e "${RED}Error: Filebeat service is not running.${TEXTRESET}"
        exit 1
    fi
}

# Main script execution
enable_suricata_module
edit_suricata_config
setup_filebeat
start_filebeat_service
check_filebeat_status
clear
echo -e "${GREEN}Filebeat Suricata module setup and configuration completed successfully.${TEXTRESET}"
echo -e "${GREEN}Setup completed successfully.${TEXTRESET}"
echo -e
echo -e "Your generated password for this installation is located in the file /root/elastic_password"
echo -e "The password is:"
cat /root/elastic_password
echo -e "If you wish to change this password you can do so using FW-Manager after the system is fully operational"
echo -e "One last step to get your dashboards are to login to Kibana http://localhost:5601 (the dashboard you logged into earlier),"
echo -e "Input "type:dashboard suricata" (without quotes) in the search box at the top, and select"
echo -e "[Filebeat Suricata] Alert Overview to load the Suricata Dashboard- Go ahead and do that now"
read -p "Press Enter to exit the Installer for Elastic/Kibana/Filebeat"
}



# Use dialog to prompt the user
cmd=(dialog --separate-output --checklist "Select services to install:" 22 76 16)
options=(
    1 "Install BIND" off
    2 "Install ISC KEA" off
    3 "Install Cockpit" off
    4 "Install Webmin" off
    5 "Install ntopng" off
    6 "Install DDNS Client" off
    7 "Install required Packages" on
    8 "Install Suricata (Only Suricata Engine)" off
    9 "Install Elastic/Kibana/Filebeat (Dashboard for Suricata Events/Alerts)" off
    10 "Install RFWB Portscan detection"
)
choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)

clear

for choice in $choices; do
    case $choice in
    1)
        install_bind
        ;;
    2)
        install_isc_kea
        ;;
    3)
        install_cockpit
        ;;
    4)
        install_webmin
        ;;
    5)
        install_ntopng
        ;;
    6)
        install_ddclient
        ;;
    7)
        install_required
        ;;
    8)
        install_suricata
        ;;
    9)
        install_elastic
        ;;
   10)
        install_portscan
        ;;

    esac
done

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

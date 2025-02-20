# Function to install rfwb-portscan detection
install_portscan() {
    # Script to set up nftables for detecting and blocking port scans on Red Hat systems
    clear
    echo -e "Installing RFWB-Portscan Detection engine..."
    sleep 2

    # Ensure the script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi

    # Install nftables if not already installed
    if ! command -v nft &>/dev/null; then
        echo "Installing nftables..."
        yum install -y nftables
    fi

    # Create or update the configuration file for user settings
    CONFIG_FILE="/etc/rfwb-portscan.conf"
    if [ ! -f "$CONFIG_FILE" ]; then
        cat <<EOF >"$CONFIG_FILE"
# Configuration file for RFWB-Portscan service

# Maximum number of retries to obtain an external IP address. Set to 0 for infinite retries.
MAX_RETRIES=10

# Initial delay in seconds before retrying to obtain the external IP address.
INITIAL_DELAY=10

# Multiplier to increase the delay after each failed attempt (exponential backoff).
RETRY_MULTIPLIER=2

# Ports to monitor for port scan detection. Separate ports with commas.
MONITORED_PORTS="20, 21, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995"

# Timeout for dynamically blocked IPs. Use 's' for seconds, 'm' for minutes, 'h' for hours, 'd' for days.
# Set to '0' for no timeout (indefinitely).
BLOCK_TIMEOUT="30m"
EOF
    fi

    # Load configuration settings
    source "$CONFIG_FILE"

    # Ensure the hosts.blocked file exists
    BLOCKED_FILE="/etc/nftables/hosts.blocked"
    if [ ! -f "$BLOCKED_FILE" ]; then
        touch "$BLOCKED_FILE"
    fi

    # Ensure the ignore networks configuration file exists and populate with RFC 1918 networks
    IGNORE_NETWORKS_FILE="/etc/nftables/ignore_networks.conf"
    if [ ! -f "$IGNORE_NETWORKS_FILE" ]; then
        echo "Creating ignore networks configuration file with RFC 1918 networks."
        cat <<EOF >"$IGNORE_NETWORKS_FILE"
# Ignore file for rfwb-nft-portscan
# The port scan detection will ignore any IP addresses or networks placed into this file
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

    # Retry mechanism to get the external IP address with exponential backoff
    EXTERNAL_IP=""
    attempt=1
    delay=$INITIAL_DELAY

    while :; do
        EXTERNAL_IP=$(ip -4 addr show "$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
        if [[ -n "$EXTERNAL_IP" ]]; then
            break
        fi
        if [[ $MAX_RETRIES -ne 0 && $attempt -gt $MAX_RETRIES ]]; then
            echo "Error: Failed to determine the external IP address after $MAX_RETRIES attempts. Exiting."
            exit 1
        fi
        echo "Attempt $attempt: Could not determine the external IP address for interface $OUTSIDE_INTERFACE. Retrying in $delay seconds..."
        sleep "$delay"
        ((attempt++))
        delay=$((delay * RETRY_MULTIPLIER))
    done

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
    cat <<EOL >"$NFT_CONF_FILE"
table inet portscan {
  set dynamic_block {
    type ipv4_addr
    flags timeout
    timeout $BLOCK_TIMEOUT
EOL

     # Only add elements if there are IPs
    if [ -n "$ELEMENTS" ]; then
        cat <<EOL >>"$NFT_CONF_FILE"
    elements = { $ELEMENTS }
EOL
    fi

    cat <<EOL >>"$NFT_CONF_FILE"
  }

  chain input {
    type filter hook input priority 0; policy accept;

    # Allow established and related connections
    ct state established,related accept

    # Drop packets from dynamically blocked IPs
    ip saddr @dynamic_block drop

    # Detect SYN packets from untrusted sources on the outside interface
    iifname "$OUTSIDE_INTERFACE" tcp flags syn limit rate 10/minute log prefix "Port Scan Detected: " counter

    # Use configured ports for detection
    ip daddr $EXTERNAL_IP tcp dport { $MONITORED_PORTS } ct state new limit rate 3/minute log prefix "Port Scan Detected: " counter
  }
}
EOL

    # Pre-start script to log the outside interface and IP
    PRE_START_SCRIPT="/usr/local/bin/rfwb-portscan-prestart.sh"
    cat <<EOF >"$PRE_START_SCRIPT"
#!/bin/bash

# Configuration for retry mechanism
MAX_RETRIES=10
INITIAL_DELAY=5
RETRY_MULTIPLIER=2
LOG_FILE="/var/log/rfwb-portscan.log"

# Initialize log file
echo "Starting rfwb-portscan pre-start script at \$(date)" > "\$LOG_FILE"

OUTSIDE_INTERFACE=""
EXTERNAL_IP=""
attempt=1
delay=\$INITIAL_DELAY

while :; do
    OUTSIDE_INTERFACE=\$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="-outside" '\$2 ~ suffix {print \$1}')
    EXTERNAL_IP=\$(ip -4 addr show "\$OUTSIDE_INTERFACE" | grep -oP  '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

    # Log the current state
    echo "\$(date): Attempt \$attempt - Interface: \$OUTSIDE_INTERFACE, IP: \$EXTERNAL_IP" >> "\$LOG_FILE"

    # Check if nftables service is active
    if ! systemctl is-active --quiet nftables; then
        echo "\$(date): nftables service is not active. Waiting for nftables service..." >> "\$LOG_FILE"
        sleep "\$delay"
        ((attempt++))
        delay=\$((delay * RETRY_MULTIPLIER))
        continue
    fi

    if [[ -n "\$OUTSIDE_INTERFACE" && -n "\$EXTERNAL_IP" ]]; then
        echo "\$(date): Successfully determined interface and IP." >> "\$LOG_FILE"
        break
    fi

    if [[ \$attempt -ge \$MAX_RETRIES ]]; then
        echo "\$(date): Error: Could not determine the outside interface or external IP address after \$attempt attempts. Exiting." >> "\$LOG_FILE"
        exit 1
    fi

    echo "\$(date): Attempt \$attempt failed. Retrying in \$delay seconds..." >> "\$LOG_FILE"
    sleep "\$delay"
    ((attempt++))
    delay=\$((delay * RETRY_MULTIPLIER))
done

echo "\$(date): Starting service: Protecting outside interface: \$OUTSIDE_INTERFACE with IP: \$EXTERNAL_IP" >> "\$LOG_FILE"
logger "rfwb-portscan: Protecting outside interface: \$OUTSIDE_INTERFACE with IP: \$EXTERNAL_IP"
EOF

    # Make the pre-start script executable
    chmod +x "$PRE_START_SCRIPT"

    # Create a stop script to clean up nftables configuration
    STOP_SCRIPT="/usr/local/bin/rfwb-portscan-stop.sh"
    cat <<'EOF' >"$STOP_SCRIPT"
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

    # Create a custom handler script to manage start action
    HANDLER_SCRIPT="/usr/local/bin/rfwb-portscan-handler.sh"
    cat <<EOF >"$HANDLER_SCRIPT"
#!/bin/bash

# Source configuration file
CONFIG_FILE="/etc/rfwb-portscan.conf"
if [ -f "\$CONFIG_FILE" ]; then
    source "\$CONFIG_FILE"
else
    echo "Configuration file \$CONFIG_FILE not found. Using default settings."
fi

# Check if the script is called with a restart action
if [[ "\$1" == "restart" ]]; then
    echo "Error: Restart action is not supported. Please use systemctl start and stop verbs."
    exit 1
fi

OUTSIDE_INTERFACE="\$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="-outside" '\$2 ~ suffix {print \$1}')"
EXTERNAL_IP="\$(ip -4 addr show "\$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)"

if [[ -z "\$OUTSIDE_INTERFACE" || -z "\$EXTERNAL_IP" ]]; then
    echo "Error: Could not determine the outside interface or external IP address. Exiting."
    exit 1
fi

# Flush existing rules to prevent duplicates
if nft list tables | grep -q "inet portscan"; then
    nft delete table inet portscan
fi

# Regenerate nftables configuration file
NFT_CONF_FILE="/etc/nftables/portscan.conf"
cat <<EOL >"\$NFT_CONF_FILE"
table inet portscan {
  set dynamic_block {
    type ipv4_addr
    flags timeout
    timeout \$BLOCK_TIMEOUT
  }

  chain input {
    type filter hook input priority 0; policy accept;

    # Allow established and related connections
    ct state established,related accept

    # Drop packets from dynamically blocked IPs
    ip saddr @dynamic_block drop

    # Detect SYN packets from untrusted sources on the outside interface
    iifname "\$OUTSIDE_INTERFACE" tcp flags syn limit rate 10/minute log prefix "Port Scan Detected: " counter

    # Use configured ports for detection
    ip daddr \$EXTERNAL_IP tcp dport { \$MONITORED_PORTS } ct state new limit rate 3/minute log prefix "Port Scan Detected: " counter
  }
}
EOL

# Apply the new nftables configuration
/usr/sbin/nft -f "\$NFT_CONF_FILE"
EOF

    # Make the handler script executable
    chmod +x "$HANDLER_SCRIPT"

    # Create systemd service file
    SYSTEMD_SERVICE_FILE="/etc/systemd/system/rfwb-portscan.service"
    cat <<EOL  >"$SYSTEMD_SERVICE_FILE"
[Unit]
Description=Port Scan Detection Service
After=network-online.target

[Service]
ExecStartPre=$PRE_START_SCRIPT
ExecStart=$HANDLER_SCRIPT start
ExecStop=$STOP_SCRIPT
Type=oneshot
RemainAfterExit=yes
Restart=on-failure
RestartSec=10

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
            echo "$ip" >>"$BLOCKED_FILE"
            echo "Blocked IP $ip added to $BLOCKED_FILE"
            # Ensure the table and set are correctly initialized before adding elements
            if nft list tables | grep -q "inet portscan"; then
                nft add element inet portscan dynamic_block { $ip }
            else
                echo "Error: The portscan table or dynamic_block set is not initialized."
            fi
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

# Call the install function
install_portscan

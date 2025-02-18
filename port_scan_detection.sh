#!/bin/bash

# Script to set up nftables for detecting and blocking port scans on Red Hat systems

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

# Add rules for the external IP
cat <<EOL >> "$NFT_CONF_FILE"
    ip daddr $EXTERNAL_IP tcp dport { 21, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080 } ct state
 new limit rate 3/minute log prefix "Port Scan Detected: " counter
EOL

cat <<EOL >> "$NFT_CONF_FILE"
  }
}
EOL

# Create a stop script to clean up nftables configuration
STOP_SCRIPT="/usr/local/bin/nft-portscan-stop.sh"
cat <<'EOF' > "$STOP_SCRIPT"
#!/bin/bash
echo "Flushing and removing dynamic block set, and resetting hosts.blocked file."

# Flush and delete the dynamic block set
nft flush set inet portscan dynamic_block
nft delete set inet portscan dynamic_block

# Optionally, delete the entire table if you want to remove all configurations
nft delete table inet portscan

# Reset the hosts.blocked file
truncate -s 0 /etc/nftables/hosts.blocked

echo "Dynamic block and configurations have been removed."
EOF

# Make the stop script executable
chmod +x "$STOP_SCRIPT"

# Create systemd service file
SYSTEMD_SERVICE_FILE="/etc/systemd/system/nft-portscan.service"
cat <<EOL > "$SYSTEMD_SERVICE_FILE"
[Unit]
Description=Port Scan Detection Service
After=network.target

[Service]
ExecStart=/usr/sbin/nft -f /etc/nftables/portscan.conf
ExecStop=$STOP_SCRIPT
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable nft-portscan.service
systemctl start nft-portscan.service

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

echo "nftables port scan detection and blocking service has been installed and started for the outside interface."
echo "Blocked IPs are logged to $BLOCKED_FILE."

# Setup logging notifications
echo "Port scan events will be logged with the prefix 'Port Scan Detected:' in the system logs."
echo "To view these logs, you can use a command such as: journalctl -xe | grep 'Port Scan Detected'"

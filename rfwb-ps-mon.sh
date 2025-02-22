#!/bin/bash

# Define variables
SCRIPT_PATH="/usr/local/bin/rfwb-ps-mon.sh"
SERVICE_PATH="/etc/systemd/system/rfwb-ps-mon.service"
IGNORE_NETWORKS_FILE="/etc/nftables/ignore_networks.conf"
BLOCKED_FILE="/etc/nftables/hosts.blocked"

# Create the monitoring script
cat << EOF > $SCRIPT_PATH
#!/bin/bash

# Ensure these variables are set
IGNORE_NETWORKS_FILE="$IGNORE_NETWORKS_FILE"
BLOCKED_FILE="$BLOCKED_FILE"

# Read ignore networks into a variable
IGNORE_NETWORKS=\$(cat "\$IGNORE_NETWORKS_FILE")

# Function to append unique IPs to the blocked file, ignoring networks from ignore_networks.conf
append_blocked_ip() {
    local ip="\$1"
    for ignore_network in \$IGNORE_NETWORKS; do
        if ipcalc -c "\$ip" "\$ignore_network" >/dev/null 2>&1; then
            echo "Ignoring IP \$ip from scanning"
            return
        fi
    done
    if ! grep -q "^\$ip\$" "\$BLOCKED_FILE"; then
        echo "\$ip" >>"\$BLOCKED_FILE"
        echo "Blocked IP \$ip added to \$BLOCKED_FILE"
        # Ensure the table and set are correctly initialized before adding elements
        if nft list tables | grep -q "inet portscan"; then
            nft add element inet portscan dynamic_block { \$ip }
        else
            echo "Error: The portscan table or dynamic_block set is not initialized."
        fi
    fi
}

# Monitor logs and update dynamic block
journalctl -kf | while read -r line; do
    if [[ "\$line" == *"Port Scan Detected:"* ]]; then
        ip=\$(echo "\$line" | grep -o 'SRC=[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}' | cut -d '=' -f 2)
        if [[ -n "\$ip" ]]; then
            append_blocked_ip "\$ip"
        fi
    fi
done
EOF

# Make the script executable
chmod +x $SCRIPT_PATH

# Test the script manually
echo "Testing the script manually..."
$SCRIPT_PATH &
sleep 5
kill $!  # Terminate the test process

# Create the systemd service unit file
cat << EOF > $SERVICE_PATH
[Unit]
Description=RFWB Port Scan Monitor
After=rfwb-portscan.service
Requires=rfwb-portscan.service

[Service]
Type=simple
ExecStart=$SCRIPT_PATH
ExecStop=/bin/kill \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=rfwb-ps-mon

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd to recognize the new service
systemctl daemon-reload

# Enable the service to start on boot
systemctl enable rfwb-ps-mon.service

# Start the service
systemctl start rfwb-ps-mon.service

# Confirm the service status
echo "Verifying the service status..."
systemctl status rfwb-ps-mon.service

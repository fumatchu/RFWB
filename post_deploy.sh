#!/bin/bash

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
TEXTRESET="\033[0m"
clear

# Install and configure dnf-automatic for security updates only
echo -e "${GREEN}Configuring system for security updates only...${TEXTRESET}"

EPEL_CONFIG="/etc/dnf/automatic.conf"
BACKUP_CONFIG="/etc/dnf/automatic.conf.bak"
TIMER_CONFIG="/etc/systemd/system/dnf-automatic.timer.d/override.conf"

echo -e "[${YELLOW}INFO${TEXTRESET}] Backing up the current dnf-automatic configuration..."
sudo cp "$EPEL_CONFIG" "$BACKUP_CONFIG"

echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring dnf-automatic for security updates..."
sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' "$EPEL_CONFIG"
sudo sed -i 's/^apply_updates.*/apply_updates = yes/' "$EPEL_CONFIG"

# Ensure the override directory exists
sudo mkdir -p /etc/systemd/system/dnf-automatic.timer.d

# Set the update time to 3 AM
echo -e "[${YELLOW}INFO${TEXTRESET}] Setting dnf-automatic to run at 3:00 AM..."
echo -e "[Timer]\nOnCalendar=*-*-* 03:00:00" | sudo tee "$TIMER_CONFIG" > /dev/null

# Reload systemd and restart the timer
echo -e "[${YELLOW}INFO${TEXTRESET}] Reloading systemd and restarting dnf-automatic.timer..."
sudo systemctl daemon-reload
sudo systemctl enable --now dnf-automatic.timer

# Validate the configuration
echo -e "[${YELLOW}INFO${TEXTRESET}] Validating configuration..."
CONFIG_CHECK=$(grep -E 'upgrade_type|apply_updates' "$EPEL_CONFIG")

if echo "$CONFIG_CHECK" | grep -q "apply_updates = yes"; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] dnf-automatic is correctly configured to apply security updates."
else
    echo -e "[${RED}ERROR${TEXTRESET}] Configuration failed! Check $EPEL_CONFIG manually."
    exit 1
fi

# Validate the timer status
echo -e "[${YELLOW}INFO${TEXTRESET}] Checking dnf-automatic.timer status..."
if systemctl is-active --quiet dnf-automatic.timer; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] dnf-automatic.timer is running."
else
    echo -e "[${RED}ERROR${TEXTRESET}] dnf-automatic.timer is NOT running! Check logs: journalctl -u dnf-automatic.timer"
    exit 1
fi

# Validate the new update time
echo -e "[${YELLOW}INFO${TEXTRESET}] Checking the scheduled update time..."
if systemctl show dnf-automatic.timer | grep -q "OnCalendar=.*03:00:00"; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] dnf-automatic is scheduled to run at 3:00 AM."
else
    echo -e "[${RED}ERROR${TEXTRESET}] Failed to set the update time! Check $TIMER_CONFIG."
    exit 1
fi

echo -e "[${YELLOW}INFO${TEXTRESET}] dnf-automatic setup is complete."
sleep 4

# Update /etc/issue for login information
sudo bash -c 'cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF'

clear
# Setup DNS
echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring Inside interface for DNS Resolution."
sleep 4

# Function to manage inside interfaces and update DNS settings
manage_inside_dns() {
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')
    if [ -z "$main_interface" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No interface ending with '-inside' found."
        exit 1
    fi
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Main inside interface found: $main_interface"

    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No connections found for interface: $main_interface and its sub-interfaces."
        exit 1
    fi

    if systemctl is-active --quiet named; then
        dns_servers="127.0.0.1 208.67.222.222 208.67.220.220"
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Using DNS servers: $dns_servers [${YELLOW}named is active${TEXTRESET}]"
    else
        dns_servers="208.67.222.222 208.67.220.220"
        echo -e "[${YELLOW}INFO${TEXTRESET}] Using DNS servers: $dns_servers [${YELLOW}named is not active${TEXTRESET}]"
    fi
    sleep 2

    for connection_name in $connection_names; do
        echo -e "[${YELLOW}INFO${TEXTRESET}] Processing connection: ${GREEN}$connection_name${TEXTRESET}"
        nmcli connection modify "$connection_name" ipv4.dns ""
        echo -e "[${YELLOW}INFO${TEXTRESET}] Cleared existing DNS settings for connection: $connection_name"
        nmcli connection modify "$connection_name" ipv4.dns "$dns_servers"
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Set new DNS servers for connection: $connection_name"
    done
    sleep 4
}

manage_inside_dns

# Setup startup scripts in rc.local
clear
echo -e "${GREEN}Installing Startup scripts to rc.local...${TEXTRESET}"
sleep 4

#Add the Kea delay start and FW delay start (if needed) on boot

SRC_SCRIPT1="/root/RFWB/kea_delay_start.sh"
DEST_SCRIPT1="/opt/kea_delay_start.sh"
SRC_SCRIPT2="/root/RFWB/fw_delay_start.sh"
DEST_SCRIPT2="/opt/fw_delay_start.sh"
RC_LOCAL="/etc/rc.d/rc.local"

# Check and copy scripts
if [ ! -f "$SRC_SCRIPT1" ] || [ ! -f "$SRC_SCRIPT2" ]; then
    echo -e "[${RED}ERROR${TEXTRESET}] One or more source scripts do not exist. Exiting."
    exit 1
fi

echo -e "[${YELLOW}INFO${TEXTRESET}] Copying startup scripts to /opt..."
sudo cp "$SRC_SCRIPT1" "$DEST_SCRIPT1"
sudo cp "$SRC_SCRIPT2" "$DEST_SCRIPT2"
sudo chmod +x "$DEST_SCRIPT1" "$DEST_SCRIPT2"
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Scripts copied and made executable."

# Setup rc.local
if [ ! -f "$RC_LOCAL" ]; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Creating rc.local file..."
    sudo touch "$RC_LOCAL"
fi
sudo chmod +x "$RC_LOCAL"
echo -e "[${GREEN}SUCCESS${TEXTRESET}] rc.local is set up and executable."

# Add scripts to rc.local
if ! grep -q "$DEST_SCRIPT1" "$RC_LOCAL"; then
    echo "$DEST_SCRIPT1" | sudo tee -a "$RC_LOCAL" >/dev/null
    echo -e "[${YELLOW}INFO${TEXTRESET}] Added $DEST_SCRIPT1 to rc.local."
fi
if ! grep -q "$DEST_SCRIPT2" "$RC_LOCAL"; then
    echo "$DEST_SCRIPT2" | sudo tee -a "$RC_LOCAL" >/dev/null
    echo -e "[${YELLOW}INFO${TEXTRESET}] Added $DEST_SCRIPT2 to rc.local."
fi

# Enable and start rc-local service
if ! systemctl is-enabled rc-local.service &>/dev/null; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling rc-local service..."
    sudo ln -s "$RC_LOCAL" /etc/rc.local
    sudo systemctl enable rc-local
fi

if ! systemctl is-active rc-local.service &>/dev/null; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Starting rc-local service..."
    sudo systemctl start rc-local
fi

echo -e "[${GREEN}SUCCESS${TEXTRESET}] Setup complete. The scripts $DEST_SCRIPT1 and $DEST_SCRIPT2 will run at startup."
sleep 4


# Manage inside gateway entries
clear
echo -e "[${YELLOW}INFO${TEXTRESET}] Updating the Inside Gateway Entries..."
sleep 4

manage_inside_gw() {
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')
    if [ -z "$main_interface" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No interface ending with '-inside' found."
        exit 1
    fi
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Main inside interface found: $main_interface"

    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No connections found for interface: $main_interface and its sub-interfaces."
        exit 1
    fi

    for connection_name in $connection_names; do
        echo -e "[${YELLOW}INFO${TEXTRESET}] Processing connection: ${GREEN}$connection_name${TEXTRESET}"
        nmcli connection modify "$connection_name" ipv4.gateway ""
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Removed gateway for connection: $connection_name"
    done
}

manage_inside_gw
sleep 4

#!/bin/bash

NFTABLES_FILE="/etc/sysconfig/nftables.conf"
TMP_FILE=$(mktemp)
DEBUG_FILE="/tmp/nftables_debug.conf"

# Backup original nftables configuration
cp "$NFTABLES_FILE" "$NFTABLES_FILE.bak"
echo -e  "[${YELLOW}INFO${TEXTRESET}] Backed up original file to: ${GREEN}$NFTABLES_FILE.bak${TEXTRESET}"

# Function to check if a service is installed
service_is_installed() {
    systemctl list-unit-files | grep -q "^$1.service"
}

# Function to check if a service is running
service_is_running() {
    systemctl is-active --quiet "$1"
}

# Track if rfwb-portscan was running before stopping it
PORTSCAN_WAS_RUNNING=false

# Step 1: Check if rfwb-portscan is installed
if service_is_installed "rfwb-portscan"; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] rfwb-portscan is installed."

    # Step 2: Check if rfwb-portscan is running
    if service_is_running "rfwb-portscan"; then
        echo "Stopping rfwb-portscan..."
        systemctl stop rfwb-portscan
        PORTSCAN_WAS_RUNNING=true
        sleep 2  # Allow time for rfwb-ps-mon to stop automatically
    else
        echo ""
    fi
else
    echo ""
fi


echo -e "[${YELLOW}INFO${TEXTRESET}] Reorganizing nftables rules for efficiency..."
# Step 1: Remove all instances of the outbound block rule from the chain output
sed -i '/chain output {/,/}/ {/ip daddr @threat_block log prefix "Outbound Blocked:" drop/d;}' "$NFTABLES_FILE"
sed -i '/chain output {/,/}/ {/ip daddr @threat_block log prefix "Outbound Blocked: " drop/d;}' "$NFTABLES_FILE"

# Step 2: Process the nftables configuration with awk
awk '
  BEGIN {
    in_input = 0;
    in_output = 0;
    in_portscan = 0;
    input_header = "";
    output_header = "";
    input_rules = "";
    output_rules = "";
    input_policy = "    type filter hook input priority filter; policy drop;";
    output_policy = "    type filter hook output priority filter; policy accept;";
    threat_rule = "    ip saddr @threat_block drop";  # Always at the top of input chain
    log_rule = "    log prefix \"Blocked:\" drop";  # Always at the bottom of input chain
    threat_out_rule = "    ip daddr @threat_block log prefix \"Outbound Blocked:\" drop";  # Ensure correct format
    threat_out_seen = 0;
  }

  /table inet portscan/ {
    in_portscan = 1;
  }

  /chain input/ && !in_portscan {
    in_input = 1;
    input_header = $0;
    input_rules = "";
    next;
  }
  
  /chain output/ {
    in_output = 1;
    output_header = $0;
    output_rules = "";
    next;
  }

  in_input && /}/ {
    in_input = 0;
    print input_header;
    print input_policy;
    print threat_rule;
    print input_rules;
    print log_rule;
    print "}";
    next;
  }

  in_input {
    if ($0 ~ /ip saddr @threat_block drop/ || $0 ~ /log prefix "Blocked:/ || $0 ~ /type filter hook input priority filter; policy/) {
      next;
    } else {
      input_rules = input_rules "\n" $0;
    }
    next;
  }

  in_output && /}/ {
    in_output = 0;
    print output_header;
    print output_policy;
    if (!threat_out_seen) {
      print threat_out_rule;
      threat_out_seen = 1;
    }
    print output_rules;
    print "}";
    next;
  }

  in_output {
    if ($0 ~ /ip daddr @threat_block log prefix "Outbound Blocked: "/ || $0 ~ /type filter hook output priority filter; policy/) {
      next;
    } else {
      output_rules = output_rules "\n" $0;
    }
    next;
  }

  { print }
' "$NFTABLES_FILE" > "$TMP_FILE"

# Save debug file before applying changes
cp "$TMP_FILE" "$DEBUG_FILE"
echo "Modified nftables configuration saved to: $DEBUG_FILE"

# Replace original file with updated rules
mv "$TMP_FILE" "$NFTABLES_FILE"

# Restore original ownership and permissions
chown --reference="$NFTABLES_FILE.bak" "$NFTABLES_FILE"
chmod --reference="$NFTABLES_FILE.bak" "$NFTABLES_FILE"

# Fix SELinux context
restorecon -v "$NFTABLES_FILE"

# Validate configuration
if nft -c -f "$NFTABLES_FILE"; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables configuration is valid. Reloading..."
    systemctl restart nftables
else
    echo -e "[${RED}ERROR${TEXTRESET}] nftables configuration test failed! Restoring previous config."
    cp "$NFTABLES_FILE.bak" "$NFTABLES_FILE"
    systemctl restart nftables
    echo "🔍 Check debug output in: $DEBUG_FILE"
fi


# Step 3: Restart services if rfwb-portscan was stopped
if [[ "$PORTSCAN_WAS_RUNNING" == true ]]; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Restarting rfwb-portscan..."
    systemctl start rfwb-portscan
    sleep 2
fi

# Ensure both services are running at the end

# Start rfwb-portscan if installed and not running
if service_is_installed "rfwb-portscan" && ! service_is_running "rfwb-portscan"; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] rfwb-portscan was not running. Attempting to start..."
    systemctl start rfwb-portscan
fi

# Start rfwb-ps-mon if installed and not running
if service_is_installed "rfwb-ps-mon" && ! service_is_running "rfwb-ps-mon"; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] rfwb-ps-mon was not running. Attempting to start..."
    systemctl start rfwb-ps-mon
fi

# Final verification
echo "🔍 Verifying service status..."

if service_is_installed "rfwb-portscan"; then
    if service_is_running "rfwb-portscan"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] rfwb-portscan is running."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] rfwb-portscan is NOT running!"
    fi
fi

if service_is_installed "rfwb-ps-mon"; then
    if service_is_running "rfwb-ps-mon"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] rfwb-ps-mon is running."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] rfwb-ps-mon is NOT running!"
    fi
fi
sleep 4

#Make sure rtp-linux is not in the dnf makecache
EPEL_REPO="/etc/yum.repos.d/epel.repo"

echo -e "[${YELLOW}INFO${TEXTRESET}] Checking for 'rtp-linux.cisco.com' in the EPEL repository configuration..."

# Check if rtp-linux.cisco.com is still referenced
if dnf repoinfo epel | grep -q "rtp-linux.cisco.com"; then
    echo -e "[${RED}WARNING${TEXTRESET}] Custom Cisco EPEL mirror detected! Updating repository settings..."

    # Force override to the official Fedora EPEL mirror
    sudo dnf config-manager --setopt=epel.baseurl=https://download.fedoraproject.org/pub/epel/9/Everything/x86_64/ --save
    echo -e "[${YELLOW}INFO${TEXTRESET}] Updated EPEL repository to use Fedora mirrors."

    # Clean and rebuild DNF cache
    echo -e "[${YELLOW}INFO${TEXTRESET}] Cleaning DNF cache..."
    sudo dnf clean all
    echo -e "[${YELLOW}INFO${TEXTRESET}] Rebuilding DNF cache..."
    sudo dnf makecache

    # Validate the change
    echo -e "[${YELLOW}INFO${TEXTRESET}] Validating EPEL repository update..."
    if dnf repoinfo epel | grep -q "rtp-linux.cisco.com"; then
        echo -e "[${RED}ERROR${TEXTRESET}] EPEL repository update failed. Please check $EPEL_REPO manually."
        exit 1
    else
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] EPEL repository updated successfully! Cisco mirror removed."
    fi
else
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] No reference to 'rtp-linux.cisco.com' found in EPEL. No changes needed."
fi


# Notify and handle firewall restart
echo "Firewall setup complete."
read -p "Do you want to restart the firewall now? (yes/no): " user_choice
if [[ "$user_choice" == "yes" ]]; then
    echo "Restarting the firewall..."
    sudo reboot
elif [[ "$user_choice" == "no" ]]; then
    echo "The firewall will not be restarted now."
else
    echo "Invalid choice. Please run the script again and select either 'yes' or 'no'."
fi

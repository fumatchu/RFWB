#!/bin/bash

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
TEXTRESET="\033[0m"

#Install dnf-auomatic and lock down 
echo -e ${GREEN}Configuring system for security updates only${TEXTRESET}"
# Install dnf-automatic
sudo dnf -y install dnf-automatic

# Backup the existing automatic.conf file
sudo cp /etc/dnf/automatic.conf /etc/dnf/automatic.conf.bak

# Edit the automatic.conf to set upgrade_type to security
sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf

# Enable and start the dnf-automatic.timer to apply security updates automatically
sudo systemctl enable --now dnf-automatic.timer

echo -e "${GREEN}dnf-automatic is installed and configured to apply only security updates.${TEXTRESET}"
sleep 4 

#Update /etc/issue so we can see the hostname and IP address Before logging in
rm -r -f /etc/issue
touch /etc/issue
cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF

#SETUP DNS
# Function to manage inside interfaces and update DNS settings
manage_inside_dns() {
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
manage_inside_dns

#Move the IP EKF Check for Startup
# Move the IP EKF Check for Startup
# Define paths
SRC_SCRIPT1="/root/RFWB/check_ip_EKF.sh"
DEST_SCRIPT1="/opt/check_ip_EKF.sh"
SRC_SCRIPT2="/root/RFWB/fw_delay_start.sh"
DEST_SCRIPT2="/opt/fw_delay_start.sh"
RC_LOCAL="/etc/rc.d/rc.local"

# Check if the source scripts exist
if [ ! -f "$SRC_SCRIPT1" ]; then
    echo "Source script $SRC_SCRIPT1 does not exist. Exiting."
    exit 1
fi

if [ ! -f "$SRC_SCRIPT2" ]; then
    echo "Source script $SRC_SCRIPT2 does not exist. Exiting."
    exit 1
fi

# Copy the scripts to /opt/
echo "Copying $SRC_SCRIPT1 to $DEST_SCRIPT1..."
sudo cp "$SRC_SCRIPT1" "$DEST_SCRIPT1"

echo "Copying $SRC_SCRIPT2 to $DEST_SCRIPT2..."
sudo cp "$SRC_SCRIPT2" "$DEST_SCRIPT2"

# Ensure the scripts are executable
echo "Ensuring $DEST_SCRIPT1 is executable..."
sudo chmod +x "$DEST_SCRIPT1"

echo "Ensuring $DEST_SCRIPT2 is executable..."
sudo chmod +x "$DEST_SCRIPT2"

# Check if rc.local exists
if [ ! -f "$RC_LOCAL" ]; then
    echo "Creating $RC_LOCAL..."
    sudo touch "$RC_LOCAL"
fi

# Ensure rc.local is executable
echo "Ensuring $RC_LOCAL is executable..."
sudo chmod +x "$RC_LOCAL"

# Add the scripts to rc.local if not already present
if ! grep -q "$DEST_SCRIPT1" "$RC_LOCAL"; then
    echo "Adding $DEST_SCRIPT1 to $RC_LOCAL..."
    echo "$DEST_SCRIPT1" | sudo tee -a "$RC_LOCAL" >/dev/null
fi

if ! grep -q "$DEST_SCRIPT2" "$RC_LOCAL"; then
    echo "Adding $DEST_SCRIPT2 to $RC_LOCAL..."
    echo "$DEST_SCRIPT2" | sudo tee -a "$RC_LOCAL" >/dev/null
fi

# Check if rc-local service is enabled
if ! systemctl is-enabled rc-local.service &>/dev/null; then
    echo "Enabling rc-local service..."

    # Create symbolic link if necessary (for compatibility)
    if [ ! -L /etc/rc.local ]; then
        sudo ln -s "$RC_LOCAL" /etc/rc.local
    fi

    # Enable the service
    sudo systemctl enable rc-local
fi

# Start the rc-local service if not already running
if ! systemctl is-active rc-local.service &>/dev/null; then
    echo "Starting rc-local service..."
    sudo systemctl start rc-local
fi

# Status of the rc-local service
echo "Checking status of rc-local service..."
systemctl status rc-local

echo "Setup complete. The scripts $DEST_SCRIPT1 and $DEST_SCRIPT2 will run at startup."
sleep 4

# Function to manage inside interfaces and remove gateway entries
echo -e "${GREEN}Updating the Gateways.. removing INSIDE interface Gateway entries.${TEXTRESET}"
sleep 4
manage_inside_gw() {
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
sleep 4
# Execute the function
manage_inside_gw

#Set Avahi on the inside interfaces
clear
echo -e "${GREEN}Configuring and installing Avahi...${TEXTRESET}"
sleep 4
# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Function to find sub-interfaces based on main interface
find_sub_interfaces() {
    local main_interface="$1"
    nmcli -t -f DEVICE device status | grep -E "^${main_interface}\.[0-9]+" | awk '{print $1}'
}

# Find inside and outside interfaces
INSIDE_INTERFACE=$(find_interface "-inside")
OUTSIDE_INTERFACE=$(find_interface "-outside")

echo -e "${GREEN}Inside interface: $INSIDE_INTERFACE${TEXTRESET}"
echo -e "${GREEN}Outside interface: $OUTSIDE_INTERFACE${TEXTRESET}"

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# Install Avahi and Avahi Tools
echo -e "${YELLOW}Installing Avahi and Avahi Tools...${TEXTRESET}"
sudo yum install -y avahi avahi-tools

# Configure Avahi to enable mDNS reflection on internal interfaces
echo -e "${YELLOW}Configuring Avahi to enable mDNS reflection...${TEXTRESET}"
# Backup existing configuration
sudo cp /etc/avahi/avahi-daemon.conf /etc/avahi/avahi-daemon.conf.bak

# Create a list of interfaces for Avahi to listen on
INTERFACES="$INSIDE_INTERFACE"
for sub_interface in $SUB_INTERFACES; do
    INTERFACES+=",${sub_interface}"
done

# Modify Avahi configuration
sudo bash -c "cat > /etc/avahi/avahi-daemon.conf <<EOL
[server]
use-ipv4=yes
use-ipv6=yes
allow-interfaces=$INTERFACES

[reflector]
enable-reflector=yes
EOL"

# Start and enable Avahi service
echo -e "${YELLOW}Starting and enabling Avahi service...${TEXTRESET}"
sudo systemctl start avahi-daemon
sudo systemctl enable avahi-daemon

# Configure nftables to allow mDNS traffic on internal interfaces only
echo -e "${YELLOW}Configuring nftables to allow mDNS traffic...${TEXTRESET}"
# Ensure nftables table and chain exist
sudo nft add table inet filter 2>/dev/null
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null

# Allow mDNS traffic on internal interfaces
sudo nft add rule inet filter input iif "$INSIDE_INTERFACE" udp dport 5353 accept
for sub_interface in $SUB_INTERFACES; do
    sudo nft add rule inet filter input iif "$sub_interface" udp dport 5353 accept
done

# Save the current ruleset
echo -e "${YELLOW}Saving the current nftables ruleset...${TEXTRESET}"
sudo nft list ruleset >/etc/sysconfig/nftables.conf

# Enable and start nftables service to ensure configuration is loaded on boot
echo -e "${YELLOW}Enabling nftables service...${TEXTRESET}"
sudo systemctl enable nftables
sudo systemctl start nftables

echo -e "${GREEN}Setup complete. Avahi is configured for mDNS reflection on internal interfaces, and nftables are configured to allow mDNS traffic only on those interfaces.${TEXTRESET}"
sleep 4


#Reorganize nftables to best practice for input chain 
echo -e "${GREEN}Organizing nftables for efficiency prcoessing${TEXTRESET}"
sleep 4
# Define variables for file paths
NFTABLES_FILE="/etc/sysconfig/nftables.conf"  # The actual nftables file path
BACKUP_FILE="/etc/sysconfig/nftables.conf.bak"  # Backup file path
TMP_FILE="/tmp/nftables_chain_input_filtered.tmp"  # Temporary file to store extracted information

# Backup the original nftables file
cp "$NFTABLES_FILE" "$BACKUP_FILE"
echo "Backup created at $BACKUP_FILE."

# Extract, rearrange, and save the specific 'input' chain content
awk '
  BEGIN {
    # Define priorities for specific lines to rearrange
    rule_order["type filter hook input priority filter; policy drop;"] = 1
    rule_order["iif \"lo\" accept"] = 2
    rule_order["ct state established,related accept"] = 3
  }
  /chain input/ {in_block=1; block=""; next}
  in_block && /}/ {
    if (block ~ /log prefix "Blocked: " drop/) {
      split(block, lines, "\n")
      # Process each line
      for (i in lines) {
        trimmed = lines[i]
        sub(/^[ \t]+/, "", trimmed)  # Trim leading whitespace
        sub(/\r$/, "", trimmed)  # Remove carriage returns if present
        if (trimmed == "") continue  # Skip empty lines
        if (rule_order[trimmed] > 0) {
          ordered_rules[rule_order[trimmed]] = trimmed
        } else if (trimmed ~ /ip saddr @threat_block drop/) {
          ip_saddr_line = trimmed
        } else if (trimmed ~ /log prefix "Blocked: " drop/) {
          log_prefix_line = trimmed
        } else {
          other_rules[++other_rules_count] = trimmed
        }
      }
      # Construct the new block with formatting
      formatted_block = "\tchain input {\n"
      for (i = 1; i <= length(ordered_rules); i++) {
        formatted_block = formatted_block "\t\t" ordered_rules[i] "\n"
      }
      for (i = 1; i <= other_rules_count; i++) {
        formatted_block = formatted_block "\t\t" other_rules[i] "\n"
      }
      if (ip_saddr_line) formatted_block = formatted_block "\t\t" ip_saddr_line "\n"
      if (log_prefix_line) formatted_block = formatted_block "\t\t" log_prefix_line "\n"
      formatted_block = formatted_block "\t}"

      print formatted_block
    }
    exit
  }
  in_block {block=block "\n" $0}
' "$NFTABLES_FILE" > "$TMP_FILE"

# Replace the original block with the rearranged and formatted content in the nftables.conf file
awk -v RS= -v ORS='\n\n' -v new_block="$(cat $TMP_FILE)" '
  /chain input.*{/,/}/ {
    if ($0 ~ /log prefix "Blocked: " drop/) {
      $0 = new_block
    }
  }
  { print }
' "$BACKUP_FILE" > "$NFTABLES_FILE"

echo "Reformatted content has been placed back into $NFTABLES_FILE."
sleep 4
clear
# Notify the user that the firewall setup is complete
echo "Firewall setup complete."

# Prompt the user to choose whether to restart the firewall
read -p "Do you want to restart the firewall now? (yes/no): " user_choice

# Check the user's input
if [[ "$user_choice" == "yes" ]]; then
    echo "Restarting the firewall..."
    # Issue the reboot command
    sudo reboot
elif [[ "$user_choice" == "no" ]]; then
    echo "The firewall will not be restarted now."
else
    echo "Invalid choice. Please run the script again and select either 'yes' or 'no'."
fi

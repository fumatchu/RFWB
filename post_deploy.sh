#!/bin/bash

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
TEXTRESET="\033[0m"

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

#SETUP the FW ALLOW all inside interfaces and subinterfaces to talk and allow all of them Internet access
# Find inside and outside interfaces
INSIDE_INTERFACE=$(find_interface "-inside")
OUTSIDE_INTERFACE=$(find_interface "-outside")

echo -e "${GREEN}Inside interface: $INSIDE_INTERFACE${TEXTRESET}"
echo -e "${GREEN}Outside interface: $OUTSIDE_INTERFACE${TEXTRESET}"

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# Enable IP forwarding
echo -e "${YELLOW}Enabling IP forwarding...${TEXTRESET}"
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Apply nftables ruleset
echo -e "${YELLOW}Applying nftables ruleset...${TEXTRESET}"

# Create and configure the inet filter table if not exists
sudo nft add table inet filter 2>/dev/null

# Ensure the input chain policy is set to drop
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null

# Allow all traffic on the loopback interface
sudo nft add rule inet filter input iif lo accept

# Allow established and related connections on the input chain
sudo nft add rule inet filter input ct state established,related accept

# Allow inbound traffic on the inside interface(s)
sudo nft add rule inet filter input iif "$INSIDE_INTERFACE" accept
for sub_interface in $SUB_INTERFACES; do
    echo -e "${YELLOW}Allowing inbound traffic for sub-interface: $sub_interface${TEXTRESET}"
    sudo nft add rule inet filter input iif "$sub_interface" accept
done

# Allow SSH on the outside interface
sudo nft add rule inet filter input iif "$OUTSIDE_INTERFACE" tcp dport 22 accept

# Create and configure the forward chain with drop policy
sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; } 2>/dev/null

# Allow established and related connections on the forward chain
sudo nft add rule inet filter forward ct state established,related accept

# Allow forwarding between inside interface and its sub-interfaces
sudo nft add rule inet filter forward iif "$INSIDE_INTERFACE" oif "$INSIDE_INTERFACE" accept
for sub_interface in $SUB_INTERFACES; do
    sudo nft add rule inet filter forward iif "$INSIDE_INTERFACE" oif "$sub_interface" accept
    sudo nft add rule inet filter forward iif "$sub_interface" oif "$INSIDE_INTERFACE" accept
    sudo nft add rule inet filter forward iif "$sub_interface" oif "$sub_interface" accept
done

# Allow forwarding from inside to outside
sudo nft add rule inet filter forward iif "$INSIDE_INTERFACE" oif "$OUTSIDE_INTERFACE" accept
for sub_interface in $SUB_INTERFACES; do
    sudo nft add rule inet filter forward iif "$sub_interface" oif "$OUTSIDE_INTERFACE" accept
done

# Create and configure the inet nat table
sudo nft add table ip nat 2>/dev/null
sudo nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null
sudo nft add rule ip nat postrouting oif "$OUTSIDE_INTERFACE" masquerade

# Log and drop unsolicited incoming traffic on the outside interface
echo -e "${YELLOW}Logging and blocking unsolicited incoming traffic on the outside interface...${TEXTRESET}"
sudo nft add rule inet filter input iif "$OUTSIDE_INTERFACE" log prefix "\"Blocked: \"" drop

echo -e "${GREEN}nftables ruleset applied successfully.${TEXTRESET}"

# Save the current ruleset
echo -e "${YELLOW}Saving the current nftables ruleset...${TEXTRESET}"
sudo nft list ruleset > /etc/sysconfig/nftables.conf

# Enable and start nftables service to ensure configuration is loaded on boot
echo -e "${YELLOW}Enabling nftables service...${TEXTRESET}"
sudo systemctl enable nftables
sudo systemctl start nftables

echo -e "${GREEN}nftables ruleset applied and saved successfully.${TEXTRESET}"


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
    echo "$DEST_SCRIPT1" | sudo tee -a "$RC_LOCAL" > /dev/null
fi

if ! grep -q "$DEST_SCRIPT2" "$RC_LOCAL"; then
    echo "Adding $DEST_SCRIPT2 to $RC_LOCAL..."
    echo "$DEST_SCRIPT2" | sudo tee -a "$RC_LOCAL" > /dev/null
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
# Function to manage inside interfaces and remove gateway entries
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

# Execute the function
manage_inside_gw

#Set Avahi on the inside interfaces 
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
sudo nft list ruleset > /etc/sysconfig/nftables.conf

# Enable and start nftables service to ensure configuration is loaded on boot
echo -e "${YELLOW}Enabling nftables service...${TEXTRESET}"
sudo systemctl enable nftables
sudo systemctl start nftables

echo -e "${GREEN}Setup complete. Avahi is configured for mDNS reflection on internal interfaces, and nftables are configured to allow mDNS traffic only on those interfaces.${TEXTRESET}"

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

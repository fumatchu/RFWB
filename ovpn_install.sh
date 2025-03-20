#!/bin/bash

# OpenVPN Installation Script for Rocky Linux 9
# This script installs and configures OpenVPN following the user's specifications

set -e  # Exit immediately if any command fails

# Install EPEL repository
echo "Installing EPEL repository..."
sudo dnf install epel-release -y

# Install OpenVPN
echo "Installing OpenVPN..."
sudo dnf install openvpn -y

# Install Easy-RSA
echo "Installing Easy-RSA..."
sudo dnf install easy-rsa -y

# Create Easy-RSA directory
echo "Creating Easy-RSA directory..."
sudo mkdir /etc/openvpn/easy-rsa

# Create a symbolic link for Easy-RSA
echo "Creating symbolic link for Easy-RSA..."
sudo ln -s /usr/share/easy-rsa /etc/openvpn/easy-rsa

# Change directory to Easy-RSA
echo "Changing directory to Easy-RSA..."
cd /etc/openvpn/easy-rsa

# Get the static hostname
STATIC_HOSTNAME=$(hostnamectl | grep "Static hostname" | awk '{print $3}' | cut -d '.' -f1)
echo "Using static hostname as Common Name (CN): $STATIC_HOSTNAME"

# Initialize the Public Key Infrastructure (PKI)
echo "Initializing PKI..."
sudo ./easy-rsa/3/easyrsa init-pki

# Build the Certificate Authority (CA) with automated Common Name
echo "Building the Certificate Authority (CA) with hostname as CN..."
sudo EASYRSA_BATCH=1 EASYRSA_REQ_CN="$STATIC_HOSTNAME" ./easy-rsa/3/easyrsa build-ca nopass

# Generate a certificate request for the server without a password, using the static hostname as CN
echo "Generating server certificate request with hostname as CN..."
sudo EASYRSA_BATCH=1 EASYRSA_REQ_CN="$STATIC_HOSTNAME" ./easy-rsa/3/easyrsa gen-req server nopass

# Sign the server certificate request automatically (without user confirmation)
echo "Signing the server certificate request..."
echo "yes" | sudo ./easy-rsa/3/easyrsa sign-req server server

# Generate Diffie-Hellman (DH) parameters
echo "Generating Diffie-Hellman parameters..."
sudo ./easy-rsa/3/easyrsa gen-dh

# Copy the sample OpenVPN server configuration to the correct directory
echo "Copying OpenVPN sample configuration..."
sudo cp /usr/share/doc/openvpn/sample/sample-config-files/server.conf /etc/openvpn/server/

# Update certificate and key paths
echo "Updating OpenVPN certificate and key paths..."
sudo sed -i '75,81s|^ca .*|ca /etc/openvpn/easy-rsa/pki/ca.crt|' /etc/openvpn/server/server.conf
sudo sed -i '75,81s|^cert .*|cert /etc/openvpn/easy-rsa/pki/issued/server.crt|' /etc/openvpn/server/server.conf
sudo sed -i '75,81s|^key .*|key /etc/openvpn/easy-rsa/pki/private/server.key|' /etc/openvpn/server/server.conf

# Update DH file path
sudo sed -i '80,85s|^dh .*|dh /etc/openvpn/easy-rsa/pki/dh.pem|' /etc/openvpn/server/server.conf

# Disable tls-auth
sudo sed -i '240,244s|^tls-auth ta.key 0 # This file is secret|#tls-auth ta.key 0 # This file is secret|' /etc/openvpn/server/server.conf

# Insert route
sudo sed -i '143i push "route 0.0.0.0 0.0.0.0"\n' /etc/openvpn/server/server.conf

# Uncomment user nobody and group nobody
sudo sed -i 's/^;user nobody/user nobody/' /etc/openvpn/server/server.conf
sudo sed -i 's/^;group nobody/group nobody/' /etc/openvpn/server/server.conf

# Check if named service is running for custom DNS
if sudo systemctl is-active --quiet named; then
    read -p "Enter the primary DNS IP for OpenVPN clients: " DNS_IP
    sudo sed -i '/push "dhcp-option DNS 208.67.222.222"/i push "dhcp-option DNS '"$DNS_IP"'"' /etc/openvpn/server/server.conf
    echo "$DNS_IP" | sudo tee /etc/openvpn/primary_dns > /dev/null
fi

# Set SELinux permissions
sudo setsebool -P openvpn_enable_homedirs on
sudo restorecon -Rv /etc/openvpn

# Enable and start OpenVPN
sudo systemctl enable openvpn-server@server
sudo systemctl start openvpn-server@server

# Check OpenVPN service status
if sudo systemctl is-active --quiet openvpn-server@server; then
    echo "OpenVPN server is running successfully!"
else
    echo "OpenVPN server failed to start. Check logs with: sudo journalctl -u openvpn-server@server --no-pager -n 50"
fi

clear 
echo "Select your interface(s) to pass VPN traffic on the firewall"

# OpenVPN Firewall Configuration Script for nftables

set -e  # Exit immediately if any command fails

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

# Validate detected interfaces
if [[ -z "$INSIDE_INTERFACE" ]]; then
    echo "Error: No inside interface found."
    exit 1
fi

if [[ -z "$OUTSIDE_INTERFACE" ]]; then
    echo "Error: No outside interface found."
    exit 1
fi

echo "Inside interface detected: $INSIDE_INTERFACE"
echo "Outside interface detected: $OUTSIDE_INTERFACE"

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# Combine inside and sub-interfaces into an array
ALL_INTERFACES=("$INSIDE_INTERFACE" $SUB_INTERFACES)
TOTAL_INTERFACES=${#ALL_INTERFACES[@]}

# User-selected interfaces
SELECTED_INTERFACES=()
echo "Select the interfaces that should participate in VPN traffic:"
echo "0. Exit without applying rules"

for i in "${!ALL_INTERFACES[@]}"; do
    echo "$((i+1)). ${ALL_INTERFACES[i]}"
done

while true; do
    if [[ ${#SELECTED_INTERFACES[@]} -eq $TOTAL_INTERFACES ]]; then
        echo "All available interfaces have been selected. Proceeding..."
        break
    fi

    read -p "Enter the number of the interface to include (0 to finish): " CHOICE

    if [[ "$CHOICE" == "0" ]]; then
        if [[ ${#SELECTED_INTERFACES[@]} -eq 0 ]]; then
            echo "No interfaces selected. Exiting..."
            exit 0
        else
            break
        fi
    elif [[ "$CHOICE" =~ ^[0-9]+$ ]] && ((CHOICE >= 1 && CHOICE <= TOTAL_INTERFACES)); then
        INTERFACE_SELECTED="${ALL_INTERFACES[CHOICE-1]}"
        if [[ ! " ${SELECTED_INTERFACES[@]} " =~ " ${INTERFACE_SELECTED} " ]]; then
            SELECTED_INTERFACES+=("$INTERFACE_SELECTED")
            echo "Added $INTERFACE_SELECTED to VPN traffic."
        else
            echo "$INTERFACE_SELECTED is already selected."
        fi
    else
        echo "Invalid choice. Please enter a valid number from the list."
    fi
done

# Apply nftables rules for OpenVPN

# Allow OpenVPN server to receive client connections (UDP 1194)
nft add rule inet filter input iifname "$OUTSIDE_INTERFACE" udp dport 1194 accept

# Allow all traffic on the VPN interface (tun0)
nft add rule inet filter input iifname "tun0" accept

# Ensure VPN clients can access the internet via the outside interface
nft add rule inet filter forward iifname "tun0" oifname "$OUTSIDE_INTERFACE" ct state new accept

# Apply rules only to selected interfaces
for IFACE in "${SELECTED_INTERFACES[@]}"; do
    nft add rule inet filter forward iifname "tun0" oifname "$IFACE" accept
    nft add rule inet filter forward iifname "$IFACE" oifname "tun0" ct state new accept
done

# Ensure NAT is applied for VPN clients so they can access the internet
#nft add rule inet nat postrouting oifname "$OUTSIDE_INTERFACE" masquerade

nft list ruleset > /etc/sysconfig/nftables.conf

echo "OpenVPN firewall rules applied successfully!"

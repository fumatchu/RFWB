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

# Initialize the Public Key Infrastructure (PKI)
echo "Initializing PKI..."
sudo ./easy-rsa/3/easyrsa init-pki

# Get the transient hostname
TRANSIENT_HOSTNAME=$(hostnamectl | grep "Transient hostname" | awk '{print $3}')
echo "Using transient hostname as Common Name (CN): $TRANSIENT_HOSTNAME"

# Build the Certificate Authority (CA) with automated Common Name
echo "Building the Certificate Authority (CA) with hostname as CN..."
sudo EASYRSA_BATCH=1 EASYRSA_REQ_CN="$TRANSIENT_HOSTNAME" ./easy-rsa/3/easyrsa build-ca nopass

# Generate a certificate request for the server without a password, using the transient hostname as CN
echo "Generating server certificate request with hostname as CN..."
sudo EASYRSA_BATCH=1 EASYRSA_REQ_CN="$TRANSIENT_HOSTNAME" ./easy-rsa/3/easyrsa gen-req server nopass

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

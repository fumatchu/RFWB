#!/bin/bash

# OpenVPN Client Config Generator

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

# Function to get the external IP address of the VPN server
get_vpn_ip() {
    if [[ -n "$OUTSIDE_INTERFACE" ]]; then
        ip -4 addr show "$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1
    else
        echo "Error: No interface ending with '-outside' found."
        echo "Please check your network interfaces and ensure one is correctly labeled with '-outside'."
        exit 1
    fi
}

# Get VPN server IP
DETECTED_SERVER_IP=$(get_vpn_ip)

# Ensure an IP was detected, otherwise exit
if [[ -z "$DETECTED_SERVER_IP" ]]; then
    echo "Error: Could not determine external VPN server IP."
    echo "Please verify your network interface settings and make sure an interface exists with '-outside' in its name."
    exit 1
fi

echo "Detected external VPN server IP: $DETECTED_SERVER_IP"

# Detect OpenVPN port and protocol from server config
SERVER_CONFIG="/etc/openvpn/server/server.conf"

if [[ -f "$SERVER_CONFIG" ]]; then
    SERVER_PORT=$(grep -E "^port " "$SERVER_CONFIG" | awk '{print $2}')
    SERVER_PORT=${SERVER_PORT:-1194}  # Default to 1194 if not found

    PROTOCOL=$(grep -E "^proto " "$SERVER_CONFIG" | awk '{print $2}')
    PROTOCOL=${PROTOCOL:-udp}  # Default to UDP if not found
else
    echo "Error: OpenVPN server configuration file not found at $SERVER_CONFIG"
    exit 1
fi

echo "Detected OpenVPN settings: Port: $SERVER_PORT, Protocol: $PROTOCOL"

# Ask user if they want to use the detected external IP or enter a custom one
read -p "Do you want to use this detected IP ($DETECTED_SERVER_IP) as the VPN server address? (y/n): " USE_DETECTED_IP
if [[ "$USE_DETECTED_IP" =~ ^[Nn]$ ]]; then
    read -p "Enter the VPN server IP or resolvable domain name: " SERVER_IP
else
    SERVER_IP="$DETECTED_SERVER_IP"
fi

# Detect DNS settings
PRIMARY_DNS_FILE="/etc/openvpn/primary_dns"
if [[ -f "$PRIMARY_DNS_FILE" ]]; then
    DETECTED_DNS=$(cat "$PRIMARY_DNS_FILE")
    read -p "Found DNS configuration: $DETECTED_DNS. Use this as the primary DNS? (y/n): " USE_DETECTED_DNS
    if [[ "$USE_DETECTED_DNS" =~ ^[Yy]$ ]]; then
        DNS1="$DETECTED_DNS"
    else
        read -p "Enter primary DNS IP for clients: " DNS1
    fi
else
    read -p "Enter primary DNS IP for clients: " DNS1
fi

DNS2=208.67.222.222
DNS3=208.67.220.220

# Ensure unique client name
while true; do
    read -p "Enter OpenVPN client name: " CLIENT_NAME
    if [[ -f "/etc/openvpn/easy-rsa/pki/issued/$CLIENT_NAME.crt" ]]; then
        echo "Error: A client with this name already exists. Please choose a different name."
    else
        break
    fi
done

# Define paths for Easy-RSA
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CERT_DIR="$EASYRSA_DIR/pki"
CLIENT_CERT="$CERT_DIR/issued/$CLIENT_NAME.crt"
CLIENT_KEY="$CERT_DIR/private/$CLIENT_NAME.key"
CA_CERT="$CERT_DIR/ca.crt"

# Generate client certificate and key
cd "$EASYRSA_DIR" || exit
./easy-rsa/3/easyrsa gen-req "$CLIENT_NAME" nopass
./easy-rsa/3/easyrsa sign-req client "$CLIENT_NAME"

# Check if required files exist
if [[ ! -f "$CLIENT_CERT" || ! -f "$CLIENT_KEY" || ! -f "$CA_CERT" ]]; then
    echo "Error: Failed to generate required certificate/key files."
    exit 1
fi

# Define output directory
OUTPUT_DIR="/etc/openvpn/clients"
mkdir -p "$OUTPUT_DIR"

# Create client config file
CONFIG_FILE="$OUTPUT_DIR/$CLIENT_NAME.ovpn"
cat > "$CONFIG_FILE" <<EOF
client
dev tun
proto $PROTOCOL
remote $SERVER_IP $SERVER_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers AES-256-GCM:AES-256-CBC
auth SHA256
verb 3

<ca>
$(cat "$CA_CERT")
</ca>

<cert>
$(cat "$CLIENT_CERT")
</cert>

<key>
$(cat "$CLIENT_KEY")
</key>

EOF

# Add DNS settings to client config
echo "Adding DNS settings to client configuration..."
echo "dhcp-option DNS $DNS1" >> "$CONFIG_FILE"
echo "dhcp-option DNS $DNS2" >> "$CONFIG_FILE"
echo "dhcp-option DNS $DNS3" >> "$CONFIG_FILE"

# Package client configuration
ZIP_FILE="$OUTPUT_DIR/${CLIENT_NAME}-config.zip"
zip "$ZIP_FILE" "$CONFIG_FILE"

# Display success message
echo "Client configuration created: $CONFIG_FILE"
echo "Packaged as: $ZIP_FILE"
echo "Transfer and import this file to your OpenVPN client."

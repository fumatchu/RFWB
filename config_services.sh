#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Define file paths and directories
NAMED_CONF="/etc/named.conf"
KEYS_FILE="/etc/named/keys.conf"
ZONE_DIR="/var/named/"


generate_tsig_key() {
    echo -e "${YELLOW}Generating TSIG key using rndc-confgen...${TEXTRESET}"

    # Generate an rndc key using rndc-confgen
    sudo rndc-confgen -a

    # The key will be generated and stored in /etc/rndc.key by default
    key_file="/etc/rndc.key"

    # Extract the key secret
    key_secret=$(grep secret $key_file | awk '{print $2}' | tr -d '";')

    echo -e "${YELLOW}Key generated: $key_secret${TEXTRESET}"

    # Append the key to keys.conf
    sudo bash -c "cat > $KEYS_FILE" <<EOF
key "Kea-DDNS" {
    algorithm hmac-sha256;
    secret "$key_secret";
};
EOF

}

configure_bind() {
    # Extract domain and hostname
    full_hostname=$(hostnamectl status | awk '/Static hostname:/ {print $3}')

    if [[ ! "$full_hostname" == *.* ]]; then
        echo -e "${RED}Error: Hostname does not contain a domain part.${TEXTRESET}"
        return 1
    fi

    hostname="${full_hostname%%.*}"
    domain="${full_hostname#*.}"

    # Get the server's IP address (IPv4 assumed here)
    ip_address=$(hostname -I | awk '{print $1}')

    if [[ -z "$ip_address" ]]; then
        echo -e "${RED}Error: Unable to determine IP address.${TEXTRESET}"
        return 1
    fi

    reverse_zone=$(echo $ip_address | awk -F. '{print $3"."$2"."$1}')
    reverse_ip=$(echo $ip_address | awk -F. '{print $4}')

    # Check if variables are set correctly
    if [[ -z "$domain" || -z "$reverse_zone" || -z "$reverse_ip" ]]; then
        echo -e "${RED}Error: Domain or reverse zone information is missing.${TEXTRESET}"
        return 1
    fi

    # Create forward and reverse zone files
    forward_zone_file="${ZONE_DIR}db.${domain}"
    reverse_zone_file="${ZONE_DIR}db.${reverse_zone}"

    echo -e "${YELLOW}Configuring BIND with forward and reverse zones...${TEXTRESET}"

    # Append new zone configurations to named.conf
    sudo bash -c "cat >> $NAMED_CONF" <<EOF

include "$KEYS_FILE";

zone "$domain" {
    type master;
    file "$forward_zone_file";
    allow-update { key "Kea-DDNS"; };
};

zone "${reverse_zone}.in-addr.arpa" {
    type master;
    file "$reverse_zone_file";
    allow-update { key "Kea-DDNS"; };
};
EOF

    # Modify existing configuration in named.conf
    sudo sed -i '/listen-on port 53 {/s/{ 127.0.0.1; }/{ 127.0.0.1; any; }/' $NAMED_CONF
    sudo sed -i 's/allow-query[[:space:]]*{[[:space:]]*localhost;[[:space:]]*};/allow-query { localhost; any; };/' $NAMED_CONF

    # Create forward zone file
    sudo bash -c "cat > $forward_zone_file" <<EOF
\$TTL 86400
@   IN  SOA   $full_hostname. admin.$domain. (
    2023100501 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
@   IN  NS    $full_hostname.
$hostname IN  A     $ip_address
EOF

    # Create reverse zone file
    sudo bash -c "cat > $reverse_zone_file" <<EOF
\$TTL 86400
@   IN  SOA   $full_hostname. admin.$domain. (
    2023100501 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
@   IN  NS    $full_hostname.
$reverse_ip  IN  PTR   $full_hostname.
EOF

    # Set file permissions
    sudo chown root:named $NAMED_CONF $forward_zone_file $reverse_zone_file $KEYS_FILE
    sudo chmod 640 $NAMED_CONF $forward_zone_file $reverse_zone_file $KEYS_FILE

    echo -e "${GREEN}BIND configuration complete.${TEXTRESET}"
}

# Main execution block
if [ -f "$NAMED_CONF" ]; then
    echo -e "${GREEN}$NAMED_CONF found. Proceeding with configuration...${TEXTRESET}"
    generate_tsig_key
    configure_bind
else
    echo -e "${RED}$NAMED_CONF not found. Skipping BIND configuration.${TEXTRESET}"
fi

# Continue with the rest of the script here
# Define file paths and directories
KEA_CONF="/etc/kea/kea-dhcp4.conf"
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

# Function to find the private IP address of the interface
find_private_ip() {
    # Find the interface ending with -inside
    interface=$(find_interface)

    # Extract the private IP address for the found interface
    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

    if [ -z "$ip" ]; then
        echo -e "${RED}Error: No IP address found for the interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$ip"
}

configure_kea() {
    echo -e "${YELLOW}Configuring Kea DHCP server...${TEXTRESET}"

    # Get the network interface and its private IP
    interface=$(find_interface)
    dns_server_ip=$(find_private_ip)

    # Function to validate CIDR notation
    validate_cidr() {
        local cidr=$1
        local ip="${cidr%/*}"
        local prefix="${cidr#*/}"
        local n="(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"

        # Check if IP and prefix are valid
        [[ $ip =~ ^$n(\.$n){3}$ ]] && [[ $prefix -ge 0 && $prefix -le 32 ]]
    }
# Extract domain name from hostnamectl
    domain=$(hostnamectl | awk -F. '/Static hostname/ {print $2"."$3}')
while true; do
    # Prompt user for network scheme until valid input is provided
    while true; do
        read -p "Enter the network scheme (e.g., 192.168.1.0/24): " network_scheme
        if validate_cidr "$network_scheme"; then
            break
        else
            echo -e "${RED}Invalid network scheme. Please enter a valid CIDR notation.${TEXTRESET}"
        fi
    done

    # Extract network address and prefix length
    IFS='/' read -r network_address prefix_length <<< "$network_scheme"

    # Calculate default pool range and router address based on the network scheme
    IFS='.' read -r net1 net2 net3 net4 <<< "$network_address"
    default_pool_start="${net1}.${net2}.${net3}.10"
    default_pool_end="${net1}.${net2}.${net3}.100"
    default_router_address="${net1}.${net2}.${net3}.1"

    # Prompt user for a friendly name for the subnet
    read -p "Please provide a friendly name for this subnet: " description

    # Prompt user to confirm or change the pool address range
    echo -e "Default IP pool range: ${GREEN}$default_pool_start - $default_pool_end${TEXTRESET}"
    read -p "Is this range OK? (y/n): " confirm_pool
    if [[ "$confirm_pool" =~ ^[Nn]$ ]]; then
        read -p "Enter the desired pool start address: " pool_start
        read -p "Enter the desired pool end address: " pool_end
    else
        pool_start="$default_pool_start"
        pool_end="$default_pool_end"
    fi

    # Prompt user to confirm or change the router address
    echo -e "Default router address: ${GREEN}$default_router_address${TEXTRESET}"
    read -p "Is this address OK? (y/n): " confirm_router
    if [[ "$confirm_router" =~ ^[Nn]$ ]]; then
        read -p "Enter the desired router address: " router_address
    else
        router_address="$default_router_address"
    fi

    # Display the information for review
    echo -e "\nReview the settings:"
    echo -e "Friendly Name: ${GREEN}$description${TEXTRESET}"
    echo -e "Network Scheme: ${GREEN}$network_scheme${TEXTRESET}"
    echo -e "IP Pool Range: ${GREEN}$pool_start - $pool_end${TEXTRESET}"
    echo -e "Router Address: ${GREEN}$router_address${TEXTRESET}"
    echo -e "NTP Server: ${GREEN}$dns_server_ip${TEXTRESET}"
    echo -e "DNS Server: ${GREEN}$dns_server_ip${TEXTRESET}"
    echo -e "Client suffix: ${GREEN}$domain${TEXTRESET}"
    echo -e "Client Search Domain: ${GREEN}$domain${TEXTRESET}"

    # Ask if the settings are correct
    read -p "Are these settings correct? (y/n): " confirm_settings
    if [[ "$confirm_settings" =~ ^[Yy]$ ]]; then
        # If settings are correct, proceed with the script
        break
    else
        # If settings are not correct, loop and ask again
        echo -e "\nLet's try again.\n"
    fi
done

    # Extract domain name from hostnamectl
    domain=$(hostnamectl | awk -F. '/Static hostname/ {print $2"."$3}')

    # Calculate reverse zone for PTR records
    reverse_zone="$(echo "$network_address" | awk -F. '{print $3"."$2"."$1}')"

    # Extract TSIG secret from keys.conf
    tsig_secret=$(grep -oP 'secret\s+"\K[^"]+' /etc/named/keys.conf)

    # Check if Kea configuration directory exists, if not, create it
    if [ ! -d "/etc/kea" ]; then
        echo -e "${YELLOW}Creating /etc/kea directory...${TEXTRESET}"
        sudo mkdir /etc/kea
    fi

    # Configure Kea DHCP4 server
    KEA_DHCP4_CONF="/etc/kea/kea-dhcp4.conf"
    echo -e "${YELLOW}Creating Kea DHCPv4 configuration...${TEXTRESET}"
    sudo bash -c "cat > $KEA_DHCP4_CONF" <<EOF
{
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": ["$interface"]
        },
        "lease-database": {
            "type": "memfile",
            "persist": true,
            "name": "/var/lib/kea/kea-leases4.csv"
        },
        "dhcp-ddns": {
            "enable-updates": true,
            "server-ip": "127.0.0.1",
            "server-port": 53001,
            "sender-ip": "127.0.0.1",
            "sender-port": 53000,
            "max-queue-size": 1024,
            "ncr-protocol": "UDP",
            "ncr-format": "JSON"
        },
        "subnet4": [
            {
                ##BEGINSUBNET-$description
                "id": 1,
                "subnet": "$network_scheme",
                "pools": [
                    {
                        "pool": "$pool_start - $pool_end"
                    }
                ],
                "option-data": [
                    {
                        "name": "routers",
                        "data": "$router_address"
                    },
                    {
                        "name": "domain-name-servers",
                        "data": "$dns_server_ip"
                    },
                    {
                        "name": "ntp-servers",
                        "data": "$dns_server_ip"
                    },
                    {
                        "name": "domain-search",
                        "data": "$domain"
                    },
                    {
                        "name": "domain-name",
                        "data": "$domain"
                    }
                 ##ENDSUBNET-$description
                ]
            }
        ]
    }
}
EOF

    # Configure Kea DHCP DDNS server
    KEA_DHCP_DDNS_CONF="/etc/kea/kea-dhcp-ddns.conf"
    echo -e "${YELLOW}Creating Kea DHCP DDNS configuration...${TEXTRESET}"
    sudo bash -c "cat > $KEA_DHCP_DDNS_CONF" <<EOF
{
    "DhcpDdns": {
        "ip-address": "127.0.0.1",
        "port": 53001,
        "dns-server-timeout": 500,
        "ncr-format": "JSON",
        "ncr-protocol": "UDP",
        "forward-ddns": {
            "ddns-domains": [
                {
                    "name": "$domain.",
                    "key-name": "Kea-DDNS",
                    "dns-server": {
                        "ip-address": "127.0.0.1",
                        "port": 53
                    }
                }
            ]
        },
        "reverse-ddns": {
            "ddns-domains": [
                {
                    "name": "$reverse_zone.in-addr.arpa.",
                    "key-name": "Kea-DDNS",
                    "dns-server": {
                        "ip-address": "127.0.0.1",
                        "port": 53
                    }
                }
            ]
        },
        "tsig-keys": [
            {
                "name": "Kea-DDNS",
                "algorithm": "HMAC-SHA256",
                "secret": "$tsig_secret"
            }
        ]
    }
}
EOF

    # Set file permissions
    echo -e "${YELLOW}Setting permissions for configuration files...${TEXTRESET}"
    sudo chown root:kea $KEA_DHCP4_CONF $KEA_DHCP_DDNS_CONF
    sudo chmod 640 $KEA_DHCP4_CONF $KEA_DHCP_DDNS_CONF

    echo -e "${GREEN}Kea DHCP server configuration complete.${TEXTRESET}"
}
if [ -f "$KEA_CONF" ]; then
    echo -e "${GREEN}$KEA_CONF found. Proceeding with configuration...${TEXTRESET}"
    configure_kea
    else
    echo -e "${RED}$KEA_CONF not found. Skipping KEA-DHCP configuration.${TEXTRESET}"
fi
}
configure_fail2ban() {
    echo -e "${YELLOW}Configuring Fail2ban Service...${TEXTRESET}"
# Copy default configuration to local configuration
echo -e "${YELLOW}Copying default Fail2ban configuration...${TEXTRESET}"
if sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; then
    echo -e "${GREEN}Configuration copied successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to copy configuration.${TEXTRESET}"
    exit 1
fi

# Configure Fail2ban
echo -e "${YELLOW}Configuring Fail2ban...${TEXTRESET}"
if sudo bash -c 'cat <<EOL >> /etc/fail2ban/jail.local

# Custom Fail2ban configuration
[DEFAULT]
bantime  = 600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOL'; then
    echo -e "${GREEN}Fail2ban configured successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to configure Fail2ban.${TEXTRESET}"
    exit 1
fi

# Start Fail2ban service
echo -e "${YELLOW}Starting Fail2ban service...${TEXTRESET}"
if sudo systemctl start fail2ban; then
    echo -e "${GREEN}Fail2ban service started successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to start Fail2ban service.${TEXTRESET}"
    exit 1
fi

# Enable Fail2ban service to start on boot
echo -e "${YELLOW}Enabling Fail2ban to start on boot...${TEXTRESET}"
if sudo systemctl enable fail2ban; then
    echo -e "${GREEN}Fail2ban enabled to start on boot successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to enable Fail2ban to start on boot.${TEXTRESET}"
    exit 1
fi

# Check Fail2ban status
echo -e "${YELLOW}Checking Fail2ban status...${TEXTRESET}"
if sudo systemctl status fail2ban; then
    echo -e "${GREEN}Fail2ban is active and running.${TEXTRESET}"
else
    echo -e "${RED}Fail2ban is not running properly.${TEXTRESET}"
fi

# Output the status of the SSH jail
echo -e "${YELLOW}Fail2ban SSH jail status:${TEXTRESET}"
sudo fail2ban-client status sshd

echo -e "${GREEN}Fail2ban installation and configuration complete.${TEXTRESET}"
}



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

    # Insert forwarders configuration right after the crypto policy include line
    sudo sed -i '/include "\/etc\/crypto-policies\/back-ends\/bind.config";/a \
forwarders {\n\
    208.67.222.222;\n\
    208.67.220.220;\n\
};\n\
forward only;' $NAMED_CONF

    # Append zone configurations at the bottom of named.conf
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

configure_fail2ban() {
    echo -e "${YELLOW}Configuring Fail2ban Service...${TEXTRESET}"
# Define the original and new file paths
ORIGINAL_FILE="/etc/fail2ban/jail.conf"
JAIL_LOCAL_FILE="/etc/fail2ban/jail.local"
SSHD_LOCAL_FILE="/etc/fail2ban/jail.d/sshd.local"

# Copy the original jail.conf to jail.local
echo -e "${YELLOW}Copying $ORIGINAL_FILE to $JAIL_LOCAL_FILE...${TEXTRESET}"
cp -v "$ORIGINAL_FILE" "$JAIL_LOCAL_FILE"

# Check if the copy was successful
if [[ $? -ne 0 ]]; then
    echo -e "${RED}Failed to copy file. Exiting.${TEXTRESET}"
    exit 1
fi

# Use sed to modify the jail.local file
echo -e "${YELLOW}Modifying $JAIL_LOCAL_FILE to enable SSH jail...${TEXTRESET}"
sed -i '/^\[sshd\]/,/^$/ s/#mode.*normal/&\nenabled = true/' "$JAIL_LOCAL_FILE"

# Check if the modification was successful
if [[ $? -ne 0 ]]; then
    echo -e "${RED}Failed to modify $JAIL_LOCAL_FILE. Exiting.${TEXTRESET}"
    exit 1
fi

# Create or overwrite the sshd.local file with the desired content
echo -e "${YELLOW}Creating or modifying $SSHD_LOCAL_FILE...${TEXTRESET}"
cat <<EOL > "$SSHD_LOCAL_FILE"
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOL

# Check if the file creation was successful
if [[ $? -ne 0 ]]; then
    echo -e "${RED}Failed to create or modify $SSHD_LOCAL_FILE. Exiting.${TEXTRESET}"
    exit 1
fi

# Enable and start the Fail2Ban service
echo -e "${YELLOW}Enabling Fail2Ban service...${TEXTRESET}"
systemctl enable fail2ban

echo -e "${YELLOW}Starting Fail2Ban service...${TEXTRESET}"
systemctl start fail2ban
sleep 5

# Check the status of the Fail2Ban service
echo -e "${YELLOW}Checking Fail2Ban service status...${TEXTRESET}"
if systemctl status fail2ban | grep -q "active (running)"; then
    echo -e "${GREEN}Fail2Ban is running.${TEXTRESET}"
else
    echo -e "${RED}Fail2Ban is not running. Checking SELinux configuration...${TEXTRESET}"

    # Check SELinux status
    selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')

    if [ "$selinux_status" == "enabled" ]; then
        echo -e "${YELLOW}SELinux is enabled.${TEXTRESET}"

        # Restore SELinux context for /etc/fail2ban/jail.local
        echo -e "${YELLOW}Restoring SELinux context for /etc/fail2ban/jail.local...${TEXTRESET}"
        restorecon -v /etc/fail2ban/jail.local

        # Check SELinux denials for fail2ban-server
        echo -e "${YELLOW}Checking SELinux denials for fail2ban-server...${TEXTRESET}"
        denials=$(ausearch -m avc -ts recent | grep "fail2ban-server" | wc -l)

        if [ "$denials" -gt 0 ]; then
            echo -e "${RED}SELinux denials found for fail2ban-server. Creating a local policy module...${TEXTRESET}"

            # Generate and install a local policy module to allow fail2ban access
            ausearch -c 'fail2ban-server' --raw | audit2allow -M my-fail2banserver
            semodule -X 300 -i my-fail2banserver.pp

            echo -e "${GREEN}Custom SELinux policy module installed.${TEXTRESET}"
        else
            echo -e "${GREEN}No SELinux denials found for fail2ban-server.${TEXTRESET}"
        fi
    else
        echo -e "${YELLOW}SELinux is not enabled.${TEXTRESET}"
    fi

    # Restart the Fail2Ban service after SELinux adjustments
    echo -e "${YELLOW}Restarting Fail2Ban service...${TEXTRESET}"
    systemctl restart fail2ban

    # Check the Fail2Ban service status again
    echo -e "${YELLOW}Re-checking Fail2Ban service status...${TEXTRESET}"
    if systemctl status fail2ban | grep -q "active (running)"; then
        echo -e "${GREEN}Fail2Ban is now running after SELinux adjustments.${TEXTRESET}"
    else
        echo -e "${RED}Fail2Ban is still not running. Further investigation may be required.${TEXTRESET}"
    fi
fi

# Verify that the SSHD jail is running and functional
echo -e "${YELLOW}Verifying SSHD jail status...${TEXTRESET}"
sshd_status=$(fail2ban-client status sshd 2>&1)

if echo "$sshd_status" | grep -q "ERROR   NOK: ('sshd',)"; then
    echo -e "${RED}SSHD jail failed to start. Please check Fail2Ban configuration.${TEXTRESET}"
elif echo "$sshd_status" | grep -E "Banned IP list:" | sed 's/^[[:space:]]*`- //'; then
    echo -e "${GREEN}SSHD jail is active and functional.${TEXTRESET}"
else
    echo -e "${RED}SSHD jail is not functional or has current failures. Please check Fail2Ban configuration.${TEXTRESET}"
fi
echo -e "${GREEN}Fail2ban configuration complete.${TEXTRESET}"
}
# Call the configure_fail2ban function
configure_fail2ban



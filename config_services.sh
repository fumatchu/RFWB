#!/bin/bash

# Define color codes for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Define file paths
NAMED_CONF="/etc/named.conf"
ZONE_DIR="/var/named/"
KEYS_FILE="/etc/named/keys.conf"
KEA_CONF="/etc/kea/kea-dhcp4.conf"

# Function to install necessary packages if not already installed
install_packages() {
    echo -e "${YELLOW}Checking for necessary packages...${TEXTRESET}"
    packages=("bind" "bind-utils" "isc-kea-dhcp4-server" "policycoreutils-python-utils")
    for pkg in "${packages[@]}"; do
        if ! rpm -q $pkg &> /dev/null; then
            echo -e "${YELLOW}Installing $pkg...${TEXTRESET}"
            sudo dnf install -y $pkg
        else
            echo -e "${GREEN}$pkg is already installed.${TEXTRESET}"
        fi
    done
}

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
configure_kea() {
    echo -e "${YELLOW}Configuring Kea DHCP server...${TEXTRESET}"

    # Function to validate CIDR notation
    validate_cidr() {
        local cidr=$1
        local ip="${cidr%/*}"
        local prefix="${cidr#*/}"
        local n="(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"

        # Check if IP and prefix are valid
        [[ $ip =~ ^$n(\.$n){3}$ ]] && [[ $prefix -ge 0 && $prefix -le 32 ]]
    }

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

    # Calculate pool range based on the network scheme
    IFS='.' read -r net1 net2 net3 net4 <<< "$network_address"
    pool_start="${net1}.${net2}.${net3}.10"
    pool_end="${net1}.${net2}.${net3}.100"
    router_address="${net1}.${net2}.${net3}.1"

    # Check if Kea configuration directory exists, if not, create it
    if [ ! -d "/etc/kea" ]; then
        sudo mkdir /etc/kea
    fi

    # Configure Kea DHCP4 server
    sudo bash -c "cat > $KEA_CONF" <<EOF
{
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": ["eth0"]
        },
        "lease-database": {
            "type": "memfile",
            "persist": true,
            "name": "/var/lib/kea/kea-leases4.csv"
        },
        "ddns-send-updates": true,
        "ddns-generated-prefix": "dhcp",
        "ddns-override-client-update": true,
        "ddns-qualifying-suffix": "$domain.",
        "ddns-rev-suffix": "in-addr.arpa.",
        "ddns-hostname": "my-dynamic-host",
        "ddns-server": {
            "ip-address": "127.0.0.1",
            "port": 53
        },
        "tsig-keys": {
            "Kea-DDNS": {
                "algorithm": "HMAC-SHA256",
                "secret": "your-generated-key-here"
            }
        },
        "zones": [
            {
                "name": "$domain.",
                "key": "Kea-DDNS"
            },
            {
                "name": "${reverse_zone}.in-addr.arpa.",
                "key": "Kea-DDNS"
            }
        ],
        "subnet4": [
            {
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
                    }
                ]
            }
        ]
    }
}
EOF

    echo -e "${GREEN}Kea DHCP server configuration complete.${TEXTRESET}"
}

    # Set file permissions
    sudo chown root:kea $KEA_CONF
    sudo chmod 640 $KEA_CONF

    echo -e "${GREEN}Kea DHCP server configuration complete.${TEXTRESET}"


# Function to configure SELinux
configure_selinux() {
    echo -e "${YELLOW}Configuring SELinux...${TEXTRESET}"

    # Check if SELinux is enabled
    if selinuxenabled; then
        # Set appropriate SELinux contexts
        sudo semanage fcontext -a -t named_zone_t "${ZONE_DIR}db.*"
        sudo semanage fcontext -a -t named_conf_t "$NAMED_CONF"
        sudo restorecon -Rv /etc/named /var/named

        echo -e "${GREEN}SELinux configuration applied.${TEXTRESET}"
    else
        echo -e "${YELLOW}SELinux is not enabled. Skipping SELinux configuration.${TEXTRESET}"
    fi
}

# Function to validate network scheme
validate_network_scheme() {
    local scheme=$1
    local regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$"
    if [[ $scheme =~ $regex ]]; then
        echo "valid"
    else
        echo "invalid"
    fi
}

# Main script execution
install_packages
generate_tsig_key

# Extract reverse zone from network scheme
IFS='.' read -r a b c d <<< "${network_scheme%/*}"
reverse_zone="$c.$b.$a"

configure_bind
configure_kea
configure_selinux

# Restart services
echo -e "${YELLOW}Restarting services...${TEXTRESET}"
sudo systemctl restart named
sudo systemctl restart kea-dhcp4-server

echo -e "${GREEN}Configuration and setup complete.${TEXTRESET}"

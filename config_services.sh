#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

clear
echo -e "${GREEN}Configuring Services${TEXTRESET}"
echo ""
sleep 2

configure_time () {

clear
echo -e "${GREEN}Configuring Time Service${TEXTRESET}"
sleep 2
# Define the path to the chrony configuration file
CHRONY_CONF="/etc/chrony.conf"
TEMP_CONF="/tmp/chrony_temp.conf"

# Check if /etc/chrony.conf exists
if [ ! -f "$CHRONY_CONF" ]; then
    echo -e "[${RED}ERROR${TEXTRESET}] /etc/chrony.conf not found. Exiting..."
    exit 0
fi

# Backup the original configuration file
cp $CHRONY_CONF ${CHRONY_CONF}.bak
echo -e "[${YELLOW}INFO${TEXTRESET}] Backup of the original configuration file created."

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

# Function to determine the IP addressing scheme for an interface
find_ip_scheme() {
    local interface="$1"
    nmcli -t -f IP4.ADDRESS dev show $interface | grep -oP '\d+\.\d+\.\d+\.\d+/\d+'
}

# Determine inside interfaces
INSIDE_INTERFACES=()
INSIDE_INTERFACES+=($(find_interface "-inside"))

# Determine sub-interfaces for each inside interface
for iface in "${INSIDE_INTERFACES[@]}"; do
    SUB_INTERFACES=($(find_sub_interfaces "$iface"))
    INSIDE_INTERFACES+=("${SUB_INTERFACES[@]}")
done

# Collect all IP schemes for inside interfaces
declare -A NETWORK_PREFIXES
for iface in "${INSIDE_INTERFACES[@]}"; do
    IP_SCHEME=$(find_ip_scheme "$iface")
    if [[ $IP_SCHEME =~ ([0-9]+\.[0-9]+)\.[0-9]+\.[0-9]+/[0-9]+ ]]; then
        NETWORK_PREFIXES["${BASH_REMATCH[1]}"]=1
    fi
done

# Determine the appropriate allow statement
ALLOW_STATEMENT=""
if [[ ${#NETWORK_PREFIXES[@]} -eq 1 ]]; then
    for prefix in "${!NETWORK_PREFIXES[@]}"; do
        ALLOW_STATEMENT="${prefix}.0.0/16"
    done
else
    ALLOW_STATEMENT="0.0.0.0/0"
fi

# Process the configuration file
awk -v allow_statement="$ALLOW_STATEMENT" '
    BEGIN { pool_added = 0 }
    /^#allow .*$/ {
        print "allow " allow_statement
        next
    }
    /^server[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}.*$/ {
        if (!pool_added) {
            print "pool 2.rocky.pool.ntp.org iburst"
            pool_added = 1
        }
        next
    }
    { print }
' $CHRONY_CONF > $TEMP_CONF

# Replace the original configuration with the modified one
mv $TEMP_CONF $CHRONY_CONF
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Configuration file updated."

# Set ownership and permissions
chown root:root $CHRONY_CONF
chmod 644 $CHRONY_CONF
restorecon -v $CHRONY_CONF
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Permissions and SELinux context set."

# Check if chronyd service is running
if systemctl is-active --quiet chronyd; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] chronyd is running, restarting service..."
    systemctl restart chronyd
else
    echo -e "[${YELLOW}INFO${TEXTRESET}] chronyd is not running, starting service...${TEXTRESET}"
    systemctl start chronyd
fi

# Check synchronization status
while true; do
    CHRONYC_OUTPUT=$(chronyc tracking)

    if echo "$CHRONYC_OUTPUT" | grep -q "Leap status.*Not synchronised"; then
        echo -e "[${RED}ERROR${TEXTRESET}] System time is not synchronized. Retrying in 10 seconds..."
        sleep 10
    else
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] System time is synchronized."
        break
    fi
done

# Function to set up nftables rules for NTP and Chrony on the inside interfaces
    # Ensure the nftables service is enabled and started
    sudo systemctl enable nftables
    sudo systemctl start nftables

    # Create a filter table if it doesn't exist
    if ! sudo nft list tables | grep -q 'inet filter'; then
        sudo nft add table inet filter
    fi

    # Create an input chain if it doesn't exist
    if ! sudo nft list chain inet filter input &>/dev/null; then
        sudo nft add chain inet filter input { type filter hook input priority 0 \; }
    fi

    # Add rules to allow NTP and Chrony on the inside interfaces
    for iface in "${INSIDE_INTERFACES[@]}"; do
        # NTP rules
        if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 123 accept"; then
            sudo nft add rule inet filter input iifname "$iface" udp dport 123 accept
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow NTP (UDP) on interface ${GREEN}$iface${TEXTRESET}"
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow NTP (UDP) on interface ${GREEN}$iface${TEXTRESET}"
        fi
        if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 123 accept"; then
            sudo nft add rule inet filter input iifname "$iface" tcp dport 123 accept
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow NTP (TCP) on interface ${GREEN}$iface${TEXTRESET}"
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow NTP (TCP) on interface ${GREEN}$iface${TEXTRESET}"
        fi

        # Chrony rules
        if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 323 accept"; then
            sudo nft add rule inet filter input iifname "$iface" udp dport 323 accept
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow Chrony (UDP) on interface ${GREEN}$iface${TEXTRESET}"
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow Chrony (UDP) on interface ${GREEN}$iface${TEXTRESET}"
        fi
    done
    
    # Check and handle rfwb-portscan service
    rfwb_status=$(systemctl is-active rfwb-portscan)
    if [ "$rfwb_status" == "active" ]; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] Stopping rfwb-portscan service before saving nftables configuration...${TEXTRESET}"
        systemctl stop rfwb-portscan
    fi

    # Save the current nftables configuration
    sudo nft list ruleset >/etc/sysconfig/nftables.conf
    # Restart the nftables service to apply changes
    echo -e "[${YELLOW}INFO${TEXTRESET}] Restarting nftables service to apply changes...${TEXTRESET}"
    sudo systemctl restart nftables
    # Restart rfwb-portscan service if it was active
    if [ "$rfwb_status" == "active" ]; then
        echo -e "[${YELLOW}INFO${TEXTRESET}]Restarting rfwb-portscan service...${TEXTRESET}"
        systemctl start rfwb-portscan
    fi
    sleep 4
}

#Call Time Function
configure_time

#Configure BIND
# Define file paths and directories
NAMED_CONF="/etc/named.conf"
KEYS_FILE="/etc/named/keys.conf"
ZONE_DIR="/var/named/"

generate_tsig_key() {
    echo -e "[${YELLOW}INFO${TEXTRESET}] Generating TSIG key using rndc-confgen..."

    # Generate an rndc key using rndc-confgen
    sudo rndc-confgen -a

    # The key will be generated and stored in /etc/rndc.key by default
    key_file="/etc/rndc.key"

    # Extract the key secret
    key_secret=$(grep secret $key_file | awk '{print $2}' | tr -d '";')

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Key generated: ${GREEN}$key_secret${TEXTRESET}"

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
        echo -e "[${RED}ERROR${TEXTRESET}] Hostname does not contain a domain part.${TEXTRESET}"
        return 1
    fi

    hostname="${full_hostname%%.*}"
    domain="${full_hostname#*.}"

    # Get the server's IP address (IPv4 assumed here)
    ip_address=$(hostname -I | awk '{print $1}')

    if [[ -z "$ip_address" ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Unable to determine IP address."
        return 1
    fi

    reverse_zone=$(echo $ip_address | awk -F. '{print $3"."$2"."$1}')
    reverse_ip=$(echo $ip_address | awk -F. '{print $4}')

    # Check if variables are set correctly
    if [[ -z "$domain" || -z "$reverse_zone" || -z "$reverse_ip" ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Domain or reverse zone information is missing."
        return 1
    fi

    # Create forward and reverse zone files
    forward_zone_file="${ZONE_DIR}db.${domain}"
    reverse_zone_file="${ZONE_DIR}db.${reverse_zone}"

    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring BIND with forward and reverse zones..."

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
    semanage boolean -m --on named_write_master_zones
    chown named:named $forward_zone_file $reverse_zone_file
    chmod g+w /var/named
    # Define the file path
    RNDC_KEY_FILE="/etc/rndc.key"

    # Check if the file exists
    if [[ -f "$RNDC_KEY_FILE" ]]; then
        # Change the ownership to 'named' user and group
        chown named:named "$RNDC_KEY_FILE"

        # Set the permissions to 600
        chmod 600 "$RNDC_KEY_FILE"

        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Permissions and ownership for ${GREEN}$RNDC_KEY_FILE${TEXTRESET} have been set."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] $RNDC_KEY_FILE does not exist."
        exit 1
    fi

    # Check SELinux status and provide guidance
    SELINUX_STATUS=$(getenforce)
    if [[ "$SELINUX_STATUS" != "Enforcing" ]]; then
        echo "SELinux is currently set to $SELINUX_STATUS."
    else
        echo " "
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] BIND configuration complete."
    sleep 3
}

start_and_enable_service() {
    local service_name="$1"

    echo -e "[${YELLOW}INFO${TEXTRESET}]Enabling and starting the ${GREEN}$service_name${TEXTRESET} service..."

    sudo systemctl enable "$service_name"
    sudo systemctl start "$service_name"

    # Check if the service is running
    if sudo systemctl status "$service_name" | grep -q "running"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}$service_name${TEXTRESET} service is running."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to start ${GREEN}$service_name${TEXTRESET} service."
        exit 1
    fi
    sleep 2
}

# Main execution block
     clear 
     echo -e "${GREEN}Configuring BIND${TEXTRESET}"
     sleep 2
if [ -f "$NAMED_CONF" ]; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] $NAMED_CONF found. Proceeding with configuration..."
    generate_tsig_key
    configure_bind
    start_and_enable_service "named"
else
    echo -e "[${YELLOW}INFO${TEXTRESET}] $NAMED_CONF not found. Skipping BIND configuration.${TEXTRESET}"
fi

KEA_CONF="/etc/kea/kea-dhcp4.conf"
# Function to find the network interface
find_interface() {
    # Find the interface with a connection ending in -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No interface with a connection ending in ${YELLOW}'-inside'${TEXTRESET} found."
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
        echo -e "[${RED}ERROR${TEXTRESET}] No IP address found for the interface ${GREEN}$interface${TEXTRESET}"
        exit 1
    fi

    echo "$ip"
}

configure_kea() {
    clear
    echo -e "${GREEN}Configuring Kea DHCP server...${TEXTRESET}"

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
            read -p "Enter the Network Scope (e.g., 192.168.1.0/24): " network_scheme
            if validate_cidr "$network_scheme"; then
                break
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Invalid Network Scope. Please enter a valid CIDR notation."
            fi
        done

        # Extract network address and prefix length
        IFS='/' read -r network_address prefix_length <<<"$network_scheme"

        # Calculate default pool range and router address based on the network scheme
        IFS='.' read -r net1 net2 net3 net4 <<<"$network_address"
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
        echo -e "\nReview settings:"
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
            echo -e "\nConfigure Scope.\n"
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
        echo -e "[${YELLOW}INFO${TEXTRESET}] Creating /etc/kea directory..."
        sudo mkdir /etc/kea
    fi

    # Configure Kea DHCP4 server
    KEA_DHCP4_CONF="/etc/kea/kea-dhcp4.conf"
    echo -e "[${YELLOW}INFO${TEXTRESET}] Creating initial Kea DHCPv4 configuration..."
    sleep 1
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
        "ddns-qualifying-suffix": "$domain",
        "ddns-override-client-update": true,
        "ddns-override-no-update": true,
        "ddns-update-on-renew": true,
        "ddns-generated-prefix": "dynamic",
        "ddns-replace-client-name": "always",
        "authoritative": true,
        "subnet4": [
            ##BEGINSUBNET-$description
            {
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
    echo -e "[${YELLOW}INFO${TEXTRESET}] Creating intial Kea DHCP DDNS configuration..."
    sleep 1
    sudo bash -c "cat > $KEA_DHCP_DDNS_CONF" <<EOF
{
    "DhcpDdns": {
        "ip-address": "127.0.0.1",
        "port": 53001,
        "control-socket": {
        "socket-type": "unix",
        "socket-name": "/tmp/kea-ddns-ctrl-socket"
          },
        "dns-server-timeout": 500,
        "ncr-format": "JSON",
        "ncr-protocol": "UDP",
        "forward-ddns": {
            "ddns-domains": [
                {
                    "name": "$domain.",
                    "key-name": "Kea-DDNS",
                    "dns-servers": [ 
                        {
                        "ip-address": "127.0.0.1",
                        "port": 53
                        }
                    ]
                }
            ]
        },
        "reverse-ddns": {
            "ddns-domains": [
                {
                    "name": "$reverse_zone.in-addr.arpa.",
                    "key-name": "Kea-DDNS",
                    "dns-servers": [ 
                        {
                        "ip-address": "127.0.0.1",
                        "port": 53
                        }
                    ]
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
    
    sudo chown root:kea $KEA_DHCP4_CONF $KEA_DHCP_DDNS_CONF
    sudo chmod 640 $KEA_DHCP4_CONF $KEA_DHCP_DDNS_CONF

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Kea DHCP server configuration complete."
    sleep 2
}
if [ -f "$KEA_CONF" ]; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] $KEA_CONF found. Proceeding with configuration..."
    configure_kea
else
    echo -e "[${RED}ERROR${TEXTRESET}] $KEA_CONF not found. Skipping KEA-DHCP configuration."
fi
#Add additional Scopes if needed
# Path to the KEA DHCP4 configuration file
KEA_DHCP4_CONF="/etc/kea/kea-dhcp4.conf"

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

# Function to add a new subnet to the KEA DHCP4 configuration
add_subnet() {
    local description
    local network_scheme
    local pool_start
    local pool_end
    local router_address

    while true; do
        # Prompt user for network scheme until valid input is provided
        while true; do
            read -p "Enter the DHCP Scope you would like to create (e.g., 192.168.2.0/24): " network_scheme
            if validate_cidr "$network_scheme"; then
                break
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Invalid network scheme. Please enter a valid CIDR notation."
            fi
        done

        # Extract network address and prefix length
        IFS='/' read -r network_address prefix_length <<<"$network_scheme"

        # Calculate default pool range and router address based on the network scheme
        IFS='.' read -r net1 net2 net3 net4 <<<"$network_address"
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
        echo -e "\nReview settings:"
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
            echo -e "\n[${RED}ERROR${TEXTRESET}] Configure Scope${TEXTRESET}\n"
        fi
    done

    # Read the current configuration file into a variable
    config_content=$(sudo cat /etc/kea/kea-dhcp4.conf)

    # Extract the last ID used and increment for the new subnet
    last_id=$(echo "$config_content" | grep '"id":' | tail -n 1 | grep -o '[0-9]\+')
    new_id=$((last_id + 1))

    # Format the new subnet entry
    new_subnet_entry=$(
        cat <<EOF
        ]
    },
    {
        ##BEGINSUBNET-$description
        "id": $new_id,
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
    )

    # Create a temporary file to store the updated configuration
    tmpfile=$(mktemp)

    # Use awk to insert the new subnet entry after the last ##ENDSUBNET and delete lines below
    awk -v new_subnet="$new_subnet_entry" '
    {
        if (/##ENDSUBNET/) last_endsubnet = NR
        lines[NR] = $0
    }
    END {
        for (i = 1; i <= last_endsubnet; i++) {
            print lines[i]
        }
        print new_subnet
    }' /etc/kea/kea-dhcp4.conf >"$tmpfile"

    # Replace the original configuration file with the updated one
    sudo mv "$tmpfile" /etc/kea/kea-dhcp4.conf

    # Set file permissions
    echo -e "[${YELLOW}INFO${TEXTRESET}] Setting permissions for configuration files...${TEXTRESET}"
    sudo chown root:kea /etc/kea/kea-dhcp4.conf
    sudo chmod 640 /etc/kea/kea-dhcp4.conf

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] New subnet added to Kea DHCP server configuration.${TEXTRESET}"
    sleep 1
}

# Check if the KEA_DHCP4_CONF file exists
if [ ! -f "$KEA_DHCP4_CONF" ]; then
    echo -e "[${RED}ERROR${TEXTRESET}] $KEA_DHCP4_CONF not found. Skipping subnet addition."
else
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] $KEA_DHCP4_CONF found. Proceeding with the script...${TEXTRESET}"

    # Loop to repeatedly ask the user if they want to add another subnet
    clear
    while true; do
        read -p "Would you like to add another DHCP subnet? (y/n): " add_subnet_choice
        if [[ "$add_subnet_choice" =~ ^[Yy]$ ]]; then
            add_subnet
        else
            echo -e "[${YELLOW}INFO${TEXTRESET}] No more subnets will be added."
            break
        fi
    done
fi
# Function to find interfaces based on connection name suffix
find_interfaces() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Find main and sub-interfaces
INSIDE_INTERFACE=$(find_interfaces "-inside")
SUB_INTERFACES=$(nmcli -t -f DEVICE device status | grep -E "${INSIDE_INTERFACE}\.[0-9]+")

# Combine interfaces into an array
INTERFACES=("$INSIDE_INTERFACE")
INTERFACES+=($SUB_INTERFACES)

# Check if kea-dhcp4.conf exists
CONFIG_FILE="/etc/kea/kea-dhcp4.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "[${RED}ERROR${TEXTRESET}] Error: Configuration file ${GREEN}$CONFIG_FILE${TEXTRESET} not found."
    exit 1
fi

# Count the number of subnets in the configuration file
SUBNET_COUNT=$(grep -c '"subnet":' "$CONFIG_FILE")

# Function to extract subnets
extract_subnets() {
    grep -A1 '"id":' "$CONFIG_FILE" | grep '"subnet":' | awk -F'"' '{print $4}'
}

# Function to update the configuration file
update_config() {
    if [ "$SUBNET_COUNT" -gt 1 ] && [ -z "$SUB_INTERFACES" ]; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] ${YELLOW}Warning:${TEXTRESET} More subnets than interfaces. Confirm if this setup is correct."
        read -p "Do you want to proceed? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            echo "Aborting changes."
            echo -e "${TEXTRESET}"
            exit 0
        fi
    fi

    if [ "$SUBNET_COUNT" -gt 1 ] && [ -n "$SUB_INTERFACES" ]; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] Multiple subnets and interfaces detected. Please select bindings:"

        echo "Available interfaces:"
        for i in "${!INTERFACES[@]}"; do
            echo "$i) ${INTERFACES[$i]}"
        done

        echo "Subnets in configuration:"
        subnets=($(extract_subnets))
        for j in "${!subnets[@]}"; do
            echo "${subnets[$j]}"
        done

        # Prompt for user input to map interfaces to subnets
        read -p "Enter interface number for subnet ${subnets[0]}: " index1
        read -p "Enter interface number for subnet ${subnets[1]}: " index2

        iface1="${INTERFACES[$index1]}"
        iface2="${INTERFACES[$index2]}"

        # Use awk to update the configuration file
        awk -v iface1="$iface1" -v iface2="$iface2" -v sub0="${subnets[0]}" -v sub1="${subnets[1]}" '
        BEGIN { interface_inserted1 = 0; interface_inserted2 = 0 }
        /"subnet":/ {
            print
            if ($0 ~ sub0 && !interface_inserted1) {
                print "        \"interface\": \"" iface1 "\","
                interface_inserted1 = 1
            } else if ($0 ~ sub1 && !interface_inserted2) {
                print "        \"interface\": \"" iface2 "\","
                interface_inserted2 = 1
            }
            next
        }
        { print }
        ' "$CONFIG_FILE" >"${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

        # Update the interfaces list in the configuration
        current_interfaces=$(grep -oP '(?<=\[)[^]]*' "$CONFIG_FILE" | tr -d '"')
        IFS=',' read -ra interface_array <<<"$current_interfaces"

        if [[ ! " ${interface_array[@]} " =~ " $iface1 " ]]; then
            interface_array+=("$iface1")
        fi
        if [[ ! " ${interface_array[@]} " =~ " $iface2 " ]]; then
            interface_array+=("$iface2")
        fi

        new_interfaces=$(printf '"%s",' "${interface_array[@]}")
        new_interfaces="[${new_interfaces%,}]"

        sed -i "s/\"interfaces\": \[.*\]/\"interfaces\": $new_interfaces/" "$CONFIG_FILE"
    fi

    if [ "$SUBNET_COUNT" -eq 1 ] && [ -n "$INSIDE_INTERFACE" ]; then
        echo -e "${GREEN}Updating configuration for single subnet and interface.${TEXTRESET}"
        sed -i "s/\"interfaces\": \[\".*\"\]/\"interfaces\": [\"$INSIDE_INTERFACE\"]/" "$CONFIG_FILE"
        awk -v iface="$INSIDE_INTERFACE" -v subnet="$(extract_subnets)" '
        BEGIN { interface_inserted = 0 }
        /"subnet":/ {
            print
            if ($0 ~ subnet && !interface_inserted) {
                print "        \"interface\": \"" iface "\","
                interface_inserted = 1
            }
            next
        }
        { print }
        ' "$CONFIG_FILE" >"${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    fi
}

# Execute the update
update_config
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Configuration update completed."
sleep 1

#Start KEA Services
start_and_enable_service() {
    local service_name="$1"
    local conf_file="$2"

    # Check for the configuration file
    if [ -f "$conf_file" ]; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] Configuration file ${GREEN}$conf_file${TEXTRESET} found. Enabling and starting the ${GREEN}$service_name${TEXTRESET} service..."

        sudo systemctl enable "$service_name"
        sudo systemctl start "$service_name"

        # Check if the service is running
        if sudo systemctl status "$service_name" | grep -q "running"; then
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}$service_name${TEXTRESET} service is running."
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Failed to start ${GREEN}$service_name${TEXTRESET} service."
            exit 1
        fi
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Configuration file ${GREEN}$conf_file${TEXTRESET} not found. Cannot enable and start ${GREEN}$service_name${TEXTRESET} service."
        exit 1
    fi
}

# Start and enable the kea-dhcp4 service
start_and_enable_service "kea-dhcp4" "/etc/kea/kea-dhcp4.conf"

# Start and enable the kea-dhcp-ddns service
start_and_enable_service "kea-dhcp-ddns" "/etc/kea/kea-dhcp-ddns.conf"

#Cleanup-If using VLANS we need to make sure mulitple subents are accounted for in the named configuration
echo -e "[${YELLOW}INFO${TEXTRESET}] Double Checking Subnet Mapping for named"
# Define file paths and directories
KEA_CONF="/etc/kea/kea-dhcp4.conf"
NAMED_CONF="/etc/named.conf"
ZONE_DIR="/var/named/"
KEYS_FILE="/etc/named/keys.conf"

# Extract domain and hostname
full_hostname=$(hostnamectl status | awk '/Static hostname:/ {print $3}')

if [[ ! "$full_hostname" == *.* ]]; then
    echo -e "${RED}Error: Hostname does not contain a domain part.${TEXTRESET}"
    exit 1
fi

hostname="${full_hostname%%.*}"
domain="${full_hostname#*.}"

# Function to reverse the IP portion of the subnet
reverse_ip() {
    local ip="$1"
    echo "$ip" | awk -F '.' '{print $3"."$2"."$1}'
}

# Get the server's IP addresses (IPv4)
ip_addresses=($(hostname -I))

# Extract subnets from the Kea configuration file
subnets=$(grep '"subnet":' "$KEA_CONF" | awk -F '"' '{print $4}')

# Stop the named service
echo -e "[${YELLOW}INFO${TEXTRESET}] Stopping named service..."
sudo systemctl stop named

# Ensure KEA-DDNS key is included once
if ! grep -q "include \"$KEYS_FILE\";" "$NAMED_CONF"; then
    echo "include \"$KEYS_FILE\";" | sudo tee -a "$NAMED_CONF"
fi

# Check each subnet for a corresponding reverse DNS zone and create if missing
for subnet in $subnets; do
    # Extract the IP portion and reverse it
    ip_portion=$(echo "$subnet" | cut -d'/' -f1)
    reversed_ip=$(reverse_ip "$ip_portion")
    reverse_zone="${reversed_ip}.in-addr.arpa"
    reverse_zone_file="${ZONE_DIR}db.${reversed_ip}"

    # Attempt to find a matching IP address for the subnet
    closest_ip=""
    for ip in "${ip_addresses[@]}"; do
        # Check for match on third octet
        if [[ "$ip" == "${ip_portion%.*}."* ]]; then
            closest_ip="$ip"
            break
        # Check for match on second octet
        elif [[ "$ip" == "${ip_portion%%.*}."* ]]; then
            closest_ip="$ip"
        fi
    done

    if [ -z "$closest_ip" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No close IP address match found for subnet ${GREEN}$subnet${TEXTRESET}"
        continue
    fi

    # Use the closest matching IP address for the reverse zone
    echo -e "[${YELLOW}INFO${TEXTRESET}] Using IP address ${GREEN}$closest_ip${TEXTRESET} for subnet ${GREEN}$subnet${TEXTRESET}"

    # Check if the reverse zone exists in the named configuration
    if ! grep -q "zone \"$reverse_zone\"" "$NAMED_CONF"; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] No matching reverse zone for subnet ${GREEN}$subnet:${TEXTRESET} creating ${GREEN}$reverse_zone${TEXTRESET}"

        # Add reverse zone to named.conf
        sudo bash -c "cat >> $NAMED_CONF" <<EOF

zone "${reverse_zone}" {
    type master;
    file "$reverse_zone_file";
    allow-update { key "Kea-DDNS"; };
};
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
${closest_ip##*.}  IN  PTR   $full_hostname.
EOF

        # Set file permissions
        sudo chmod 640 $reverse_zone_file
        sudo chown named:named $reverse_zone_file
    else
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Match found for subnet ${GREEN}$subnet:${TEXTRESET} ${GREEN}$reverse_zone${TEXTRESET}"
    fi
done

# Start the named service
echo -e "[${YELLOW}INFO${TEXTRESET}] Starting named service..."
sudo systemctl start named

# Validate that the named service is running
if systemctl is-active --quiet named; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Named service is running successfully."
else
    echo -e "[${RED}ERROR${TEXTRESET}] Named service failed to start after KEA subnet Cleanup."
    exit 1
fi

configure_fail2ban() {
    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring Fail2ban Service..."
    # Define the original and new file paths
    ORIGINAL_FILE="/etc/fail2ban/jail.conf"
    JAIL_LOCAL_FILE="/etc/fail2ban/jail.local"
    SSHD_LOCAL_FILE="/etc/fail2ban/jail.d/sshd.local"

    # Copy the original jail.conf to jail.local
    cp -v "$ORIGINAL_FILE" "$JAIL_LOCAL_FILE"

    # Check if the copy was successful
    if [[ $? -ne 0 ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to copy ${GREEN}$ORIGINAL_FILE${TEXTRESET} to ${GREEN}$JAIL_LOCAL_FILE${TEXTRESET} file. ${RED}Exiting.${TEXTRESET}"
        exit 1
    fi

    # Use sed to modify the jail.local file
    echo -e "[${YELLOW}INFO${TEXTRESET}] Modifying ${GREEN}$JAIL_LOCAL_FILE${TEXTRESET} to enable SSH jail..."
    sed -i '/^\[sshd\]/,/^$/ s/#mode.*normal/&\nenabled = true/' "$JAIL_LOCAL_FILE"

    # Check if the modification was successful
    if [[ $? -ne 0 ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to modify ${GREEN}$JAIL_LOCAL_FILE${TEXTRESET}. ${RED}Exiting.${TEXTRESET}"
        exit 1
    fi

    # Create or overwrite the sshd.local file with the desired content
    cat <<EOL >"$SSHD_LOCAL_FILE"
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
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to create or modify $SSHD_LOCAL_FILE. ${RED}Exiting.${TEXTRESET}"
        exit 1
    fi

    # Enable and start the Fail2Ban service
    echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling Fail2Ban service..."
    systemctl enable fail2ban

    echo -e "[${YELLOW}INFO${TEXTRESET}] Starting Fail2Ban service..."
    systemctl start fail2ban
    sleep 5

    # Check the status of the Fail2Ban service
    if systemctl status fail2ban | grep -q "active (running)"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Fail2Ban is running.${TEXTRESET}"
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Fail2Ban is not running. Checking SELinux configuration...${TEXTRESET}"

        # Check SELinux status
        selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')

        if [ "$selinux_status" == "enabled" ]; then
            echo -e "[${YELLOW}INFO${TEXTRESET}] SELinux is enabled."

            # Restore SELinux context for /etc/fail2ban/jail.local
            echo -e "[${YELLOW}INFO${TEXTRESET}] Restoring SELinux context for /etc/fail2ban/jail.local..."
            restorecon -v /etc/fail2ban/jail.local

            # Check SELinux denials for fail2ban-server
            echo -e "[${YELLOW}INFO${TEXTRESET}] Checking SELinux denials for fail2ban-server...${TEXTRESET}"
            denials=$(ausearch -m avc -ts recent | grep "fail2ban-server" | wc -l)

            if [ "$denials" -gt 0 ]; then
                echo -e "[${RED}ERROR${TEXTRESET}] SELinux denials found for fail2ban-server. Creating a local policy module..."

                # Generate and install a local policy module to allow fail2ban access
                ausearch -c 'fail2ban-server' --raw | audit2allow -M my-fail2banserver
                semodule -X 300 -i my-fail2banserver.pp

                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Custom SELinux policy module installed.${TEXTRESET}"
            else
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] No SELinux denials found for fail2ban-server.${TEXTRESET}"
            fi
        else
            echo -e "[${YELLOW}INFO${TEXTRESET}] SELinux is not enabled.${TEXTRESET}"
        fi

        # Restart the Fail2Ban service after SELinux adjustments
        echo -e "[${YELLOW}INFO${TEXTRESET}] Restarting Fail2Ban service..."
        systemctl restart fail2ban

        # Check the Fail2Ban service status again
        echo -e "[${YELLOW}INFO${TEXTRESET}] Re-checking Fail2Ban service status..."
        if systemctl status fail2ban | grep -q "active (running)"; then
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Fail2Ban is now running after SELinux adjustments.${TEXTRESET}"
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Fail2Ban is still not running. ${YELLOW}Further investigation may be required.${TEXTRESET}"
        fi
    fi

    # Verify that the SSHD jail is running and functional
    echo -e "[${YELLOW}INFO${TEXTRESET}] Verifying SSHD jail status...${TEXTRESET}"
    sshd_status=$(fail2ban-client status sshd 2>&1)

    if echo "$sshd_status" | grep -q "ERROR   NOK: ('sshd',)"; then
        echo -e "[${RED}ERROR${TEXTRESET}] SSHD jail failed to start. ${YELLOW}Please check Fail2Ban configuration.${TEXTRESET}"
    elif echo "$sshd_status" | grep -E "Banned IP list:" | sed 's/^[[:space:]]*`- //'; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] SSHD jail is active and functional.${TEXTRESET}"
    else
        echo -e "[${RED}ERROR${TEXTRESET}] SSHD jail is not functional or has current failures. ${YELLOW}Please check Fail2Ban configuration.${TEXTRESET}"
    fi
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}Fail2ban configuration complete.${TEXTRESET}"
    sleep 4
}
# Call the configure_fail2ban function
configure_fail2ban

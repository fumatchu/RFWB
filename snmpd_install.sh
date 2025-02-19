#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}This script must be run as root. Please use sudo or log in as root.${TEXTRESET}"
    exit 1
fi

# Function to validate IP address or network
function validate_ip_or_network() {
    local ip_network=$1
    if [[ $ip_network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$ ]]; then
        IFS='/' read -r ip prefix <<< "$ip_network"
        for octet in $(echo $ip | tr '.' ' '); do
            if ((octet < 0 || octet > 255)); then
                echo -e "${RED}Invalid IP address or network: $ip_network${TEXTRESET}"
                return 1
            fi
        done
        if [ -n "$prefix" ] && ((prefix < 0 || prefix > 32)); then
            echo -e "${RED}Invalid prefix length: $prefix${TEXTRESET}"
            return 1
        fi
        return 0
    else
        echo -e "${RED}Invalid IP address or network format: $ip_network${TEXTRESET}"
        return 1
    fi
}

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    # Find the interface ending with -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi

    # Extract the private IP address for the found interface
    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

    if [ -z "$ip" ]; then
        echo -e "${RED}Error: No IP address found for the interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Install SNMP daemon
echo -e "${YELLOW}Installing SNMP daemon...${TEXTRESET}"
yum install -y net-snmp net-snmp-utils

# Ask user for SNMP version
echo -e "${YELLOW}Select SNMP version to run:${TEXTRESET}"
echo "1) SNMPv1"
echo "2) SNMPv2c"
echo "3) SNMPv3"
read -p "Enter the number corresponding to your choice (1, 2, or 3): " snmp_version
while ! [[ "$snmp_version" =~ ^[1-3]$ ]]; do
    echo -e "${RED}Invalid selection. Please enter 1, 2, or 3.${TEXTRESET}"
    read -p "Enter the number corresponding to your choice (1, 2, or 3): " snmp_version
done

# Ask for SNMP community string if SNMPv1 or SNMPv2c is selected
if [ "$snmp_version" == "1" ] || [ "$snmp_version" == "2" ]; then
    read -p "Enter the SNMP community string (default is 'public'): " community_string
    community_string=${community_string:-public}
fi

# If SNMPv3 is selected, gather additional credentials
if [ "$snmp_version" == "3" ]; then
    read -p "Enter SNMPv3 username: " snmpv3_user
    read -p "Enter SNMPv3 authentication protocol (MD5/SHA): " auth_protocol
    read -sp "Enter SNMPv3 authentication password: " auth_pass
    echo
    read -p "Enter SNMPv3 privacy protocol (DES/AES): " priv_protocol
    read -sp "Enter SNMPv3 privacy password: " priv_pass
    echo
fi

# Ask user for IP address or network
read -p "Enter the IP address or network (e.g., 192.168.1.0/24) allowed to monitor this device: " allowed_network
while ! validate_ip_or_network "$allowed_network"; do
    read -p "Please enter a valid IP address or network: " allowed_network
done

# Ask for system location and contact
read -p "Enter system location: " syslocation
read -p "Enter system contact: " syscontact

# Configure firewall using nftables
interface=$(find_private_ip)
echo -e "${YELLOW}Configuring firewall to allow SNMP traffic on interface $interface...${TEXTRESET}"
nft add rule inet filter input iifname "$interface" udp dport 161 accept

# Check and handle rfwb-portscan service
rfwb_status=$(systemctl is-active rfwb-portscan)
if [ "$rfwb_status" == "active" ]; then
    echo -e "${YELLOW}Stopping rfwb-portscan service before saving nftables configuration...${TEXTRESET}"
    systemctl stop rfwb-portscan
fi

# Save nftables configuration
echo -e "${YELLOW}Saving nftables configuration...${TEXTRESET}"
nft list ruleset > /etc/sysconfig/nftables.conf

# Restart rfwb-portscan service if it was active
if [ "$rfwb_status" == "active" ]; then
    echo -e "${YELLOW}Restarting rfwb-portscan service...${TEXTRESET}"
    systemctl start rfwb-portscan
fi

# Backup existing configuration
echo -e "${YELLOW}Backing up existing configuration file...${TEXTRESET}"
cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.backup

# Create a new configuration file based on user input and the provided template
echo -e "${YELLOW}Configuring SNMP...${TEXTRESET}"

cat <<EOF > /etc/snmp/snmpd.conf
###############################################################################
# System contact information
syslocation $syslocation
syscontact $syscontact

###############################################################################
# Access Control
###############################################################################
com2sec notConfigUser  $allowed_network  ${community_string:-public}

# SNMPv3 user setup
$(if [ "$snmp_version" == "3" ]; then
    echo "createUser $snmpv3_user $auth_protocol \"$auth_pass\" $priv_protocol \"$priv_pass\""
    echo "rouser $snmpv3_user"
fi)

# Views and Access
group notConfigGroup v1 notConfigUser
group notConfigGroup v2c notConfigUser
view systemview included .1.3.6.1.2.1.1
view systemview included .1.3.6.1.2.1.25.1.1
view systemview included .1
access notConfigGroup "" any noauth exact systemview none none

###############################################################################
# Additional SNMP Views
###############################################################################
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteIfIndex
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric1
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric2
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric3
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric4

###############################################################################
# Process checks.
###############################################################################
# Ensure nftables is running
proc nftables

###############################################################################
# Load Average Checks
###############################################################################
load 12 14 14

###############################################################################
# Disk checks
###############################################################################
disk / 10000000  # Ensure at least 10GB of space

###############################################################################
# Extensible sections.
###############################################################################
# Uncomment and modify the following examples as needed:
# exec echotest /bin/echo hello world
# exec shelltest /bin/sh /tmp/shtest
EOF

# Start and enable SNMP service
echo -e "${YELLOW}Starting SNMP service...${TEXTRESET}"
systemctl start snmpd
systemctl enable snmpd

# Validate that the service is running
if systemctl status snmpd | grep "active (running)" > /dev/null; then
    echo -e "${GREEN}SNMP service is running successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to start SNMP service. Please check the configuration.${TEXTRESET}"
fi

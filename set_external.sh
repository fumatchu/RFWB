#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
clear
# Ensure nmcli is installed
if ! command -v nmcli &>/dev/null; then
    echo -e "${RED}nmcli is not installed. Please install it and try again.${TEXTRESET}"
    exit 1
fi

# Ensure nftables is installed and running
if ! command -v nft &>/dev/null; then
    echo -e "${RED}nftables is not installed. Please install it and try again.${TEXTRESET}"
    exit 1
fi

if ! systemctl is-active --quiet nftables; then
    echo -e "${RED}nftables is not running. Please start it and try again.${TEXTRESET}"
    exit 1
fi

# Get all connections managed by NetworkManager
connections=$(nmcli -t -f NAME,DEVICE,TYPE connection show)

# Display all interfaces that will be checked
echo -e "Checking the following network interfaces for autoconnect settings:"

while IFS=: read -r name device type; do
    # Only show valid ethernet or wifi connections
    if [ "$type" == "802-3-ethernet" ] || [ "$type" == "wifi" ]; then
        echo -e "- $device ($name): Type $type"
    fi
done <<<"$connections"

# Check and modify autoconnect settings
echo -e "\n${YELLOW}Modifying interfaces that are not set to autoconnect...${TEXTRESET}"

while IFS=: read -r name device type; do
    # Process valid ethernet or wifi connections
    if [ "$type" == "802-3-ethernet" ] || [ "$type" == "wifi" ]; then
        # Check if the connection is set to autoconnect
        autoconnect=$(nmcli -g connection.autoconnect connection show "$name")

        if [ "$autoconnect" != "yes" ]; then
            echo -e "${RED}Connection $name (Device: $device) is not set to autoconnect. Enabling autoconnect...${TEXTRESET}"
            nmcli connection modify "$name" connection.autoconnect yes

            if [ $? -eq 0 ]; then
                echo -e "${GREEN}Autoconnect enabled for $name (Device: $device).${TEXTRESET}"
            else
                echo -e "${RED}Failed to enable autoconnect for $name (Device: $device).${TEXTRESET}"
            fi
        else
            echo -e "${GREEN}Connection $name (Device: $device) is already set to autoconnect.${TEXTRESET}"
        fi
    fi
done <<<"$connections"

echo -e "${GREEN}Completed checking and updating autoconnect settings.${TEXTRESET}"

# Get currently connected interfaces
existing_connections=$(nmcli -t -f DEVICE,STATE dev status | grep ":connected" | cut -d: -f1)
echo -e "Existing connected interfaces:"
echo "$existing_connections"

echo -e "Please plug in your Internet connection into the firewall. It should be in a separate subnet."
echo -e "Waiting for a new interface to come up..."

# Monitor for a new connection
while true; do
    # Get current connected devices
    current_connections=$(nmcli -t -f DEVICE,STATE dev status | grep ":connected" | cut -d: -f1)

    # Find the new connection, excluding 'lo'
    new_connection=$(comm -13 <(echo "$existing_connections" | sort) <(echo "$current_connections" | sort) | grep -v "^lo$")

    if [ -n "$new_connection" ]; then
        echo -e "${GREEN}Detected a new connection: $new_connection${TEXTRESET}"

        # Get the current profile name associated with the new connection
        current_profile=$(nmcli -t -f NAME,DEVICE connection show --active | grep ":${new_connection}$" | cut -d: -f1)

        if [ -n "$current_profile" ]; then
            # Update the connection profile name to include '-outside'
            new_profile_name="${new_connection}-outside"
            echo -e "Updating connection profile name to: $new_profile_name"
            nmcli connection modify "$current_profile" connection.id "$new_profile_name"
            nmcli connection reload
        else
            echo -e "${RED}Error: Could not find an active profile for $new_connection.${TEXTRESET}"
        fi
        break
    fi

    sleep 0.5 # Check every 0.5 seconds
done

# Function to find the outside interface
find_outside_interface() {
    # Find the interface with a connection ending in -outside
    outside_interface=$(nmcli device status | awk '/-outside/ {print $1}')

    if [ -z "$outside_interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '-outside' found.${TEXTRESET}"
        exit 1
    fi

    echo "$outside_interface"
}

##Load nftables with configuration and install threat lists
# Define variables for threat list management
THREAT_LISTS=(
    "https://iplists.firehol.org/files/firehol_level1.netset"
    "https://www.abuseipdb.com/blacklist.csv"
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
)
BLOCK_SET="threat_block"
TMP_DIR="/etc/nftables"
TMP_FILE="$TMP_DIR/threat_list.txt"

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

# Setup the FW: Determine inside and outside interfaces
echo -e "${YELLOW}Determining network interfaces...${TEXTRESET}" | tee >(logger)
INSIDE_INTERFACE=$(find_interface "-inside")
OUTSIDE_INTERFACE=$(find_interface "-outside")

echo -e "${GREEN}Inside interface: $INSIDE_INTERFACE${TEXTRESET}" | tee >(logger)
echo -e "${GREEN}Outside interface: $OUTSIDE_INTERFACE${TEXTRESET}" | tee >(logger)

if [[ -z "$INSIDE_INTERFACE" || -z "$OUTSIDE_INTERFACE" ]]; then
    echo -e "${RED}Error: Could not determine one or both interfaces. Please check your connection names.${TEXTRESET}" | tee >(logger)
    exit 1
fi

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# Enable IP forwarding
echo -e "Enabling IP forwarding..." | tee >(logger)
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Apply nftables ruleset
echo -e "Applying nftables ruleset..." | tee >(logger)

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
    echo -e "Allowing inbound traffic for sub-interface: $sub_interface" | tee >(logger)
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
sudo nft add table inet nat 2>/dev/null
sudo nft add chain inet nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null
sudo nft add rule inet nat postrouting oif "$OUTSIDE_INTERFACE" masquerade

# Log and drop unsolicited incoming traffic on the outside interface
echo -e "Logging and blocking unsolicited incoming traffic on the outside interface..." | tee >(logger)
sudo nft add rule inet filter input iif "$OUTSIDE_INTERFACE" log prefix "\"Blocked: \"" drop

# Create a named set for threat blocking
sudo nft add set inet filter $BLOCK_SET { type ipv4_addr\; flags timeout\; } 2>/dev/null

# Add a rule to drop traffic from IPs in the threat list
sudo nft add rule inet filter input ip saddr @$BLOCK_SET drop

echo -e "${GREEN}nftables ruleset applied successfully.${TEXTRESET}" | tee >(logger)

# Save the current ruleset
echo -e "Saving the current nftables ruleset..." | tee >(logger)
sudo nft list ruleset >/etc/sysconfig/nftables.conf

# Enable and start nftables service to ensure configuration is loaded on boot
echo -e "Enabling nftables service..." | tee >(logger)
sudo systemctl enable nftables
sudo systemctl start nftables

echo -e "${GREEN}nftables ruleset applied and saved successfully.${TEXTRESET}" | tee >(logger)
echo -e "${YELLOW}Downloading and compiling threat lists for nftables...Please Wait${TEXTRESET}"
# Create the threat list update script
cat <<'EOF' >/usr/local/bin/update_nft_threatlist.sh
#!/bin/bash

# Define variables
THREAT_LISTS=(
    "https://iplists.firehol.org/files/firehol_level1.netset"
     "https://www.abuseipdb.com/blacklist.csv"
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
)
BLOCK_SET="threat_block"
TMP_DIR="/etc/nftables"
TMP_FILE="$TMP_DIR/threat_list.txt"

# Ensure the directory exists
mkdir -p $TMP_DIR

# Clear the temporary file
> $TMP_FILE

# Download and combine threat lists
for LIST_URL in "${THREAT_LISTS[@]}"; do
    echo "Downloading $LIST_URL..." | tee >(logger)
    curl -s $LIST_URL >> $TMP_FILE
done

# Extract only valid IP addresses
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' $TMP_FILE | sort -u > $TMP_FILE.cleaned

# Create or update the named set in nftables
sudo nft add table inet filter 2>/dev/null
sudo nft add set inet filter $BLOCK_SET { type ipv4_addr\; flags timeout\; } 2>/dev/null

# Clear the existing set elements
sudo nft flush set inet filter $BLOCK_SET

# Populate the set with IPs from the cleaned threat list
while IFS= read -r ip; do
    sudo nft add element inet filter $BLOCK_SET { $ip }
done < $TMP_FILE.cleaned

echo "Threat list updated successfully." | tee >(logger)
EOF

# Make the script executable
chmod +x /usr/local/bin/update_nft_threatlist.sh

# Create a systemd service file for the threat list update
cat <<EOF >/etc/systemd/system/rfwb-nft-threatlist.service
[Unit]
Description=RFWB NFTables Threat List Updater
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update_nft_threatlist.sh

[Install]
WantedBy=multi-user.target
EOF

# Create a systemd timer to run the service daily at 4 AM
cat <<EOF >/etc/systemd/system/rfwb-nft-threatlist.timer
[Unit]
Description=Run RFWB NFTables Threat List Updater Daily

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Reload systemd, enable and start the timer
sudo systemctl daemon-reload
sudo systemctl enable rfwb-nft-threatlist.service
sudo systemctl start rfwb-nft-threatlist.service
sudo systemctl enable rfwb-nft-threatlist.timer
sudo systemctl start rfwb-nft-threatlist.timer

echo -e "${GREEN}Threat list update service and timer configured successfully.${TEXTRESET}" | tee >(logger)


# Validate the update
if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}Threat list updated and loaded into nftables successfully.${TEXTRESET}" | tee >(logger)
    echo -e "Threat list updates will run everyday at 4:00 (A.M.)" | tee >(logger)
else
    echo -e "${RED}Failed to update the threat list.${TEXTRESET}" | tee >(logger)
fi

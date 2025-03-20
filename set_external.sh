#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
clear
# Ensure nmcli is installed
if ! command -v nmcli &>/dev/null; then
    echo -e "$[${RED}ERROR${TEXTRESET}] nmcli is not installed. Please install it and try again."
    exit 1
fi

# Ensure nftables is installed and running
if ! command -v nft &>/dev/null; then
    echo -e "[${RED}ERROR${TEXTRESET}] nftables is not installed. Please install it and try again."
    exit 1
fi

if ! systemctl is-active --quiet nftables; then
    echo -e "[${RED}ERROR${TEXTRESET}] nftables is not running. Please start it and try again."
    exit 1
fi

# Get all connections managed by NetworkManager
connections=$(nmcli -t -f NAME,DEVICE,TYPE connection show)

# Display all interfaces that will be checked
echo -e "Checking the following network interfaces for autoconnect settings:"

while IFS=: read -r name device type; do
    # Only show valid ethernet or wifi connections
    if [ "$type" == "802-3-ethernet" ] || [ "$type" == "wifi" ]; then
        echo -e "- ${GREEN}$device ($name)${TEXTRESET}: Type $type"
    fi
done <<<"$connections"

# Check and modify autoconnect settings
echo -e "\n[${YELLOW}INFO${TEXTRESET}] Modifying interfaces that are not set to autoconnect..."

while IFS=: read -r name device type; do
    # Process valid ethernet or wifi connections
    if [ "$type" == "802-3-ethernet" ] || [ "$type" == "wifi" ]; then
        # Check if the connection is set to autoconnect
        autoconnect=$(nmcli -g connection.autoconnect connection show "$name")

        if [ "$autoconnect" != "yes" ]; then
            echo -e "[${RED}ERROR${TEXTRESET}] Connection ${GREEN}$name (Device: $device)${TEXTRESET} is not set to autoconnect. ${YELLOW}Enabling autoconnect...${TEXTRESET}"
            nmcli connection modify "$name" connection.autoconnect yes

            if [ $? -eq 0 ]; then
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Autoconnect enabled for ${GREEN}$name (Device: $device).${TEXTRESET}"
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Failed to enable autoconnect for ${GREEN}$name (Device: $device).${TEXTRESET}"
            fi
        else
            echo -e "Connection ${GREEN}$name (Device: $device)${TEXTRESET} is already set to autoconnect."
        fi
    fi
done <<<"$connections"

echo -e "[${GREEN}SUCCESS${TEXTRESET}]Completed checking and updating autoconnect settings."

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
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected a new connection: ${GREEN}$new_connection${TEXTRESET}"

        # Get the current profile name associated with the new connection
        current_profile=$(nmcli -t -f NAME,DEVICE connection show --active | grep ":${new_connection}$" | cut -d: -f1)

        if [ -n "$current_profile" ]; then
            # Update the connection profile name to include '-outside'
            new_profile_name="${new_connection}-outside"
            echo -e "[${YELLOW}INFO${TEXTRESET}] Updating connection profile name to: ${GREEN}$new_profile_name${TEXTRESET}"
            nmcli connection modify "$current_profile" connection.id "$new_profile_name"
            nmcli connection reload
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Error: Could not find an active profile for ${GREEN}$new_connection.${TEXTRESET}"
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
        echo -e "[${RED}ERROR${TEXTRESET}] Error: No interface with a connection ending in '-outside' found.${TEXTRESET}"
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
echo -e "[${YELLOW}INFO${TEXTRESET}] Determining network interfaces..." | tee >(logger)
INSIDE_INTERFACE=$(find_interface "-inside")
OUTSIDE_INTERFACE=$(find_interface "-outside")

echo -e "Inside interface: ${GREEN}$INSIDE_INTERFACE${TEXTRESET}" | tee >(logger)
echo -e "Outside interface: ${GREEN}$OUTSIDE_INTERFACE${TEXTRESET}" | tee >(logger)

if [[ -z "$INSIDE_INTERFACE" || -z "$OUTSIDE_INTERFACE" ]]; then
    echo -e "[${RED}ERROR${TEXTRESET}] Error: Could not determine one or both interfaces. Please check your connection names." | tee >(logger)
    exit 1
fi

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# Enable IP forwarding
echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling IP forwarding..." | tee >(logger)
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Apply nftables ruleset
echo -e "[${YELLOW}INFO${TEXTRESET}] Applying nftables ruleset..." | tee >(logger)

# Create and configure the inet filter table if not exists
sudo nft add table inet filter 2>/dev/null

# Ensure the input chain policy is set to drop
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null

# Allow all traffic on the loopback interface
sudo nft add rule inet filter input iifname lo accept

# Allow established and related connections on the input chain
sudo nft add rule inet filter input ct state established,related accept

# Allow inbound traffic on the inside interface(s)
sudo nft add rule inet filter input iifname "$INSIDE_INTERFACE" accept
for sub_interface in $SUB_INTERFACES; do
    echo -e "[${YELLOW}INFO${TEXTRESET}] Allowing inbound traffic for sub-interface: ${GREEN}$sub_interface${TEXTRESET}" | tee >(logger)
    sudo nft add rule inet filter input iifname "$sub_interface" accept
done

# Allow SSH on the outside interface
sudo nft add rule inet filter input iifname "$OUTSIDE_INTERFACE" tcp dport 22 accept

# Create and configure the forward chain with drop policy
sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; } 2>/dev/null

# Allow established and related connections on the forward chain
sudo nft add rule inet filter forward ct state established,related accept

# Allow forwarding between inside interface and its sub-interfaces
sudo nft add rule inet filter forward iif "$INSIDE_INTERFACE" oif "$INSIDE_INTERFACE" accept
for sub_interface in $SUB_INTERFACES; do
    sudo nft add rule inet filter forward iifname "$INSIDE_INTERFACE" oifname "$sub_interface" accept
    sudo nft add rule inet filter forward iifname "$sub_interface" oifname "$INSIDE_INTERFACE" accept
    sudo nft add rule inet filter forward iifname "$sub_interface" oifname "$sub_interface" accept
done

# Allow forwarding from inside to outside
sudo nft add rule inet filter forward iifname "$INSIDE_INTERFACE" oifname "$OUTSIDE_INTERFACE" accept
for sub_interface in $SUB_INTERFACES; do
    sudo nft add rule inet filter forward iifname "$sub_interface" oifname "$OUTSIDE_INTERFACE" accept
done

# Create and configure the inet nat table
sudo nft add table inet nat 2>/dev/null
sudo nft add chain inet nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null
sudo nft add rule inet nat postrouting oifname "$OUTSIDE_INTERFACE" masquerade

# Log and drop unsolicited incoming traffic on the outside interface
echo -e "[${YELLOW}INFO${TEXTRESET}] Logging and blocking unsolicited incoming traffic on the outside interface..." | tee >(logger)
sudo nft add rule inet filter input iifname "$OUTSIDE_INTERFACE" log prefix "\"Blocked: \"" drop

# Create a named set for threat blocking
sudo nft add set inet filter $BLOCK_SET { type ipv4_addr\; flags timeout\; } 2>/dev/null

# Add a rule to drop traffic from IPs in the threat list
sudo nft add rule inet filter input ip saddr @$BLOCK_SET drop

echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables ruleset applied successfully." | tee >(logger)

# Save the current ruleset
echo -e "[${YELLOW}INFO${TEXTRESET}] Saving the current nftables ruleset..." | tee >(logger)
sudo nft list ruleset >/etc/sysconfig/nftables.conf

# Enable and start nftables service to ensure configuration is loaded on boot
echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling nftables service..." | tee >(logger)
sudo systemctl enable nftables
sudo systemctl start nftables

echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables ruleset applied and saved successfully." | tee >(logger)

#Install NFT-Threat-Lists

LOG_TAG="nft-threat-list"

echo -e "[${YELLOW}INFO${TEXTRESET}] Installing NFTables Threat List Updater..."
# Ensure required directories exist
mkdir -p /etc/nft-threat-list

# Define paths
THREAT_LIST_FILE="/etc/nft-threat-list/threat_list.txt"
MANUAL_BLOCK_LIST="/etc/nft-threat-list/manual_block_list.txt"
COMBINED_BLOCK_LIST="/etc/nft-threat-list/combined_block_list.txt"
TMP_FILE="/etc/nft-threat-list/threat_list.tmp"
UPDATE_SCRIPT="/usr/local/bin/update_nft_threatlist.sh"
CRON_JOB="/etc/cron.d/nft-threat-list"
LOG_FILE="/var/log/nft-threat-list.log"

# Overwrite the manual block list file with a proper format
echo "# Manual Block List for NFTables" > "$MANUAL_BLOCK_LIST"
echo "# Add IP addresses below the marker to be blocked" >> "$MANUAL_BLOCK_LIST"
echo "#" >> "$MANUAL_BLOCK_LIST"
echo "# Example:" >> "$MANUAL_BLOCK_LIST"
echo "# 203.0.113.45  # Suspicious traffic" >> "$MANUAL_BLOCK_LIST"
echo "# 192.168.100.50  # Internal policy block" >> "$MANUAL_BLOCK_LIST"
echo "#" >> "$MANUAL_BLOCK_LIST"
echo "######### Place IP Addresses under this line to be compiled #########" >> "$MANUAL_BLOCK_LIST"

# Verify file creation
if [ -s "$MANUAL_BLOCK_LIST" ]; then
    echo ""
else
    echo "ERROR: Manual block list was not created!" >&2
fi

# Create the threat list update script
cat <<'EOF' >$UPDATE_SCRIPT
#!/bin/bash

LOG_TAG="nft-threat-list"
THREAT_LISTS=(
    "https://iplists.firehol.org/files/firehol_level1.netset"
    "https://www.abuseipdb.com/blacklist.csv"
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
)

THREAT_LIST_FILE="/etc/nft-threat-list/threat_list.txt"
MANUAL_BLOCK_LIST="/etc/nft-threat-list/manual_block_list.txt"
COMBINED_BLOCK_LIST="/etc/nft-threat-list/combined_block_list.txt"
TMP_FILE="/etc/nft-threat-list/threat_list.tmp"
MAX_RETRIES=3
LOG_FILE="/var/log/nft-threat-list.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE" | logger -t $LOG_TAG
}

log "Starting NFTables threat list update..."

# Clear temporary file
> "$TMP_FILE"

# Download and compile IPs with retries
for LIST_URL in "${THREAT_LISTS[@]}"; do
    ATTEMPT=1
    SUCCESS=0
    while [ $ATTEMPT -le $MAX_RETRIES ]; do
        log "Downloading $LIST_URL (Attempt $ATTEMPT)..."
        curl -s --retry 3 --retry-delay 5 $LIST_URL >> "$TMP_FILE" && SUCCESS=1 && break
        ATTEMPT=$((ATTEMPT+1))
    done
    if [ $SUCCESS -eq 0 ]; then
        log "Failed to download $LIST_URL after $MAX_RETRIES attempts!"
    fi
done

# Extract only valid IPv4 addresses from downloaded lists
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$TMP_FILE" | sort -u > "$THREAT_LIST_FILE"

# Extract valid IPs from the manual block list (only below the marker)
if grep -q "######### Place IP Addresses under this line to be compiled #########" "$MANUAL_BLOCK_LIST"; then
    awk '/######### Place IP Addresses under this line to be compiled #########/{found=1; next} found && /^[0-9]+\./' "$MANUAL_BLOCK_LIST" > "$TMP_FILE"
else
    log "Marker not found in manual block list. Manual IPs will not be added."
    > "$TMP_FILE"
fi

# Merge manual block list with downloaded threat list
cat "$THREAT_LIST_FILE" "$TMP_FILE" | sort -u > "$COMBINED_BLOCK_LIST"

log "Threat list and manual block list merged successfully."

# Ensure nftables set exists
if ! sudo nft list set inet filter threat_block &>/dev/null; then
    sudo nft add table inet filter
    sudo nft add set inet filter threat_block { type ipv4_addr\; flags timeout\; }
    log "Created threat_block set in nftables."
else
    log "threat_block set already exists. Updating..."
    sudo nft flush set inet filter threat_block
fi

# Load combined IP list into nftables set
while IFS= read -r ip; do
    sudo nft add element inet filter threat_block { $ip }
done < "$COMBINED_BLOCK_LIST"

# Ensure the input chain exists
if ! sudo nft list chain inet filter input &>/dev/null; then
    sudo nft add chain inet filter input { type filter hook input priority 0 \; }
    log "Created input chain in nftables."
fi

# Add a rule to drop packets from the threat list (INPUT)
if ! sudo nft list chain inet filter input | grep -q "ip saddr @threat_block drop"; then
    sudo nft add rule inet filter input ip saddr @threat_block drop
    log "Added threat block rule to INPUT chain."
else
    log "Threat block rule already exists in INPUT chain."
fi

# Ensure the OUTPUT chain exists
if ! sudo nft list chain inet filter output &>/dev/null; then
    sudo nft add chain inet filter output { type filter hook output priority 0 \; }
    log "Created OUTPUT chain in nftables."
fi

# Add a rule to drop and log outbound packets to threat-listed IPs (OUTPUT)
if ! sudo nft list chain inet filter output | grep -q -F 'ip daddr @threat_block log prefix "Outbound Blocked:" drop'; then
    sudo nft add rule inet filter output ip daddr @threat_block log prefix \"Outbound Blocked:\" drop
    log "Added threat block rule to OUTPUT chain."
else
    log "Threat block rule already exists in OUTPUT chain."
fi


# Verify threat list application
if sudo nft list set inet filter threat_block | grep -q 'elements'; then
    log "NFTables threat list successfully applied."
else
    log "WARNING: NFTables threat list was not applied correctly!"
fi

log "Threat list update completed."
EOF

# Make the update script executable
chmod +x $UPDATE_SCRIPT

# Add a cron job to run at 4 AM and on boot
cat <<EOF >$CRON_JOB
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
@reboot root $UPDATE_SCRIPT
0 4 * * * root $UPDATE_SCRIPT
EOF

# Ensure cron job has correct permissions
chmod 644 $CRON_JOB

# Ensure cron is running
systemctl enable --now crond

# Run the update script now to initialize the threat list
echo -e "[${YELLOW}INFO${TEXTRESET}] Downloading Threat Updates and compiling lists. This may take a minute..."
bash $UPDATE_SCRIPT

echo -e "[${GREEN}SUCCESS${TEXTRESET}] Installation complete. Threat list updater will run at 4 AM daily and on boot."
logger -t $LOG_TAG "NFTables Threat List Updater Installed Successfully."

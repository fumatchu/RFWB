#!/bin/bash

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

echo -e "${GREEN}Inside interface:${TEXTRESET} $INSIDE_INTERFACE"
echo -e "${GREEN}Outside interface:${TEXTRESET} $OUTSIDE_INTERFACE"

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# List available interfaces for selection
AVAILABLE_INTERFACES=("$INSIDE_INTERFACE" $SUB_INTERFACES)
echo "Available inside interfaces:"
for i in "${!AVAILABLE_INTERFACES[@]}"; do
    echo "$i: ${AVAILABLE_INTERFACES[$i]}"
done

# Initialize an array to store selected interfaces
SELECTED_INTERFACES=()

# Loop to allow multiple selections
while true; do
    echo "Select an interface number for OpenVPN access:"
    read -r index

    # Validate index
    if [[ $index =~ ^[0-9]+$ ]] && (( index >= 0 && index < ${#AVAILABLE_INTERFACES[@]} )); then
        SELECTED_INTERFACES+=("${AVAILABLE_INTERFACES[index]}")
        echo "Selected ${AVAILABLE_INTERFACES[index]}"
        # Remove the selected interface from the available list
        AVAILABLE_INTERFACES[index]=""
    else
        echo "Invalid selection. Please enter a valid number."
        continue
    fi

    # Check if all interfaces have been selected
    if [[ ${#SELECTED_INTERFACES[@]} -eq ${#AVAILABLE_INTERFACES[@]} ]]; then
        echo "All available interfaces have been selected."
        break
    fi

    # Ask if the user wants to add another interface
    echo "Do you want to add another interface? (yes/no)"
    read -r response

    if [[ $response != "yes" ]]; then
        break
    fi
done

# Save current ruleset for comparison
nft list ruleset > /tmp/nftables_before.conf

# Apply NFTables rules using the selected interfaces
nft add table inet openvpn

nft add chain inet openvpn input { type filter hook input priority 0\; }
nft add chain inet openvpn forward { type filter hook forward priority 0\; }

nft add rule inet openvpn input iifname "$OUTSIDE_INTERFACE" udp dport 1194 accept
for iface in "${SELECTED_INTERFACES[@]}"; do
    nft add rule inet openvpn input iifname "$iface" accept
    nft add rule inet openvpn forward iifname "$iface" accept
    nft add rule inet openvpn forward iifname "$OUTSIDE_INTERFACE" oifname "$iface" accept
    nft add rule inet openvpn forward iifname "$iface" oifname "${INSIDE_INTERFACE}*" ct state established,related accept
done

# Save the new ruleset
nft list ruleset > /tmp/nftables_after.conf

# Show changes made
echo "Changes to NFTables ruleset:"
diff -u /tmp/nftables_before.conf /tmp/nftables_after.conf

# Ask the user if they want to save the changes
echo "Do you want to save these changes to the NFTables configuration? (yes/no)"
read -r save_response

if [[ $save_response == "yes" ]]; then
    # Save the current NFTables configuration permanently for Red Hat systems
    echo "Saving the current NFTables configuration..."
    nft list ruleset > /etc/sysconfig/nftables.conf
    echo "Configuration saved."
else
    echo "Changes were not saved."
fi

# Clean up temporary files
rm /tmp/nftables_before.conf /tmp/nftables_after.conf

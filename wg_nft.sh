#!/bin/bash

# Detect interfaces
outside_interface=$(nmcli con show | grep -oE "[a-zA-Z0-9-]+-outside" | cut -d- -f1)
echo "Outside interface detected: $outside_interface"

inside_interface=$(nmcli con show | grep -oE "[a-zA-Z0-9-]+-inside" | cut -d- -f1)
echo "Inside interface detected: $inside_interface"

echo "Detecting sub-interfaces..."
sub_interfaces=$(ip link show | grep "$inside_interface\." | awk '{print $2}' | sed 's/://' | sed 's/@.*//')

if [ -n "$sub_interfaces" ]; then
  echo "Sub-interfaces found: $sub_interfaces"
else
  echo "No sub-interfaces found."
fi

# Extract the first sub-interface
sub_interface=$(echo "$sub_interfaces" | awk '{print $1}')

# Track selected interfaces
inside_selected=0
sub_selected=0

# Display available interfaces
echo ""
echo "Available interfaces:"
echo "  1. $inside_interface"
if [ -n "$sub_interface" ]; then
  echo "  2. $sub_interface"
fi

echo ""
echo "Please select which interfaces should participate in the WireGuard VPN:"
echo "(Enter the number of the interface you want to add, or 0 when done)"

while true; do
  echo ""
  read -p "Enter interface number (or 0 to finish): " choice
  
  if [ "$choice" = "0" ]; then
    break
  fi
  
  if [ "$choice" = "1" ] && [ "$inside_selected" = "0" ]; then
    inside_selected=1
    echo "Interface $inside_interface added to selection."
  elif [ "$choice" = "2" ] && [ -n "$sub_interface" ] && [ "$sub_selected" = "0" ]; then
    sub_selected=1
    echo "Interface $sub_interface added to selection."
  elif [ "$choice" = "1" ] && [ "$inside_selected" = "1" ]; then
    echo "Interface $inside_interface is already selected."
  elif [ "$choice" = "2" ] && [ "$sub_selected" = "1" ]; then
    echo "Interface $sub_interface is already selected."
  else
    echo "Invalid selection. Please enter a valid number."
  fi
  
  # Show remaining interfaces
  echo ""
  echo "Available interfaces (not yet selected):"
  if [ "$inside_selected" = "0" ]; then
    echo "  1. $inside_interface"
  fi
  
  if [ -n "$sub_interface" ] && [ "$sub_selected" = "0" ]; then
    echo "  2. $sub_interface"
  fi
  
  # Check if all interfaces have been selected
  if [ "$inside_selected" = "1" ] && ([ -z "$sub_interface" ] || [ "$sub_selected" = "1" ]); then
    echo "All interfaces have been selected."
    break
  fi
done

# Display selected interfaces explicitly without variable expansion
echo ""
echo -n "Selected interfaces: "
if [ "$inside_selected" = "1" ]; then
  echo -n "$inside_interface"
  if [ "$sub_selected" = "1" ] && [ -n "$sub_interface" ]; then
    echo -n " $sub_interface"
  fi
elif [ "$sub_selected" = "1" ] && [ -n "$sub_interface" ]; then
  echo -n "$sub_interface"
else
  echo -n "None"
fi
echo ""

# Check if WireGuard interface exists
wg_interface="wg0"
if ip link show $wg_interface &>/dev/null; then
  echo "WireGuard interface $wg_interface exists"
  wg_exists=true
else
  echo "WARNING: WireGuard interface $wg_interface does not exist!"
  echo "Make sure WireGuard is properly configured and running."
  echo "You can create the interface with: wg-quick up /etc/wireguard/wg0.conf"
  echo ""
  echo "NOTE: Adding rules for non-existent interfaces may not work as expected with nftables."
  echo "The rules may be added but might not appear in the output until the interface exists."
  echo ""
  read -p "Continue anyway? (y/n): " continue_anyway
  if [[ "$continue_anyway" != "y" && "$continue_anyway" != "Y" ]]; then
    echo "Exiting."
    exit 1
  fi
  wg_exists=false
fi

echo ""
echo "Adding WireGuard forwarding rules to nftables..."

# Save current nftables configuration
nft list ruleset > /tmp/nftables_before.txt

# Create a temporary nftables script file
TEMP_FILE=$(mktemp)
echo "#!/usr/sbin/nft -f" > $TEMP_FILE

# Add rules to the forward chain for WireGuard to internet
echo "Adding rule: Allow traffic from WireGuard to internet via $outside_interface"
echo "add rule inet filter forward iif $$wg_interface oif$$ outside_interface accept" >> $TEMP_FILE

# Add rules for the selected interfaces
if [ "$inside_selected" = "1" ]; then
    echo "Adding rules for interface: $inside_interface"
    # Allow traffic from inside interface to WireGuard
    echo "add rule inet filter forward iif $$inside_interface oif$$ wg_interface accept" >> $TEMP_FILE
    # Allow traffic from WireGuard to inside interface
    echo "add rule inet filter forward iif $$wg_interface oif$$ inside_interface accept" >> $TEMP_FILE
fi

if [ "$sub_selected" = "1" ] && [ -n "$sub_interface" ]; then
    echo "Adding rules for interface: $sub_interface"
    # Allow traffic from sub-interface to WireGuard
    echo "add rule inet filter forward iif $$sub_interface oif$$ wg_interface accept" >> $TEMP_FILE
    # Allow traffic from WireGuard to sub-interface
    echo "add rule inet filter forward iif $$wg_interface oif$$ sub_interface accept" >> $TEMP_FILE
fi

# Make sure UDP port 51820 is allowed in the input chain
if ! nft list chain inet filter input | grep -q "udp dport 51820 accept"; then
    echo "Adding rule: Allow WireGuard UDP port 51820 in input chain"
    echo "add rule inet filter input udp dport 51820 accept" >> $TEMP_FILE
else
    echo "Rule already exists: Allow WireGuard UDP port 51820 in input chain"
fi

# Add specific masquerade rule for WireGuard traffic in the postrouting chain
if ! nft list chain inet nat postrouting | grep -q "ip saddr 10.8.0.0/24 oif \"$outside_interface\" masquerade"; then
    echo "Adding rule: Masquerade WireGuard traffic (10.8.0.0/24) via $outside_interface"
    echo "add rule inet nat postrouting ip saddr 10.8.0.0/24 oif $outside_interface masquerade" >> $TEMP_FILE
else
    echo "Rule already exists: Masquerade WireGuard traffic (10.8.0.0/24) via $outside_interface"
fi

# Execute the nftables script
chmod +x $TEMP_FILE
$TEMP_FILE
rm $TEMP_FILE

# Save the nftables configuration
echo "Saving nftables configuration..."
nft list ruleset > /etc/nftables.conf

# Save updated nftables configuration
nft list ruleset > /tmp/nftables_after.txt

# Show the updated nftables configuration
echo ""
echo "============================================================"
echo "UPDATED NFTABLES CONFIGURATION"
echo "============================================================"
echo ""
echo "INPUT CHAIN:"
echo "------------------------------------------------------------"
nft list chain inet filter input
echo ""
echo "FORWARD CHAIN:"
echo "------------------------------------------------------------"
nft list chain inet filter forward
echo ""
echo "NAT POSTROUTING CHAIN:"
echo "------------------------------------------------------------"
nft list chain inet nat postrouting
echo ""

# Show diff of changes
echo "============================================================"
echo "CHANGES MADE (DIFF):"
echo "============================================================"
diff -u /tmp/nftables_before.txt /tmp/nftables_after.txt
echo ""

echo "WireGuard forwarding rules have been added."
echo "The following interfaces are now configured for WireGuard VPN access:"
if [ "$inside_selected" = "1" ]; then
    echo "- $inside_interface"
fi
if [ "$sub_selected" = "1" ] && [ -n "$sub_interface" ]; then
    echo "- $sub_interface"
fi
echo ""

if [ "$wg_exists" = false ]; then
    echo "IMPORTANT: The WireGuard interface (wg0) does not exist yet."
    echo "The rules have been added to nftables, but they may not appear in the output"
    echo "until the WireGuard interface is created."
    echo ""
    echo "To create the WireGuard interface, you need to:"
    echo "1. Create a WireGuard configuration file at /etc/wireguard/wg0.conf"
    echo "2. Start the WireGuard interface with: sudo wg-quick up /etc/wireguard/wg0.conf"
    echo "3. Enable the WireGuard service with: sudo systemctl enable --now [email protected]"
    echo ""
    echo "After the WireGuard interface is created, the rules will take effect."
    echo "You can verify this by running: sudo nft list chain inet filter forward"
fi

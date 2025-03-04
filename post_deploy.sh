#!/bin/bash

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
TEXTRESET="\033[0m"
clear

# Install and configure dnf-automatic for security updates only
echo -e "${GREEN}Configuring system for security updates only...${TEXTRESET}"
sleep 3
sudo dnf -y install dnf-automatic

# Backup and modify automatic.conf
sudo cp /etc/dnf/automatic.conf /etc/dnf/automatic.conf.bak
sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer
echo -e "${GREEN}dnf-automatic is installed and configured to apply only security updates.${TEXTRESET}"
sleep 4

# Update /etc/issue for login information
sudo bash -c 'cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF'

clear
# Setup DNS
echo -e "${GREEN}Configuring Inside interface for DNS Resolution.${TEXTRESET}"
sleep 4

# Function to manage inside interfaces and update DNS settings
manage_inside_dns() {
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')
    if [ -z "$main_interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi
    echo -e "${GREEN}Main inside interface found: $main_interface${TEXTRESET}"

    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        echo -e "${RED}No connections found for interface: $main_interface and its sub-interfaces.${TEXTRESET}"
        exit 1
    fi

    if systemctl is-active --quiet named; then
        dns_servers="127.0.0.1 208.67.222.222 208.67.220.220"
        echo -e "${GREEN}Using DNS servers:${TEXTRESET} $dns_servers (named is active)"
    else
        dns_servers="208.67.222.222 208.67.220.220"
        echo -e "${YELLOW}Using DNS servers:${TEXTRESET} $dns_servers (named is not active)"
    fi
    sleep 2

    for connection_name in $connection_names; do
        echo -e "${GREEN}Processing connection: $connection_name${TEXTRESET}"
        nmcli connection modify "$connection_name" ipv4.dns ""
        echo -e "${GREEN}Cleared existing DNS settings for connection:${TEXTRESET} $connection_name"
        nmcli connection modify "$connection_name" ipv4.dns "$dns_servers"
        echo -e "${GREEN}Set new DNS servers for connection:${TEXTRESET} $connection_name"
    done
    sleep 4
}
manage_inside_dns

# Setup startup scripts in rc.local
clear
echo -e "${GREEN}Installing Startup scripts to rc.local...${TEXTRESET}"
sleep 4

SRC_SCRIPT1="/root/RFWB/check_ip_EKF.sh"
DEST_SCRIPT1="/opt/check_ip_EKF.sh"
SRC_SCRIPT2="/root/RFWB/fw_delay_start.sh"
DEST_SCRIPT2="/opt/fw_delay_start.sh"
RC_LOCAL="/etc/rc.d/rc.local"

# Check and copy scripts
if [ ! -f "$SRC_SCRIPT1" ] || [ ! -f "$SRC_SCRIPT2" ]; then
    echo "One or more source scripts do not exist. Exiting."
    exit 1
fi

sudo cp "$SRC_SCRIPT1" "$DEST_SCRIPT1"
sudo cp "$SRC_SCRIPT2" "$DEST_SCRIPT2"
sudo chmod +x "$DEST_SCRIPT1" "$DEST_SCRIPT2"

# Setup rc.local
if [ ! -f "$RC_LOCAL" ]; then
    sudo touch "$RC_LOCAL"
fi
sudo chmod +x "$RC_LOCAL"

# Add scripts to rc.local
if ! grep -q "$DEST_SCRIPT1" "$RC_LOCAL"; then
    echo "$DEST_SCRIPT1" | sudo tee -a "$RC_LOCAL" >/dev/null
fi
if ! grep -q "$DEST_SCRIPT2" "$RC_LOCAL"; then
    echo "$DEST_SCRIPT2" | sudo tee -a "$RC_LOCAL" >/dev/null
fi

# Enable and start rc-local service
if ! systemctl is-enabled rc-local.service &>/dev/null; then
    sudo ln -s "$RC_LOCAL" /etc/rc.local
    sudo systemctl enable rc-local
fi
if ! systemctl is-active rc-local.service &>/dev/null; then
    sudo systemctl start rc-local
fi

echo "Setup complete. The scripts $DEST_SCRIPT1 and $DEST_SCRIPT2 will run at startup."
sleep 4

# Manage inside gateway entries
clear
echo -e "${GREEN}Updating the Inside Gateway Entries...${TEXTRESET}"
sleep 4
manage_inside_gw() {
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')
    if [ -z "$main_interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi
    echo -e "${GREEN}Main inside interface found: $main_interface${TEXTRESET}"

    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        echo -e "${RED}No connections found for interface: $main_interface and its sub-interfaces.${TEXTRESET}"
        exit 1
    fi

    for connection_name in $connection_names; do
        echo -e "${GREEN}Processing connection:${TEXTRESET} $connection_name"
        nmcli connection modify "$connection_name" ipv4.gateway ""
        echo -e "${GREEN}Removed gateway for connection:${TEXTRESET} $connection_name"
    done
}
manage_inside_gw
sleep 4

# Reorganize nftables
clear
echo -e "${GREEN}Organizing nftables for efficient processing${TEXTRESET}"
sleep 4

NFTABLES_FILE="/etc/sysconfig/nftables.conf"
BACKUP_FILE="/etc/sysconfig/nftables.conf.bak"
TMP_FILE="/tmp/nftables_chain_input_filtered.tmp"

cp "$NFTABLES_FILE" "$BACKUP_FILE"
echo "Backup created at $BACKUP_FILE."

awk '
  BEGIN {
    rule_order["type filter hook input priority filter; policy drop;"] = 1
    rule_order["iif \"lo\" accept"] = 2
    rule_order["ct state established,related accept"] = 3
  }
  /chain input/ {in_block=1; block=""; next}
  in_block && /}/ {
    if (block ~ /log prefix "Blocked: " drop/) {
      split(block, lines, "\n")
      for (i in lines) {
        trimmed = lines[i]
        sub(/^[ \t]+/, "", trimmed)
        sub(/\r$/, "", trimmed)
        if (trimmed == "") continue
        if (rule_order[trimmed] > 0) {
          ordered_rules[rule_order[trimmed]] = trimmed
        } else if (trimmed ~ /ip saddr @threat_block drop/) {
          ip_saddr_line = trimmed
        } else if (trimmed ~ /log prefix "Blocked: " drop/) {
          log_prefix_line = trimmed
        } else {
          other_rules[++other_rules_count] = trimmed
        }
      }
      formatted_block = "\tchain input {\n"
      for (i = 1; i <= length(ordered_rules); i++) {
        formatted_block = formatted_block "\t\t" ordered_rules[i] "\n"
      }
      for (i = 1; i <= other_rules_count; i++) {
        formatted_block = formatted_block "\t\t" other_rules[i] "\n"
      }
      if (ip_saddr_line) formatted_block = formatted_block "\t\t" ip_saddr_line "\n"
      if (log_prefix_line) formatted_block = formatted_block "\t\t" log_prefix_line "\n"
      formatted_block = formatted_block "\t}"
      print formatted_block
    }
    exit
  }
  in_block {block=block "\n" $0}
' "$NFTABLES_FILE" > "$TMP_FILE"

awk -v RS= -v ORS='\n\n' -v new_block="$(cat $TMP_FILE)" '
  /chain input.*{/,/}/ {
    if ($0 ~ /log prefix "Blocked: " drop/) {
      $0 = new_block
    }
  }
  { print }
' "$BACKUP_FILE" > "$NFTABLES_FILE"

echo "Reformatted content has been placed back into $NFTABLES_FILE."
sleep 4
clear

# Notify and handle firewall restart
echo "Firewall setup complete."
read -p "Do you want to restart the firewall now? (yes/no): " user_choice
if [[ "$user_choice" == "yes" ]]; then
    echo "Restarting the firewall..."
    sudo reboot
elif [[ "$user_choice" == "no" ]]; then
    echo "The firewall will not be restarted now."
else
    echo "Invalid choice. Please run the script again and select either 'yes' or 'no'."
fi

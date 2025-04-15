#!/bin/bash
update_login_console() {
    # Notify user with dialog
    dialog --title "Login Banner Update" \
           --infobox "Updating login console with server information (issue).\n" 6 60
    sleep 3

    # Update /etc/issue with dynamic login info
    sudo bash -c 'cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF'
}
configure_dnf_automatic() {
    exec 3>&1

    EPEL_CONFIG="/etc/dnf/automatic.conf"
    BACKUP_CONFIG="/etc/dnf/automatic.conf.bak"
    TIMER_CONFIG="/etc/systemd/system/dnf-automatic.timer.d/override.conf"

    # Initial message
    dialog --title "DNF Automatic Configuration" \
           --infobox "Configuring system to apply security updates using dnf-automatic..." 6 80
    sleep 3

    # Backup existing config
    dialog --title "Backing Up Configuration" \
           --infobox "Backing up current configuration:\n$EPEL_CONFIG -> $BACKUP_CONFIG" 6 60
    sudo cp "$EPEL_CONFIG" "$BACKUP_CONFIG"
    sleep 3

    # Modify configuration
    dialog --title "Applying Security-Only Settings" \
           --infobox "Setting upgrade_type security and apply_updates to 'yes'" 6 80
    sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' "$EPEL_CONFIG"
    sudo sed -i 's/^apply_updates.*/apply_updates = yes/' "$EPEL_CONFIG"
    sleep 3

    # Create timer override directory
    sudo mkdir -p /etc/systemd/system/dnf-automatic.timer.d

    # Schedule updates for 3 AM
    dialog --title "Setting Timer" \
           --infobox "Configuring dnf-automatic to run at 3:00 AM daily..." 6 60
    echo -e "[Timer]\nOnCalendar=*-*-* 03:00:00" | sudo tee "$TIMER_CONFIG" > /dev/null
    sleep 3

    # Reload systemd and enable/start the timer
    dialog --title "Reloading systemd" \
           --infobox "Reloading systemd and enabling dnf-automatic.timer" 6 60
    sudo systemctl daemon-reload
    sudo systemctl enable --now dnf-automatic.timer
    sleep 3

    # Validate config changes
    CONFIG_CHECK=$(grep -E 'upgrade_type|apply_updates' "$EPEL_CONFIG")
    if echo "$CONFIG_CHECK" | grep -q "apply_updates = yes"; then
        dialog --title "Configuration Success" \
               --infobox "dnf-automatic is set to apply security updates." 6 60
    else
        dialog --title "Configuration Error" \
               --msgbox "Failed to apply security settings to:\n$EPEL_CONFIG\nPlease check manually." 8 60
        exit 1
    fi
    sleep 3

    # Validate timer is running
    if ! systemctl is-active --quiet dnf-automatic.timer; then
        dialog --title "Timer Error" \
               --msgbox "dnf-automatic.timer is NOT running!\nCheck with:\n  journalctl -u dnf-automatic.timer" 8 60
        exit 1
    fi
    sleep 2

    # Internally check the schedule (but don't show it separately)
    if ! systemctl show dnf-automatic.timer | grep -q "OnCalendar=.*03:00:00"; then
        dialog --title "Schedule Error" \
               --msgbox "Failed to confirm the scheduled time!\nCheck:\n$TIMER_CONFIG" 8 60
        exit 1
    fi

    dialog --title "Setup Complete" \
           --infobox "dnf-automatic has been successfully configured for:\n• Security-only updates\n• Daily execution at 3:00 AM\n\nNo further action is required." 9 60
    sleep 3
    exec 3>&-
}

# Function to manage inside interfaces and update DNS settings using dialog
manage_inside_dns() {
    exec 3>&1

    # Initial notice
    dialog --title "DNS Update in Progress" \
           --infobox "Updating DNS entries for all 'inside' interfaces on the firewall..." 6 80
    sleep 3

    main_interface=$(nmcli device status | awk '/-inside/ {print $1}' | head -n 1)
    if [ -z "$main_interface" ]; then
        dialog --title "Error" --msgbox "No interface ending with '-inside' found." 7 50
        exit 1
    fi

    dialog --title "Inside Interface Found" --infobox "Main inside interface: $main_interface" 5 50
    sleep 3

    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        dialog --title "Error" --msgbox "No connections found for interface: $main_interface and its sub-interfaces." 7 60
        exit 1
    fi

    if systemctl is-active --quiet named; then
        dns_servers="127.0.0.1 208.67.222.222 208.67.220.220"
        dialog --title "DNS Configuration" --infobox "Using DNS servers:\n$dns_servers\n(named is active)" 7 50
    else
        dns_servers="208.67.222.222 208.67.220.220"
        dialog --title "DNS Configuration" --infobox "Using DNS servers:\n$dns_servers\n(named is NOT active)" 7 50
    fi
    sleep 3

    for connection_name in $connection_names; do
        dialog --title "Modifying DNS" --infobox "Processing connection:\n$connection_name" 6 50
        sleep 3

        nmcli connection modify "$connection_name" ipv4.dns ""
        dialog --title "DNS Cleared" --infobox "Cleared existing DNS for:\n$connection_name" 6 50
        sleep 3

        nmcli connection modify "$connection_name" ipv4.dns "$dns_servers"
        dialog --title "DNS Set" --infobox "Set DNS for:\n$connection_name\n$dns_servers" 7 50
        sleep 3
    done

    dialog --title "Done" --msgbox "DNS settings have been updated for all matching connections." 7 50
    exec 3>&-
}
# Function to configure rc.local with KEA startup script using dialog
setup_kea_startup_script() {
    exec 3>&1

    SRC_SCRIPT="/root/RFWB/kea_delay_start.sh"
    DEST_SCRIPT="/usr/local/bin/kea_delay_start.sh"
    RC_LOCAL="/etc/rc.d/rc.local"

    # Initial message
    dialog --title "KEA Startup Setup" \
           --infobox "Installing KEA startup script using rc.local..." 6 60
    sleep 3

    # Check if source script exists
    if [ ! -f "$SRC_SCRIPT" ]; then
        dialog --title "Error" \
               --msgbox "KEA startup script not found:\n$SRC_SCRIPT\n\nExiting." 8 60
        exit 1
    fi

    # Copy script to /usr/local/bin
    dialog --title "Copying Script" \
           --infobox "Copying KEA startup script to:\n$DEST_SCRIPT" 6 60
    sleep 3

    sudo cp "$SRC_SCRIPT" "$DEST_SCRIPT"
    sudo chmod +x "$DEST_SCRIPT"

    dialog --title "Success" \
           --infobox "KEA startup script copied and made executable." 5 50
    sleep 3

    # Ensure rc.local exists
    if [ ! -f "$RC_LOCAL" ]; then
        dialog --title "rc.local" \
               --infobox "Creating rc.local file..." 5 50
        sudo touch "$RC_LOCAL"
        sleep 3
    fi

    sudo chmod +x "$RC_LOCAL"
    dialog --title "rc.local" \
           --infobox "rc.local is now executable." 5 50
    sleep 3

    # Add to rc.local if not already added
    if ! grep -q "$DEST_SCRIPT" "$RC_LOCAL"; then
        echo "$DEST_SCRIPT" | sudo tee -a "$RC_LOCAL" >/dev/null
        dialog --title "rc.local" \
               --infobox "Added $DEST_SCRIPT to rc.local." 5 60
        sleep 3
    fi

    # Enable rc-local service if not enabled
    if ! systemctl is-enabled rc-local.service &>/dev/null; then
        dialog --title "rc-local Service" \
               --infobox "Enabling rc-local service..." 5 50
        sudo ln -sf "$RC_LOCAL" /etc/rc.local
        sudo systemctl enable rc-local
        sleep 3
    fi

    # Start rc-local service if not running
    if ! systemctl is-active rc-local.service &>/dev/null; then
        dialog --title "rc-local Service" \
               --infobox "Starting rc-local service..." 5 50
        sudo systemctl start rc-local
        sleep 3
    fi

    dialog --title "Setup Complete" \
           --infobox "KEA startup script has been successfully configured to run at boot:\n$DEST_SCRIPT" 7 80
    sleep 3
    exec 3>&-
}
manage_inside_gw() {
    exec 3>&1

    # Initial notification
    dialog --title "Gateway Cleanup" \
           --infobox "Removing all default gateway entries from 'inside' interfaces..." 6 70
    sleep 3

    # Detect main -inside interface
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}' | head -n 1)
    if [ -z "$main_interface" ]; then
        dialog --title "Error" \
               --msgbox "No interface ending with '-inside' found." 6 50
        exit 1
    fi

    dialog --title "Interface Found" \
           --infobox "Main inside interface found:\n$main_interface" 6 50
    sleep 3

    # Get all associated connections for the interface
    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        dialog --title "Error" \
               --msgbox "No connections found for interface: $main_interface and its sub-interfaces." 7 60
        exit 1
    fi

    # Remove gateway from each connection
    for connection_name in $connection_names; do
        dialog --title "Processing" \
               --infobox "Removing gateway for connection:\n$connection_name" 6 50
        sleep 3

        nmcli connection modify "$connection_name" ipv4.gateway ""

        dialog --title "Success" \
               --infobox "Gateway removed for:\n$connection_name" 6 50
        sleep 3
    done

    dialog --title "Done" \
           --infobox "All default gateways have been removed from connections on $main_interface." 6 70
           sleep 3
    exec 3>&-
}
organize_nft () {
NFTABLES_FILE="/etc/sysconfig/nftables.conf"
TMP_FILE=$(mktemp)
DEBUG_FILE="/tmp/nftables_debug.conf"

exec 3>&1

# Initial notification
dialog --title "nftables Optimization" \
       --infobox "Reorganizing nftables rules for optimization." 6 60
sleep 3

# Backup original config
cp "$NFTABLES_FILE" "$NFTABLES_FILE.bak"
dialog --title "Backup Created" \
       --infobox "Original nftables config backed up to:\n$NFTABLES_FILE.bak" 6 60
sleep 3

# Check if a service is installed
service_is_installed() {
    systemctl list-unit-files | grep -q "^$1.service"
}

# Check if a service is running
service_is_running() {
    systemctl is-active --quiet "$1"
}

PORTSCAN_WAS_RUNNING=false

# Stop rfwb-portscan if running
if service_is_installed "rfwb-portscan"; then
    if service_is_running "rfwb-portscan"; then
        dialog --title "Stopping Service" --infobox "Stopping rfwb-portscan temporarily..." 5 50
        systemctl stop rfwb-portscan
        PORTSCAN_WAS_RUNNING=true
        sleep 2
    fi
fi

# Inform rule reorganization
dialog --title "nftables Rule Cleanup" \
       --infobox "Removing duplicate outbound block rules from output chain..." 6 70
sleep 3

# Remove old rules
sed -i '/chain output {/,/}/ {/ip daddr @threat_block log prefix "Outbound Blocked:" drop/d;}' "$NFTABLES_FILE"
sed -i '/chain output {/,/}/ {/ip daddr @threat_block log prefix "Outbound Blocked: " drop/d;}' "$NFTABLES_FILE"

# Rewrite config with cleaned ruleset
awk '
  BEGIN {
    in_input = 0;
    in_output = 0;
    in_portscan = 0;
    input_header = "";
    output_header = "";
    input_rules = "";
    output_rules = "";
    input_policy = "    type filter hook input priority filter; policy drop;";
    output_policy = "    type filter hook output priority filter; policy accept;";
    threat_rule = "    ip saddr @threat_block drop";
    log_rule = "    log prefix \"Blocked:\" drop";
    threat_out_rule = "    ip daddr @threat_block log prefix \"Outbound Blocked:\" drop";
    threat_out_seen = 0;
  }

  /table inet portscan/ {
    in_portscan = 1;
  }

  /chain input/ && !in_portscan {
    in_input = 1;
    input_header = $0;
    input_rules = "";
    next;
  }

  /chain output/ {
    in_output = 1;
    output_header = $0;
    output_rules = "";
    next;
  }

  in_input && /}/ {
    in_input = 0;
    print input_header;
    print input_policy;
    print threat_rule;
    print input_rules;
    print log_rule;
    print "}";
    next;
  }

  in_input {
    if ($0 ~ /ip saddr @threat_block drop/ || $0 ~ /log prefix "Blocked:/ || $0 ~ /type filter hook input priority filter; policy/) {
      next;
    } else {
      input_rules = input_rules "\n" $0;
    }
    next;
  }

  in_output && /}/ {
    in_output = 0;
    print output_header;
    print output_policy;
    if (!threat_out_seen) {
      print threat_out_rule;
      threat_out_seen = 1;
    }
    print output_rules;
    print "}";
    next;
  }

  in_output {
    if ($0 ~ /ip daddr @threat_block log prefix "Outbound Blocked: "/ || $0 ~ /type filter hook output priority filter; policy/) {
      next;
    } else {
      output_rules = output_rules "\n" $0;
    }
    next;
  }

  { print }
' "$NFTABLES_FILE" > "$TMP_FILE"

cp "$TMP_FILE" "$DEBUG_FILE"
dialog --title "Debug File Saved" \
       --infobox "Modified nftables configuration saved to:\n$DEBUG_FILE" 6 60
sleep 3

mv "$TMP_FILE" "$NFTABLES_FILE"
chown --reference="$NFTABLES_FILE.bak" "$NFTABLES_FILE"
chmod --reference="$NFTABLES_FILE.bak" "$NFTABLES_FILE"
restorecon -v "$NFTABLES_FILE" &>/dev/null

# Validate nftables config
if nft -c -f "$NFTABLES_FILE"; then
    dialog --title "Validation" \
           --infobox "nftables configuration is valid.\nReloading firewall..." 6 50
    systemctl restart nftables
    sleep 3
else
    dialog --title "ERROR" \
           --msgbox "nftables configuration test failed!\nRestoring previous config..." 7 60
    cp "$NFTABLES_FILE.bak" "$NFTABLES_FILE"
    systemctl restart nftables
    dialog --title "Recovery" \
           --msgbox "Restored from backup.\nCheck debug output:\n$DEBUG_FILE" 7 60
fi

# Restart rfwb-portscan if it was previously running
if [[ "$PORTSCAN_WAS_RUNNING" == true ]]; then
    dialog --title "Restarting" \
           --infobox "Restarting rfwb-portscan service..." 5 50
    systemctl start rfwb-portscan
    sleep 2
fi

# Final service status checks
status_msg=""

if service_is_installed "rfwb-portscan"; then
    if service_is_running "rfwb-portscan"; then
        status_msg+="rfwb-portscan is running.\n"
    else
        systemctl start rfwb-portscan
        status_msg+="rfwb-portscan was restarted.\n"
    fi
fi

if service_is_installed "rfwb-ps-mon"; then
    if service_is_running "rfwb-ps-mon"; then
        status_msg+="rfwb-ps-mon is running.\n"
    else
        systemctl start rfwb-ps-mon
        status_msg+="rfwb-ps-mon was restarted.\n"
    fi
fi

dialog --title "Final Status" --infobox "$status_msg" 10 60
sleep 3
exec 3>&-
}
#!/bin/bash

prompt_firewall_restart() {
    exec 3>&1

    dialog --title "Firewall Setup Complete" \
           --yesno "The firewall setup is complete.\n\nDo you want to restart the system now?" 8 60

    response=$?

    case $response in
        0)
            dialog --title "Rebooting" \
                   --infobox "Restarting the firewall now..." 5 50
            sleep 2
            sudo reboot
            ;;
        1)
            dialog --title "Reboot Skipped" \
                   --msgbox "The firewall will not be restarted now." 6 50
            ;;
        *)
            dialog --title "Invalid Input" \
                   --msgbox "No valid choice made. Please run the script again to restart the firewall." 6 60
            ;;
    esac

    exec 3>&-
}
prompt_firewall_restart() {
    exec 3>&1

    dialog --title "Firewall Setup Complete" \
           --yesno "The firewall setup is complete.\n\nDo you want to restart the system now?" 8 60

    response=$?

    case $response in
        0)
            dialog --title "Rebooting" \
                   --infobox "Restarting the firewall now..." 5 50
            sleep 2
            sudo reboot
            ;;
        1)
            dialog --title "Reboot Skipped" \
                   --msgbox "The firewall will not be restarted now." 6 50
            ;;
        *)
            dialog --title "Invalid Input" \
                   --msgbox "No valid choice made. Please run the script again to restart the firewall." 6 60
            ;;
    esac

    exec 3>&-
}
configure_dnf_automatic
manage_inside_dns
update_login_console
setup_kea_startup_script
manage_inside_gw
organize_nft
prompt_firewall_restart

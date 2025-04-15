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

# Function to manage inside interfaces and update DNS settings using dialog
manage_inside_dns() {
    exec 3>&1

    # Initial notice
    dialog --title "DNS Update in Progress" \
           --infobox "Updating DNS entries for all 'inside' interfaces on the firewall...\nPlease wait." 6 80
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

# Run the function
update_login_console
manage_inside_dns


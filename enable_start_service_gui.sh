#!/bin/bash

# Define colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
TEXTRESET="\033[0m"

# Check if dialog is installed
if ! command -v dialog &>/dev/null; then
    echo -e "${RED}Dialog is not installed. Please install it to use this script.${TEXTRESET}"
    exit 1
fi

# Function to show an infobox message with a title
show_infobox() {
    dialog --title "Checking installed services" --infobox "$1" 5 70
    sleep 2
}

# Function to check if a package is installed
check_package_installed() {
    local package_name="$1"
    if dnf list installed "$package_name" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to enable and start a service
enable_and_start_service() {
    local service_name="$1"
    show_infobox "Enabling $service_name service to start on boot..."
    sudo systemctl enable "$service_name"

    show_infobox "Starting $service_name service..."
    sudo systemctl start "$service_name"

    if systemctl is-active --quiet "$service_name"; then
        show_infobox "$service_name service is running."
    else
        show_infobox "$service_name service failed to start."
    fi
}

# Display a starting banner with a title
dialog --title "Checking activated services" --infobox "Enabling and Starting services..." 5 70
sleep 3

# Main script execution
for service in netdata evebox ntopng suricata avahi net-snmp; do
    if check_package_installed "$service"; then
        enable_and_start_service "$service"
    fi
done

# Special handling for bind
if check_package_installed "bind"; then
    enable_and_start_service "named"
fi

# Special handling for Cockpit
if check_package_installed "cockpit"; then
    enable_and_start_service "cockpit.socket"
fi

# Special handling for Kea
if check_package_installed "isc-kea-dhcp4"; then
    enable_and_start_service "kea-dhcp4"
fi

# Special handling for Kea DDNS
if check_package_installed "isc-kea-dhcp-ddns"; then
    enable_and_start_service "kea-dhcp-ddns"
fi

if check_package_installed "ddclient"; then
    show_infobox "ddclient is installed. Please manually configure it for your DDNS requirements."
    sleep 3
fi

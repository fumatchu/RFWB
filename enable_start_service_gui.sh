#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Check if dialog is installed
if ! command -v dialog &> /dev/null; then
    echo -e "${RED}Dialog is not installed. Please install it to use this script.${TEXTRESET}"
    exit 1
fi

# Function to show an infobox message
show_infobox() {
    dialog --infobox "$1" 5 50
    sleep 3
}

# Function to check if a package is installed
check_package_installed() {
    local package_name="$1"
    if dnf list installed "$package_name" &> /dev/null; then
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

# Main script execution
for service in bind isc-kea-dhcp4 cockpit webmin ntopng suricata filebeat kibana elasticsearch; do
    if check_package_installed "$service"; then
        enable_and_start_service "$service"
    else
        show_infobox "$service is not installed. Skipping..."
    fi
done

if check_package_installed "ddclient"; then
    show_infobox "ddclient is installed. Please manually configure it for your DDNS requirements."
fi

echo -e "${GREEN}Script execution completed.${TEXTRESET}"

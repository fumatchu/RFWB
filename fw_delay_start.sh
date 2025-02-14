#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
TEXTRESET="\033[0m"

# Check the status of the nftables service
echo -e "${YELLOW}Checking the status of the nftables service...${TEXTRESET}"
nftables_status=$(sudo systemctl is-active nftables)

if [ "$nftables_status" != "active" ]; then
    echo -e "${RED}The nftables service is not running. Delaying service start for 10 seconds...${TEXTRESET}"
    sleep 10

    echo -e "${YELLOW}Attempting to start the nftables service...${TEXTRESET}"
    sudo systemctl start nftables

    # Validate that the service is now running
    nftables_status=$(sudo systemctl is-active nftables)
    if [ "$nftables_status" == "active" ]; then
        echo -e "${GREEN}The nftables service has been successfully started and is running.${TEXTRESET}"
    else
        echo -e "${RED}Failed to start the nftables service. Please check the system logs for more information.${TEXTRESET}"
    fi
else
    echo -e "${GREEN}The nftables service is already running.${TEXTRESET}"
fi

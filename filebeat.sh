#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
TEXTRESET="\033[0m"

# Install Filebeat
echo -e "Installing Filebeat..."
sudo dnf install --enablerepo=elasticsearch filebeat -y

# Define Filebeat configuration file path
FILEBEAT_YML="/etc/filebeat/filebeat.yml"
PASSWORD_FILE="/root/elastic_password"

# Modify Filebeat configuration
echo -e "Configuring Filebeat..."
password=$(cat "$PASSWORD_FILE")

# Use sed to uncomment and update the username and password lines, preserving indentation
sudo sed -i -e 's/^\([[:space:]]*\)#\(username: "elastic"\)/\1\2/' \
            -e "s/^\([[:space:]]*\)#password: \"changeme\"/\1password: \"$password\"/" \
            "$FILEBEAT_YML"

# Append setup.ilm.overwrite: true to the configuration file
echo "setup.ilm.overwrite: true" | sudo tee -a "$FILEBEAT_YML" >/dev/null

# Validate configuration with Elasticsearch
echo -e "Validating Filebeat configuration..."
curl_output=$(curl -s -u elastic:"$password" http://localhost:9200)

if echo "$curl_output" | grep -q '"tagline" : "You Know, for Search"'; then
    echo -e "${GREEN}Filebeat authenticated successfully with Elasticsearch.${TEXTRESET}"
else
    echo -e "${RED}Filebeat could not authenticate to Elasticsearch.${TEXTRESET}"
    exit 1
fi

# Enable Suricata module in Filebeat
echo -e "Enabling Suricata module..."
sudo filebeat modules enable suricata

# Modify Suricata module configuration
SURICATA_YML="/etc/filebeat/modules.d/suricata.yml"
sudo sed -i 's/^  enabled: false/  enabled: true/' "$SURICATA_YML"
sudo sed -i 's|^  #var.paths:.*|  var.paths: ["/var/log/suricata/eve.json"]|' "$SURICATA_YML"

# Run Filebeat setup with a spinner
echo -e "Running Filebeat setup..."
{
    filebeat setup
} &
setup_pid=$!

# Spinner function
spin() {
    local -a marks=('-' '\' '|' '/')
    while kill -0 $setup_pid 2>/dev/null; do
        for mark in "${marks[@]}"; do
            echo -ne "\r$mark"
            sleep 0.1
        done
    done
}

# Start the spinner
spin
wait $setup_pid
setup_exit_code=$?

# Check the exit code of the filebeat setup
if [ $setup_exit_code -ne 0 ]; then
    echo -e "\r${RED}Filebeat setup encountered an error. Exiting.${TEXTRESET}"
    exit 1
fi

echo -e "\r${GREEN}Filebeat setup completed successfully.${TEXTRESET}"

# Enable and start Filebeat service
echo -e "Starting Filebeat service..."
sudo systemctl enable filebeat --now

# Check if Filebeat service is running
if systemctl is-active --quiet filebeat; then
    echo -e "${GREEN}Filebeat service is running successfully.${TEXTRESET}"
else
    echo -e "${RED}Filebeat service failed to start.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}Filebeat installation and configuration completed successfully.${TEXTRESET}"

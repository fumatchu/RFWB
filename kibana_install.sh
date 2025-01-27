#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Define paths
ELASTIC_CERT_PATH="/etc/elasticsearch/certs/http_ca.crt"
KIBANA_DIR="/etc/kibana"
KIBANA_CONFIG="$KIBANA_DIR/kibana.yml"
KIBANA_BIN_DIR="/usr/share/kibana/bin"

# Function to copy Elasticsearch certificate to Kibana directory
copy_certificate() {
    echo -e "${YELLOW}Copying Elasticsearch certificate to Kibana directory...${TEXTRESET}"
    if sudo cp "$ELASTIC_CERT_PATH" "$KIBANA_DIR/"; then
        echo -e "${GREEN}Certificate copied successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to copy the certificate. Please check the paths and permissions.${TEXTRESET}"
        exit 1
    fi
}

# Function to generate Kibana encryption keys
generate_encryption_keys() {
    echo -e "${YELLOW}Generating Kibana encryption keys...${TEXTRESET}"

    # Capture only the lines with encryption keys from the output
    keys_output=$(sudo "$KIBANA_BIN_DIR/kibana-encryption-keys" generate -q 2>/dev/null | grep -E '^xpack\.')

    if [ -n "$keys_output" ]; then
        echo -e "${GREEN}Encryption keys generated successfully.${TEXTRESET}"
        echo "$keys_output"
    else
        echo -e "${RED}Failed to generate encryption keys.${TEXTRESET}"
        exit 1
    fi
}

# Function to update Kibana configuration
update_kibana_config() {
    local keys="$1"
    echo -e "${YELLOW}Updating Kibana configuration...${TEXTRESET}"
    if echo -e "\n$keys" | sudo tee -a "$KIBANA_CONFIG" > /dev/null; then
        echo -e "${GREEN}Kibana configuration updated successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update Kibana configuration.${TEXTRESET}"
        exit 1
    fi

    # Ensure no extraneous lines are left in the file
    sudo sed -i '/Generating Kibana encryption keys.../d' "$KIBANA_CONFIG"
    sudo sed -i '/Encryption keys generated successfully./d' "$KIBANA_CONFIG"
}

# Main script execution
main() {
    copy_certificate
    keys=$(generate_encryption_keys)
    update_kibana_config "$keys"
}

# Run the main function
main

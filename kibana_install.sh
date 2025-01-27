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
    if sudo cp "$ELASTIC_CERT_PATH" "$KIBANA_DIR/http_ca.crt"; then
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

    # Add encryption keys to the configuration file
    if echo -e "\n$keys" | sudo tee -a "$KIBANA_CONFIG" > /dev/null; then
        echo -e "${GREEN}Kibana configuration updated with encryption keys.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update Kibana configuration with encryption keys.${TEXTRESET}"
        exit 1
    fi

    # Ensure no extraneous lines are left in the file
    sudo sed -i '/Generating Kibana encryption keys.../d' "$KIBANA_CONFIG"
    sudo sed -i '/Encryption keys generated successfully./d' "$KIBANA_CONFIG"

    # Append telemetry settings to the configuration file
    if echo -e "\ntelemetry.optIn: false" | sudo tee -a "$KIBANA_CONFIG" > /dev/null && \
       echo "telemetry.allowChangingOptInStatus: false" | sudo tee -a "$KIBANA_CONFIG" > /dev/null; then
        echo -e "${GREEN}Telemetry settings added to Kibana configuration.${TEXTRESET}"
    else
        echo -e "${RED}Failed to add telemetry settings to Kibana configuration.${TEXTRESET}"
        exit 1
    fi

    # Update the elasticsearch.ssl.certificateAuthorities setting
    if sudo sed -i 's|^#*\(elasticsearch\.ssl\.certificateAuthorities:\).*|\1 [ "/etc/kibana/http_ca.crt" ]|' "$KIBANA_CONFIG"; then
        echo -e "${GREEN}Updated elasticsearch.ssl.certificateAuthorities in Kibana configuration.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update elasticsearch.ssl.certificateAuthorities in Kibana configuration.${TEXTRESET}"
        exit 1
    fi
}

# Function to validate Kibana configuration changes
validate_config_changes() {
    echo -e "${YELLOW}Validating Kibana configuration changes...${TEXTRESET}"

    # Validate encryption keys
    for key in xpack.encryptedSavedObjects.encryptionKey xpack.reporting.encryptionKey xpack.security.encryptionKey; do
        if ! grep -q "$key" "$KIBANA_CONFIG"; then
            echo -e "${RED}Missing $key in Kibana configuration.${TEXTRESET}"
            exit 1
        fi
    done

    # Validate telemetry settings
    if ! grep -q "telemetry.optIn: false" "$KIBANA_CONFIG" || ! grep -q "telemetry.allowChangingOptInStatus: false" "$KIBANA_CONFIG"; then
        echo -e "${RED}Telemetry settings are not properly configured.${TEXTRESET}"
        exit 1
    fi

    # Validate certificate authorities setting
    if ! grep -q 'elasticsearch.ssl.certificateAuthorities: \[ "/etc/kibana/http_ca.crt" \]' "$KIBANA_CONFIG"; then
        echo -e "${RED}elasticsearch.ssl.certificateAuthorities is not properly configured.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}All Kibana configuration changes validated successfully.${TEXTRESET}"
}

# Main script execution
main() {
    copy_certificate
    keys=$(generate_encryption_keys)
    update_kibana_config "$keys"
    validate_config_changes
}

# Run the main function
main

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    # Find the interface ending with -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "Error: No interface ending with '-inside' found."
        exit 1
    fi

    # Extract the private IP address for the found interface
    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

    if [ -z "$ip" ]; then
        echo -e "Error: No IP address found for the interface $interface."
        exit 1
    fi

    echo "$ip"
}

# Function to configure Kibana
configure_kibana() {
    local private_ip="$1"
    local kibana_yml="/etc/kibana/kibana.yml"  # Path to your Kibana config

    echo "Backing up the original Kibana configuration..."
    # Backup the original Kibana configuration file
    sudo cp "$kibana_yml" "${kibana_yml}.bak"

    echo "Updating the Kibana configuration..."
    # Use awk to insert the server.host line below the specified comments
    sudo awk -v ip="$private_ip" '
    BEGIN {inserted=0}
    {
        print $0
        if (!inserted && $0 ~ /^#server.host: "localhost"$/) {
            print "server.host: \"" ip "\""
            inserted=1
        }
    }
    ' "$kibana_yml" > /tmp/kibana.yml && sudo mv /tmp/kibana.yml "$kibana_yml"
}

# Main execution
private_ip=$(find_private_ip)
configure_kibana "$private_ip"

echo "Kibana has been configured to use the private IP address: $private_ip"

# Define the file path
FILE_PATH="/etc/kibana/kibana.yml"

# Function to check and set the group of the file
check_and_set_group() {
    current_group=$(stat -c "%G" "$FILE_PATH")

    if [ "$current_group" != "kibana" ]; then
        echo -e "${YELLOW}Current group of $FILE_PATH is $current_group. Changing it to 'kibana'...${TEXTRESET}"
        sudo chgrp kibana "$FILE_PATH"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Group changed to 'kibana'.${TEXTRESET}"
        else
            echo -e "${RED}Error: Failed to change group to 'kibana'.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${GREEN}Group is already set to 'kibana'.${TEXTRESET}"
    fi
}

# Function to check and set the permissions of the file
check_and_set_permissions() {
    current_permissions=$(stat -c "%a" "$FILE_PATH")

    # Extract the group permissions (second digit in the octal representation)
    group_permissions=$(( (current_permissions / 10) % 10 ))

    if (( group_permissions != 6 )); then
        echo -e "${YELLOW}Current group permissions of $FILE_PATH are not 'rw'. Changing permissions...${TEXTRESET}"
        sudo chmod g+rw "$FILE_PATH"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Permissions changed to allow group 'kibana' read and write access.${TEXTRESET}"
        else
            echo -e "${RED}Error: Failed to change permissions.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${GREEN}Permissions are already correct for group 'kibana'.${TEXTRESET}"
    fi
}

# Main script execution
check_and_set_group
check_and_set_permissions

echo -e "${GREEN}Validation and correction of group and permissions completed successfully.${TEXTRESET}"
# Define the file path to store the enrollment token
TOKEN_FILE="/root/kibana_enrollment_token"

# Function to generate the enrollment token
generate_enrollment_token() {
    echo -e "${YELLOW}Generating Kibana enrollment token...${TEXTRESET}"
    token=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null)

    if [ -z "$token" ]; then
        echo -e "${RED}Error: Failed to generate enrollment token.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Enrollment token generated successfully.${TEXTRESET}"
    echo "$token" > "$TOKEN_FILE"
    echo -e "${GREEN}Enrollment token stored in ${TOKEN_FILE}.${TEXTRESET}"
}

# Function to start and enable the Kibana service
start_kibana_service() {
    echo -e "${YELLOW}Starting and enabling Kibana service...${TEXTRESET}"
    sudo systemctl enable kibana --now

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to start and enable Kibana service.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Kibana service started and enabled.${TEXTRESET}"
}

# Function to check the status of the Kibana service
check_kibana_status() {
    echo -e "${YELLOW}Checking Kibana service status...${TEXTRESET}"
    sudo systemctl status kibana --no-pager

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Kibana service is not running.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Kibana service is running.${TEXTRESET}"
}

# Main script execution
generate_enrollment_token
start_kibana_service
check_kibana_status

echo -e "${GREEN}Kibana setup and startup process completed successfully.${TEXTRESET}"

# Function to display initial instructions
display_instructions() {
    echo -e "${GREEN}The Kibana Service is now running${TEXTRESET}"
    echo -e "${YELLOW}The next step is to log in to the Elastic dashboard.${TEXTRESET}"
    echo ""
    echo "#1 - Open a browser (Leave this terminal open)"
    echo ""
    echo -e "#2 - In the address bar of your browser, navigate to ${GREEN}${private_ip}:5601${TEXTRESET}"
    echo ""
    echo "#3 - You will be asked for an enrollment token:"
    echo -e "Token: $(cat /root/kibana_enrollment_token)"
    echo ""
    echo "#4 - Once you have input your enrollment token, the webpage will ask you for the verification code:"
    echo ""
}

# Function to generate a new enrollment token
generate_enrollment_token() {
    echo -e "${YELLOW}Generating a new enrollment token...${TEXTRESET}"
    token=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null)
    echo "$token" > /root/kibana_enrollment_token
    echo -e "${GREEN}New token generated and saved to /root/kibana_enrollment_token.${TEXTRESET}"
}

# Function to get a verification code
get_verification_code() {
    echo -e "${YELLOW}Generating a verification code...${TEXTRESET}"
    sudo /usr/share/kibana/bin/kibana-verification-code
}

# Main script execution
display_instructions

# Loop to manage enrollment token generation
while true; do
    read -p "Was the enrollment token successful? If it was you're being asked for a verification code (yes/no): " token_success
    if [[ "$token_success" == "no" ]]; then
        generate_enrollment_token
    else
        break
    fi
done

# Prompt for verification code
while true; do
    read -p "Press Enter to get your Verification Code When Ready: "
    get_verification_code

    read -p "Do you need a new verification code? (yes/no): " code_needed
    if [[ "$code_needed" == "no" ]]; then
        break
    fi
done

echo -e "${GREEN}Setup completed. You can now proceed with using Kibana.${TEXTRESET}"

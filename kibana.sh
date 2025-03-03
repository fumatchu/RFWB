# Define paths
KIBANA_DIR="/etc/kibana"
KIBANA_CONFIG="$KIBANA_DIR/kibana.yml"

# Function to update Kibana configuration
update_kibana_config() {
    echo -e "Updating Kibana configuration...${TEXTRESET}"

    # Append telemetry settings to the configuration file
    if echo -e "\ntelemetry.optIn: false" | sudo tee -a "$KIBANA_CONFIG" >/dev/null &&
        echo "telemetry.allowChangingOptInStatus: false" | sudo tee -a "$KIBANA_CONFIG" >/dev/null; then
        echo -e "${GREEN}Telemetry settings added to Kibana configuration.${TEXTRESET}"
    else
        echo -e "${RED}Failed to add telemetry settings to Kibana configuration.${TEXTRESET}"
        exit 1
    fi
}

# Function to validate Kibana configuration changes
validate_config_changes() {
    echo -e "Validating Kibana configuration changes...${TEXTRESET}"

    # Validate telemetry settings
    if ! grep -q "telemetry.optIn: false" "$KIBANA_CONFIG" || ! grep -q "telemetry.allowChangingOptInStatus: false" "$KIBANA_CONFIG"; then
        echo -e "${RED}Telemetry settings are not properly configured.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}All Kibana configuration changes validated successfully.${TEXTRESET}"
}

# Main script execution
update_kibana_config
validate_config_changes

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
    local kibana_yml="/etc/kibana/kibana.yml" # Path to your Kibana config

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
' "$kibana_yml" >/tmp/kibana.yml && sudo mv /tmp/kibana.yml "$kibana_yml"
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
        echo -e "Current group of $FILE_PATH is $current_group. Changing it to 'kibana'...${TEXTRESET}"
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
    group_permissions=$(((current_permissions / 10) % 10))

    if ((group_permissions != 6)); then
        echo -e "Current group permissions of $FILE_PATH are not 'rw'. Changing permissions...${TEXTRESET}"
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

# Function to start and enable the Kibana service
start_kibana_service() {
    echo -e "Starting and enabling Kibana service...${TEXTRESET}"
    sudo systemctl enable kibana --now

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to start and enable Kibana service.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Kibana service started and enabled.${TEXTRESET}"
}

# Function to check the status of the Kibana service
check_kibana_status() {
    echo -e "Checking Kibana service status...${TEXTRESET}"
    sudo systemctl status kibana --no-pager

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Kibana service is not running.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Kibana service is running.${TEXTRESET}"
}

# Main script execution
start_kibana_service
check_kibana_status
echo -e "${GREEN}Kibana setup and startup process completed successfully.${TEXTRESET}"

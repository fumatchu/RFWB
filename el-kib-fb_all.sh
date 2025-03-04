#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
TEXTRESET="\033[0m"

# Unified installation and configuration function
install_el_kib_fb() {
    # Spinner function
    spinner() {
        local pid=$1
        local delay=0.1
        local spinstr='|/-\'
        while [ "$(ps a | awk '{print $1}' | grep "$pid")" ]; do
            local temp=${spinstr#?}
            printf " [%c]  " "$spinstr"
            local spinstr=$temp${spinstr%"$temp"}
            sleep $delay
            printf "\b\b\b\b\b\b"
        done
        printf "    \b\b\b\b"
    }

    # Install and configure Elasticsearch
    clear
    echo -e "${GREEN}Installing Elasticsearch and Kibana...${TEXTRESET}"
    echo -e "${YELLOW}Downloading packages this may take a few minutes...${TEXTRESET}"

    echo -e "Importing the Elastic GPG key...${TEXTRESET}"
    (sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch) & spinner $!
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Elastic GPG key imported successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to import Elastic GPG key.${TEXTRESET}"
        exit 1
    fi

    echo -e "Creating the Elasticsearch repository file...${TEXTRESET}"
    repo_file="/etc/yum.repos.d/elasticsearch.repo"
    (sudo bash -c "cat > $repo_file" <<EOF
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0
autorefresh=1
type=rpm-md
EOF
    ) & spinner $!
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Elasticsearch repository file created successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to create Elasticsearch repository file.${TEXTRESET}"
        exit 1
    fi

    INSTALL_LOG="/tmp/elastic_install.log"
    echo -e "${GREEN}Installing Elasticsearch and Kibana...${TEXTRESET}"
    (sudo dnf install --enablerepo=elasticsearch elasticsearch kibana -y | tee "$INSTALL_LOG") & spinner $!
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Elasticsearch and Kibana installed successfully.${TEXTRESET}"

        SECURITY_INFO_FILE="/root/elastic_security_info.txt"
        awk '/--------------------------- Security autoconfiguration information ------------------------------/,/-------------------------------------------------------------------------------------------------/' "$INSTALL_LOG" > "$SECURITY_INFO_FILE"

        if [ -s "$SECURITY_INFO_FILE" ]; then
            echo "Security configuration information captured and stored in $SECURITY_INFO_FILE."
            PASSWORD=$(grep "The generated password for the elastic built-in superuser is :" "$SECURITY_INFO_FILE" | awk -F': ' '{print $2}' | tr -d '[:space:]')
            PASSWORD_FILE="/root/elastic_password"
            if [ -n "$PASSWORD" ]; then
                echo "$PASSWORD" > "$PASSWORD_FILE"
                echo "Password for the elastic user stored in $PASSWORD_FILE."
            else
                echo "Error: Password not found in the security configuration information."
                exit 1
            fi
        else
            echo "Error: Security configuration information not found in the installation output."
            exit 1
        fi
    else
        echo -e "${RED}Failed to install Elasticsearch and Kibana.${TEXTRESET}"
        exit 1
    fi

    rm -f "$INSTALL_LOG"

    ELASTIC_YML="/etc/elasticsearch/elasticsearch.yml"
    JVM_OPTIONS_DIR="/etc/elasticsearch/jvm.options.d"
    JVM_HEAP_OPTIONS="$JVM_OPTIONS_DIR/jvm-heap.options"

    configure_elasticsearch() {
        echo -e "Backing up the original Elasticsearch configuration...${TEXTRESET}"
        sudo cp "$ELASTIC_YML" "${ELASTIC_YML}.bak"
        echo -e "Updating the Elasticsearch configuration...${TEXTRESET}"

        if grep -q "^xpack.security.enabled:" "$ELASTIC_YML"; then
            sudo sed -i 's/^xpack.security.enabled:.*/xpack.security.enabled: true/' "$ELASTIC_YML"
        else
            echo "xpack.security.enabled: true" | sudo tee -a "$ELASTIC_YML" >/dev/null
        fi

        if grep -q "^xpack.security.http.ssl:" "$ELASTIC_YML"; then
            sudo sed -i '/^xpack.security.http.ssl:/,/^ *keystore.path:/{s/^ *enabled:.*/  enabled: false/}' "$ELASTIC_YML"
        else
            echo -e "xpack.security.http.ssl:\n  enabled: false" | sudo tee -a "$ELASTIC_YML" >/dev/null
        fi

        if grep -q "^xpack.security.transport.ssl:" "$ELASTIC_YML"; then
            sudo sed -i '/^xpack.security.transport.ssl:/,/^ *truststore.path:/{s/^ *enabled:.*/  enabled: false/}' "$ELASTIC_YML"
        else
            echo -e "xpack.security.transport.ssl:\n  enabled: false" | sudo tee -a "$ELASTIC_YML" >/dev/null
        fi

        if ! grep -q "^discovery.type: single-node" "$ELASTIC_YML"; then
            echo "discovery.type: single-node" | sudo tee -a "$ELASTIC_YML" >/dev/null
        fi
        sudo sed -i 's/^cluster.initial_master_nodes:.*$/#&/' "$ELASTIC_YML" || {
            echo -e "${RED}Error: Failed to comment out initial master nodes setting.${TEXTRESET}"
            exit 1
        }
    }

    configure_jvm_heap() {
        sudo mkdir -p "$JVM_OPTIONS_DIR"
        echo "-Xms3g" | sudo tee "$JVM_HEAP_OPTIONS" >/dev/null
        echo "-Xmx3g" | sudo tee -a "$JVM_HEAP_OPTIONS" >/dev/null
    }

    echo -e "Configuring Elasticsearch...${TEXTRESET}"
    configure_elasticsearch
    echo -e "Configuring JVM heap size...${TEXTRESET}"
    configure_jvm_heap

    find_interface() {
        interface=$(nmcli device status | awk '/-inside/ {print $1}')
        if [ -z "$interface" ]; then
            echo -e "${RED}Error: No interface with a connection ending in '-inside' found.${TEXTRESET}"
            exit 1
        fi
        echo "$interface"
    }

    configure_nftables() {
        local interface="$1"
        echo -e "Configuring nftables for interface: $interface...${TEXTRESET}"
        sudo systemctl enable nftables
        sudo systemctl start nftables
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi
        if ! sudo nft list chain inet filter input | grep -q "iifname \"$interface\" tcp dport 5601 accept"; then
            sudo nft add rule inet filter input iifname "$interface" tcp dport 5601 accept
            echo -e "${GREEN}Rule added: Allow TCP traffic on port 5601 for interface $interface${TEXTRESET}"
        else
            echo "Rule already exists: Allow TCP traffic on port 5601 for interface $interface"
        fi
        rfwb_status=$(systemctl is-active rfwb-portscan)
        if [ "$rfwb_status" == "active" ]; then
            systemctl stop rfwb-portscan
        fi
        sudo nft list ruleset >/etc/sysconfig/nftables.conf
        sudo systemctl restart nftables
        if [ "$rfwb_status" == "active" ]; then
            systemctl start rfwb-portscan
        fi
        sudo nft list chain inet filter input
    }

    interface=$(find_interface)
    configure_nftables "$interface"
    echo -e "${GREEN}Firewall configuration for port 5601 complete.${TEXTRESET}"

    reload_daemon() {
        echo -e "Reloading systemd daemon...${TEXTRESET}"
        if sudo systemctl daemon-reload; then
            echo -e "${GREEN}Systemd daemon reloaded successfully.${TEXTRESET}"
        else
            echo -e "${RED}Failed to reload systemd daemon.${TEXTRESET}"
            exit 1
        fi
    }

    enable_start_elasticsearch() {
        echo -e "Enabling and starting Elasticsearch service...${TEXTRESET}"
        if sudo systemctl enable elasticsearch --now; then
            echo -e "${GREEN}Elasticsearch service enabled and start command issued.${TEXTRESET}"
        else
            echo -e "${RED}Failed to enable and start Elasticsearch service.${TEXTRESET}"
            exit 1
        fi
    }

    check_status() {
        echo -e "Checking Elasticsearch service status...${TEXTRESET}"
        while true; do
            status=$(sudo systemctl is-active elasticsearch)
            if [ "$status" == "active" ]; then
                echo -e "${GREEN}Elasticsearch service is active and running.${TEXTRESET}"
                break
            else
                echo -e "Waiting for Elasticsearch service to start...${TEXTRESET}"
                sleep 5
            fi
        done
    }

    reload_daemon
    enable_start_elasticsearch
    check_status

    test_elasticsearch() {
        local url="http://localhost:9200"
        local password_file="/root/elastic_password"
        echo -e "Testing Elasticsearch response...${TEXTRESET}"
        if [[ -f "$password_file" ]]; then
            password=$(<"$password_file")
        else
            echo -e "${RED}Password file not found: $password_file${TEXTRESET}"
            exit 1
        fi
        response=$(curl -u elastic:"$password" "$url" 2>/dev/null)
        if echo "$response" | grep -q '"tagline" : "You Know, for Search"'; then
            echo -e "${GREEN}Elasticsearch is responding to queries.${TEXTRESET}"
            echo "$response"
        else
            echo -e "${RED}Failed to get a valid response from Elasticsearch.${TEXTRESET}"
            exit 1
        fi
    }

    test_elasticsearch
    echo -e "${GREEN}Elasticsearch Install Complete...${TEXTRESET}"

    # Update Kibana Configuration
    KIBANA_DIR="/etc/kibana"
    KIBANA_CONFIG="$KIBANA_DIR/kibana.yml"
    
    update_kibana_config() {
        echo -e "Updating Kibana configuration...${TEXTRESET}"

        if echo -e "\ntelemetry.optIn: false" | sudo tee -a "$KIBANA_CONFIG" >/dev/null &&
            echo "telemetry.allowChangingOptInStatus: false" | sudo tee -a "$KIBANA_CONFIG" >/dev/null; then
            echo -e "${GREEN}Telemetry settings added to Kibana configuration.${TEXTRESET}"
        else
            echo -e "${RED}Failed to add telemetry settings to Kibana configuration.${TEXTRESET}"
            exit 1
        fi
    }

    validate_config_changes() {
        echo -e "Validating Kibana configuration changes...${TEXTRESET}"
        if ! grep -q "telemetry.optIn: false" "$KIBANA_CONFIG" || ! grep -q "telemetry.allowChangingOptInStatus: false" "$KIBANA_CONFIG"; then
            echo -e "${RED}Telemetry settings are not properly configured.${TEXTRESET}"
            exit 1
        fi
        echo -e "${GREEN}All Kibana configuration changes validated successfully.${TEXTRESET}"
    }

    update_kibana_config
    validate_config_changes

    configure_kibana() {
        local kibana_yml="/etc/kibana/kibana.yml"

        echo "Backing up the original Kibana configuration..."
        sudo cp "$kibana_yml" "${kibana_yml}.bak"

        echo "Updating the Kibana configuration to listen on all interfaces..."
        sudo awk '
    BEGIN {inserted=0}
    {
        print $0
        if (!inserted && $0 ~ /^#server.host: "localhost"$/) {
            print "server.host: \"0.0.0.0\""
            inserted=1
        }
    }
    ' "$kibana_yml" >/tmp/kibana.yml && sudo mv /tmp/kibana.yml "$kibana_yml"
    }

    configure_kibana
    echo "Kibana has been configured to listen on all interfaces (0.0.0.0)."

    FILE_PATH="/etc/kibana/kibana.yml"

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

    check_and_set_permissions() {
        current_permissions=$(stat -c "%a" "$FILE_PATH")
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

    check_and_set_group
    check_and_set_permissions
    echo -e "${GREEN}Validation and correction of group and permissions completed successfully.${TEXTRESET}"

    start_kibana_service() {
        echo -e "Starting and enabling Kibana service...${TEXTRESET}"
        sudo systemctl enable kibana --now

        if [ $? -ne 0 ]; then
            echo -e "${RED}Error: Failed to start and enable Kibana service.${TEXTRESET}"
            exit 1
        fi

        echo -e "${GREEN}Kibana service started and enabled.${TEXTRESET}"
    }

    check_kibana_status() {
        echo -e "Checking Kibana service status...${TEXTRESET}"
        sudo systemctl status kibana --no-pager

        if [ $? -ne 0 ]; then
            echo -e "${RED}Error: Kibana service is not running.${TEXTRESET}"
            exit 1
        fi

        echo -e "${GREEN}Kibana service is running.${TEXTRESET}"
    }

    start_kibana_service
    check_kibana_status
    echo -e "${GREEN}Kibana setup and startup process completed successfully.${TEXTRESET}"

    RESET_PASSWORD_CMD="/usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system"
    PASSWORD_FILE="/root/kibana_system_password"
    KIBANA_YML="/etc/kibana/kibana.yml"
    OUTPUT=$(echo "y" | $RESET_PASSWORD_CMD 2>&1)
    NEW_PASSWORD=$(echo "$OUTPUT" | grep -oP 'New value: \K.*')

    if [ -n "$NEW_PASSWORD" ]; then
        echo "$NEW_PASSWORD" > "$PASSWORD_FILE"
        echo "New password for kibana_system user saved to $PASSWORD_FILE."
    else
        echo "Failed to capture the new password."
        exit 1
    fi

    echo "Updating the Kibana configuration file..."
    sudo sed -i 's/^#elasticsearch.username: "kibana_system"/elasticsearch.username: "kibana_system"/' "$KIBANA_YML"
    sudo sed -i "s|^#elasticsearch.password: .*|elasticsearch.password: \"$NEW_PASSWORD\"|" "$KIBANA_YML"

    echo "Restarting the Kibana service..."
    if sudo systemctl restart kibana; then
        echo "Kibana service restarted successfully."
    else
        echo "Failed to restart Kibana service."
        exit 1
    fi

    echo "Validating Kibana service status..."
    if sudo systemctl is-active --quiet kibana; then
        echo "Kibana service is active and running."
    else
        echo "Kibana service is not running."
        exit 1
    fi

    # Install and configure Filebeat
    echo -e "Installing Filebeat..."
    sudo dnf install --enablerepo=elasticsearch filebeat -y

    FILEBEAT_YML="/etc/filebeat/filebeat.yml"
    PASSWORD_FILE="/root/elastic_password"

    echo -e "Configuring Filebeat..."
    password=$(cat "$PASSWORD_FILE")

    sudo sed -i -e 's/^\([[:space:]]*\)#\(username: "elastic"\)/\1\2/' \
                -e "s/^\([[:space:]]*\)#password: \"changeme\"/\1password: \"$password\"/" \
                "$FILEBEAT_YML"

    echo "setup.ilm.overwrite: true" | sudo tee -a "$FILEBEAT_YML" >/dev/null

    echo -e "Validating Filebeat configuration..."
    curl_output=$(curl -s -u elastic:"$password" http://localhost:9200)

    if echo "$curl_output" | grep -q '"tagline" : "You Know, for Search"'; then
        echo -e "${GREEN}Filebeat authenticated successfully with Elasticsearch.${TEXTRESET}"
    else
        echo -e "${RED}Filebeat could not authenticate to Elasticsearch.${TEXTRESET}"
        exit 1
    fi

    echo -e "Enabling Suricata module..."
    sudo filebeat modules enable suricata

    SURICATA_YML="/etc/filebeat/modules.d/suricata.yml"
    sudo sed -i 's/^  enabled: false/  enabled: true/' "$SURICATA_YML"
    sudo sed -i 's|^  #var.paths:.*|  var.paths: ["/var/log/suricata/eve.json"]|' "$SURICATA_YML"

    echo -e "Running Filebeat setup..."
    {
        filebeat setup
    } &
    setup_pid=$!

    spin
    wait $setup_pid
    setup_exit_code=$?

    if [ $setup_exit_code -ne 0 ]; then
        echo -e "${RED}Filebeat setup encountered an error. Exiting.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Filebeat setup completed successfully.${TEXTRESET}"

    echo -e "Starting Filebeat service..."
    sudo systemctl enable filebeat --now

    if systemctl is-active --quiet filebeat; then
        echo -e "${GREEN}Filebeat service is running successfully.${TEXTRESET}"
    else
        echo -e "${RED}Filebeat service failed to start.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Filebeat installation and configuration completed successfully.${TEXTRESET}"
}

# Execute the function
install_el_kib_fb

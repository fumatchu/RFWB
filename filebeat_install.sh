#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Paths and file variables
SOURCE_CERT_PATH="/etc/elasticsearch/certs/http_ca.crt"
DEST_CERT_DIR="/etc/filebeat"
DEST_CERT_PATH="$DEST_CERT_DIR/http_ca.crt"
FILEBEAT_YML="/etc/filebeat/filebeat.yml"
SURICATA_MODULE_YML="/etc/filebeat/modules.d/suricata.yml"
ELASTIC_PASSWORD_FILE="/root/elastic_password"

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi

    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

    if [ -z "$ip" ]; then
        echo -e "${RED}Error: No IP address found for the interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$ip"
}

# Install Filebeat
install_filebeat() {
    echo -e "${YELLOW}Installing Filebeat...${TEXTRESET}"
    sudo dnf install --enablerepo=elasticsearch filebeat -y

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Filebeat installed successfully.${TEXTRESET}"
    else
        echo -e "${RED}Error: Failed to install Filebeat.${TEXTRESET}"
        exit 1
    fi
}

# Copy the http_ca.crt file locally
copy_certificate_locally() {
    if [ -f "$SOURCE_CERT_PATH" ]; then
        echo -e "${YELLOW}Copying http_ca.crt from $SOURCE_CERT_PATH to $DEST_CERT_DIR...${TEXTRESET}"
        sudo cp "$SOURCE_CERT_PATH" "$DEST_CERT_PATH"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Certificate copied successfully to $DEST_CERT_PATH.${TEXTRESET}"
        else
            echo -e "${RED}Error: Failed to copy certificate to $DEST_CERT_PATH.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${RED}Error: Certificate file not found at $SOURCE_CERT_PATH.${TEXTRESET}"
        exit 1
    fi
}

# Configure Filebeat
configure_filebeat() {
    local private_ip="$1"

    if [ ! -f "$ELASTIC_PASSWORD_FILE" ]; then
        echo -e "${RED}Error: Elastic password file not found at $ELASTIC_PASSWORD_FILE.${TEXTRESET}"
        exit 1
    fi

    local elastic_password
    elastic_password=$(cat "$ELASTIC_PASSWORD_FILE")

    echo -e "${YELLOW}Backing up the original Filebeat configuration...${TEXTRESET}"
    sudo cp "$FILEBEAT_YML" "${FILEBEAT_YML}.bak"

    echo -e "${YELLOW}Updating the Filebeat configuration...${TEXTRESET}"
    sudo awk -v ip="$private_ip" -v password="$elastic_password" '
    BEGIN {in_elasticsearch=0; inserted_kibana=0}
    {
        if ($0 ~ /^setup.kibana:/) {
            in_elasticsearch=0
        }
        if ($0 ~ /^output.elasticsearch:/) {
            in_elasticsearch=1
        }
        if (!inserted_kibana && $0 ~ /^  #host: "localhost:5601"$/) {
            print "  host: \"" ip ":5601\""
            print "  protocol: \"http\""
            print "  ssl.enabled: true"
            print "  ssl.certificate_authorities: [\"/etc/filebeat/http_ca.crt\"]"
            inserted_kibana=1
        }
        if (in_elasticsearch) {
            if ($0 ~ /^  hosts:/) {
                print "  hosts: [\"" ip ":9200\"]"
                next
            }
            if ($0 ~ /^  # Protocol/) {
                print "  protocol: \"https\""
            }
            if ($0 ~ /^  #api_key:/) {
                print "  username: \"elastic\""
                print "  password: \"" password "\""
                print "  ssl.certificate_authorities: [\"/etc/filebeat/http_ca.crt\"]"
                print "  ssl.verification_mode: full"
            }
        }
        print $0
    }
    END {
        print "\nsetup.ilm.overwrite: true"
    }
    ' "$FILEBEAT_YML" > /tmp/filebeat.yml && sudo mv /tmp/filebeat.yml "$FILEBEAT_YML"
}

# Modify Suricata module configuration
configure_suricata_module() {
    echo -e "${YELLOW}Configuring Suricata module...${TEXTRESET}"
    sudo awk '
    BEGIN {in_eve=0}
    {
        if ($0 ~ /^- module: suricata$/) {
            in_eve=0
        }
        if ($0 ~ /^  eve:$/) {
            in_eve=1
        }
        if (in_eve && $0 ~ /^    #enabled: false$/) {
            print "    enabled: true"
            next
        }
        if (in_eve && $0 ~ /^    #var.paths:/) {
            print "    var.paths: [\"/var/log/suricata/eve.json\"]"
            next
        }
        print $0
    }
    ' "$SURICATA_MODULE_YML" > /tmp/suricata.yml && sudo mv /tmp/suricata.yml "$SURICATA_MODULE_YML"
}

# Verify Elasticsearch connection and enable Suricata module
verify_and_enable_module() {
    local private_ip="$1"

    if [ ! -f "$ELASTIC_PASSWORD_FILE" ]; then
        echo -e "${RED}Error: Elastic password file not found at $ELASTIC_PASSWORD_FILE.${TEXTRESET}"
        exit 1
    fi

    local elastic_password
    elastic_password=$(cat "$ELASTIC_PASSWORD_FILE")

    echo -e "${YELLOW}Verifying Elasticsearch connection...${TEXTRESET}"
    curl -v --cacert "$DEST_CERT_PATH" "https://$private_ip:9200" -u elastic:"$elastic_password"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Elasticsearch connection verified successfully.${TEXTRESET}"
        echo -e "${YELLOW}Enabling Suricata module in Filebeat...${TEXTRESET}"
        sudo filebeat modules enable suricata

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Suricata module enabled successfully.${TEXTRESET}"
            configure_suricata_module
        else
            echo -e "${RED}Error: Failed to enable Suricata module.${TEXTRESET}"
        fi
    else
        echo -e "${RED}Error: Failed to verify Elasticsearch connection.${TEXTRESET}"
    fi
}

# Main script execution
install_filebeat
copy_certificate_locally
private_ip=$(find_private_ip)
configure_filebeat "$private_ip"
verify_and_enable_module "$private_ip"

echo -e "${GREEN}Filebeat setup and configuration completed successfully.${TEXTRESET}"

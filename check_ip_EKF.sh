#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    interface=$(nmcli device status | awk '/-inside/ {print $1}')
    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
        exit 1
    fi

    # Extract the private IP address for the found interface
    ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')
    if [ -z "$ip" ]; then
        echo -e "${RED}Error: No IP address found for the interface $interface.${TEXTRESET}"
        exit 1
    fi
    echo "$ip"
}

# Function to manage service state
manage_service() {
    service_name="$1"
    action="$2"
    echo -e "${YELLOW}${action^}ing $service_name service...${TEXTRESET}"
    sudo systemctl "$action" "$service_name"
    if systemctl is-active --quiet "$service_name"; then
        if [ "$action" == "stop" ]; then
            echo -e "${RED}$service_name service is still running. Exiting.${TEXTRESET}"
            exit 1
        else
            echo -e "${GREEN}$service_name service is running.${TEXTRESET}"
        fi
    else
        if [ "$action" == "start" ]; then
            echo -e "${RED}$service_name service failed to start. Exiting.${TEXTRESET}"
            exit 1
        else
            echo -e "${GREEN}$service_name service stopped successfully.${TEXTRESET}"
        fi
    fi
}

# Function to update IP in configuration file
update_ip_in_file() {
    config_file="$1"
    search_pattern="$2"
    new_ip="$3"
    if [ -n "$search_pattern" ]; then
        echo -e "${YELLOW}Changing IP from $search_pattern to $new_ip in $config_file.${TEXTRESET}"
        sudo sed -i "s/$search_pattern/$new_ip/g" "$config_file"
    else
        echo -e "${RED}No valid pattern found in $config_file to update.${TEXTRESET}"
    fi
}

# Function to check and update IP addresses in Kibana config
check_and_update_kibana_ip() {
    config_file="/etc/kibana/kibana.yml"
    interface_ip="$1"
    changed=0

    echo -e "${YELLOW}Validating IP addresses in $config_file...${TEXTRESET}"
    server_host_ip=$(awk '/# This section was automatically generated during setup./,0' "$config_file" | grep 'server.host:' | awk '{print $2}')
    elasticsearch_hosts_ip=$(grep 'elasticsearch.hosts:' "$config_file" | sed -n "s/.*['\"]https:\/\/\([0-9.]*\):.*/\1/p")
    elasticsearch_comma_hosts_ip=$(grep 'elasticsearch, hosts:' "$config_file" | sed -n "s/.*['\"]https:\/\/\([0-9.]*\):.*/\1/p")

    if [ -n "$server_host_ip" ] && [ "$interface_ip" != "$server_host_ip" ]; then
        echo -e "${YELLOW}Detected change: server.host IP in $config_file from $server_host_ip to $interface_ip.${TEXTRESET}"
        sudo sed -i "s/server.host: $server_host_ip/server.host: $interface_ip/" "$config_file"
        changed=1
    fi
    if [ -n "$elasticsearch_hosts_ip" ] && [ "$interface_ip" != "$elasticsearch_hosts_ip" ]; then
        echo -e "${YELLOW}Detected change: elasticsearch.hosts IP in $config_file from $elasticsearch_hosts_ip to $interface_ip.${TEXTRESET}"
        sudo sed -i "s|https://$elasticsearch_hosts_ip:9200|https://$interface_ip:9200|g" "$config_file"
        changed=1
    fi
    if [ -n "$elasticsearch_comma_hosts_ip" ] && [ "$interface_ip" != "$elasticsearch_comma_hosts_ip" ]; then
        echo -e "${YELLOW}Detected change: elasticsearch, hosts IP in $config_file from $elasticsearch_comma_hosts_ip to $interface_ip.${TEXTRESET}"
        sudo sed -i "s|https://$elasticsearch_comma_hosts_ip:9200|https://$interface_ip:9200|g" "$config_file"
        changed=1
    fi

    # Update elasticsearch.ssl.verificationMode setting only if there's a change and it's not already set to 'certificate'
    if [ "$changed" -eq 1 ]; then
        current_mode=$(grep 'elasticsearch.ssl.verificationMode:' "$config_file" | awk '{print $2}')
        if [ "$current_mode" != "certificate" ]; then
            echo -e "${YELLOW}Updating elasticsearch.ssl.verificationMode in $config_file to certificate...${TEXTRESET}"
            sudo sed -i 's/#elasticsearch\.ssl\.verificationMode: full/elasticsearch.ssl.verificationMode: certificate/' "$config_file"
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}Successfully updated elasticsearch.ssl.verificationMode to certificate in $config_file.${TEXTRESET}"
            fi
        else
            echo -e "${GREEN}elasticsearch.ssl.verificationMode is already set to certificate.${TEXTRESET}"
        fi
    fi

    return $changed
}

# Function to check and update IP addresses in Elasticsearch config
check_and_update_elasticsearch_ip() {
    config_file="/etc/elasticsearch/elasticsearch.yml"
    interface_ip="$1"
    changed=0

    echo -e "${YELLOW}Validating IP addresses in $config_file...${TEXTRESET}"
    config_ip=$(grep 'network.bind_host' "$config_file" | awk -F'[][]' '{print $2}' | awk -F', ' '{print $2}' | tr -d '"')
    if [ -n "$config_ip" ] && [ "$interface_ip" != "$config_ip" ]; then
        echo -e "${YELLOW}Detected change: network.bind_host IP in $config_file from $config_ip to $interface_ip.${TEXTRESET}"
        update_ip_in_file "$config_file" "$config_ip" "$interface_ip"
        changed=1
    fi

    return $changed
}

# Function to check and update IP addresses in Filebeat config
check_and_update_filebeat_ip() {
    config_file="/etc/filebeat/filebeat.yml"
    interface_ip="$1"
    changed=0

    echo -e "${YELLOW}Validating IP addresses in $config_file...${TEXTRESET}"
    filebeat_host_ip=$(grep 'host:' "$config_file" | sed -n  's/.*"\([0-9.]*\):5601".*/\1/p')
    filebeat_hosts_ip=$(grep 'hosts:' "$config_file" | sed -n 's/.*\["\([0-9.]*\):9200"\].*/\1/p')

    if [ -n "$filebeat_host_ip" ] && [ "$interface_ip" != "$filebeat_host_ip" ]; then
        echo -e "${YELLOW}Detected change: host IP in $config_file from $filebeat_host_ip to $interface_ip.${TEXTRESET}"
        update_ip_in_file "$config_file" "$filebeat_host_ip" "$interface_ip"
        changed=1
    fi
    if [ -n "$filebeat_hosts_ip" ] && [ "$interface_ip" != "$filebeat_hosts_ip" ]; then
        echo -e "${YELLOW}Detected change: hosts IP in $config_file from $filebeat_hosts_ip to $interface_ip.${TEXTRESET}"
        update_ip_in_file "$config_file" "$filebeat_hosts_ip" "$interface_ip"
        changed=1
    fi

    # Update ssl.verification_mode to none if IP address changed and it is not already set to none
    if [ "$changed" -eq 1 ]; then
        current_mode=$(grep 'ssl.verification_mode:' "$config_file" | awk '{print $2}')
        if [ "$current_mode" != "none" ]; then
            echo -e "${YELLOW}Updating ssl.verification_mode in $config_file to none...${TEXTRESET}"
            sudo sed -i 's/ssl\.verification_mode: full/ssl.verification_mode: none/' "$config_file"
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}Successfully updated ssl.verification_mode to none in $config_file.${TEXTRESET}"
            fi
        else
            echo -e "${GREEN}ssl.verification_mode is already set to none.${TEXTRESET}"
        fi
    fi

    return $changed
}

# Main script execution
interface_ip=$(find_private_ip)

# Track if any changes are made
needs_restart=0

# Check and update IP addresses
check_and_update_kibana_ip "$interface_ip" || needs_restart=1
check_and_update_elasticsearch_ip "$interface_ip" || needs_restart=1
check_and_update_filebeat_ip "$interface_ip" || needs_restart=1

# Only restart services if changes were made
if [ "$needs_restart" -eq 1 ]; then
    echo -e "${YELLOW}Changes detected, restarting services...${TEXTRESET}"

    # Stop services in the correct order
    manage_service "filebeat" "stop"
    manage_service "kibana" "stop"
    manage_service "elasticsearch" "stop"

    # Start services in the correct order
    manage_service "elasticsearch" "start"
    manage_service "kibana" "start"
    manage_service "filebeat" "start"
else
    echo -e "${GREEN}No changes detected. Services do not need to be restarted.${TEXTRESET}"
fi

#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Inform the user that the process is starting
echo -e "${YELLOW}Starting the installation of Elasticsearch and Kibana...${TEXTRESET}"

# Step 1: Import the Elastic GPG key
echo -e "${YELLOW}Importing the Elastic GPG key...${TEXTRESET}"
if sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch; then
    echo -e "${GREEN}Elastic GPG key imported successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to import Elastic GPG key.${TEXTRESET}"
    exit 1
fi

# Step 2: Create the Elasticsearch repository file
echo -e "${YELLOW}Creating the Elasticsearch repository file...${TEXTRESET}"
repo_file="/etc/yum.repos.d/elasticsearch.repo"
sudo bash -c "cat > $repo_file" << EOF
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0
autorefresh=1
type=rpm-md
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Elasticsearch repository file created successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to create Elasticsearch repository file.${TEXTRESET}"
    exit 1
fi

# Step 3: Install Elasticsearch and Kibana
echo -e "${YELLOW}Installing Elasticsearch and Kibana...${TEXTRESET}"
if sudo dnf install --enablerepo=elasticsearch elasticsearch kibana -y; then
    echo -e "${GREEN}Elasticsearch and Kibana installed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to install Elasticsearch and Kibana.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}Installation process completed successfully.${TEXTRESET}"

# Define the Elasticsearch configuration paths
ELASTIC_YML="/etc/elasticsearch/elasticsearch.yml"
JVM_OPTIONS_DIR="/etc/elasticsearch/jvm.options.d"
JVM_HEAP_OPTIONS="$JVM_OPTIONS_DIR/jvm-heap.options"

# Function to locate the server's private IP address using nmcli
find_private_ip() {
    # Find the interface ending with -inside
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

# Function to configure Elasticsearch
configure_elasticsearch() {
    local private_ip="$1"

    echo -e "${YELLOW}Backing up the original Elasticsearch configuration...${TEXTRESET}"
    # Backup the original Elasticsearch configuration file
    sudo cp "$ELASTIC_YML" "${ELASTIC_YML}.bak"

    echo -e "${YELLOW}Updating the Elasticsearch configuration...${TEXTRESET}"
    # Use awk to insert the network.bind_host line below the specified comments
    sudo awk -v ip="$private_ip" '
    BEGIN {inserted=0}
    {
        print $0
        if (!inserted && $0 ~ /^#network.host: 192.168.0.1$/) {
            print "network.bind_host: [\"127.0.0.1\", \"" ip "\"]"
            inserted=1
        }
    }
    ' "$ELASTIC_YML" > /tmp/elasticsearch.yml && sudo mv /tmp/elasticsearch.yml "$ELASTIC_YML"

    # Check if discovery.type: single-node is present, if not, append it
    if ! grep -q "^discovery.type: single-node" "$ELASTIC_YML"; then
        echo "discovery.type: single-node" | sudo tee -a "$ELASTIC_YML" > /dev/null
    fi

    # Comment out the initial master nodes setting if present
    sudo sed -i 's/^cluster.initial_master_nodes:.*$/#&/' "$ELASTIC_YML" || {
        echo -e "${RED}Error: Failed to comment out initial master nodes setting.${TEXTRESET}"
        exit 1
    }
}

# Function to set JVM heap size
configure_jvm_heap() {
    echo -e "${YELLOW}Configuring JVM heap size...${TEXTRESET}"
    # Create the JVM options directory if it doesn't exist
    sudo mkdir -p "$JVM_OPTIONS_DIR"

    # Write the JVM heap configuration
    echo "-Xms3g" | sudo tee "$JVM_HEAP_OPTIONS" > /dev/null
    echo "-Xmx3g" | sudo tee -a "$JVM_HEAP_OPTIONS" > /dev/null
}

# Main script execution
main() {
    echo -e "${YELLOW}Locating the server's private IP address...${TEXTRESET}"
    private_ip=$(find_private_ip)

    if [ -z "$private_ip" ]; then
        echo -e "${RED}Error: Unable to determine the private IP address.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Private IP identified as: $private_ip${TEXTRESET}"

    echo -e "${YELLOW}Configuring Elasticsearch...${TEXTRESET}"
    configure_elasticsearch "$private_ip"

    echo -e "${YELLOW}Configuring JVM heap size...${TEXTRESET}"
    configure_jvm_heap

    echo -e "${GREEN}Configuration complete. Please restart the Elasticsearch service to apply changes.${TEXTRESET}"
}

# Run the main function
main
#Set FW Rules 
# Function to find the network interface
find_interface() {
    # Find the interface with a connection ending in -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '-inside' found.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Function to find the zone associated with the interface
find_zone() {
    local interface="$1"
    # Get the active zones and find the one associated with the interface
    zone=$(sudo firewall-cmd --get-active-zones | awk -v iface="$interface" '
        {
            if ($1 != "" && $1 !~ /interfaces:/) { current_zone = $1 }
        }
        /^  interfaces:/ {
            if ($0 ~ iface) { print current_zone }
        }
    ')

    if [ -z "$zone" ]; then
        echo -e "${RED}Error: No zone associated with interface $interface.${TEXTRESET}"
        exit 1
    fi

    echo "$zone"
}

# Function to configure firewall rules
configure_firewall() {
    local interface="$1"
    local zone="$2"

    echo -e "${YELLOW}Configuring firewall for interface: $interface in zone: $zone...${TEXTRESET}"

    # Change the interface to the appropriate zone
    if sudo firewall-cmd --permanent --zone="$zone" --change-interface="$interface"; then
        echo -e "${GREEN}Interface $interface changed to the zone $zone.${TEXTRESET}"
    else
        echo -e "${RED}Failed to change interface $interface to the zone $zone.${TEXTRESET}"
        exit 1
    fi

    # Add services to the zone
    if sudo firewall-cmd --permanent --zone="$zone" --add-service=elasticsearch; then
        echo -e "${GREEN}Elasticsearch service added to the zone $zone.${TEXTRESET}"
    else
        echo -e "${RED}Failed to add Elasticsearch service to the zone $zone.${TEXTRESET}"
        exit 1
    fi

    if sudo firewall-cmd --permanent --zone="$zone" --add-service=kibana; then
        echo -e "${GREEN}Kibana service added to the zone $zone.${TEXTRESET}"
    else
        echo -e "${RED}Failed to add Kibana service to the zone $zone.${TEXTRESET}"
        exit 1
    fi

    # Open port 5601 for Kibana
    if sudo firewall-cmd --permanent --zone="$zone" --add-port=5601/tcp; then
        echo -e "${GREEN}Port 5601/tcp opened for Kibana.${TEXTRESET}"
    else
        echo -e "${RED}Failed to open port 5601/tcp for Kibana.${TEXTRESET}"
        exit 1
    fi

    # Reload the firewall to apply changes
    if sudo firewall-cmd --reload; then
        echo -e "${GREEN}Firewall reloaded successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to reload the firewall.${TEXTRESET}"
        exit 1
    fi
}

# Main script execution
main() {
    echo -e "${YELLOW}Locating the network interface...${TEXTRESET}"
    interface=$(find_interface)

    echo -e "${YELLOW}Determining the zone for interface $interface...${TEXTRESET}"
    zone=$(find_zone "$interface")

    echo -e "${YELLOW}Starting firewall configuration...${TEXTRESET}"
    configure_firewall "$interface" "$zone"

    echo -e "${GREEN}Firewall configuration complete.${TEXTRESET}"
}

# Run the main function
main

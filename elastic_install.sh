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

#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to find the private IP address and zone for the interface ending with -inside
find_interface_details() {
    # Get the list of interfaces with their IP addresses using nmcli
    interfaces=$(nmcli device status | awk '/-inside/ {print $1}')

    # Loop through interfaces to find the IP address and zone
    for interface in $interfaces; do
        # Get IP address for the interface
        ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')
        
        # Get the zone associated with the interface
        zone=$(sudo firewall-cmd --get-active-zones | awk -v iface="$interface" '
            {zone=$1} 
            /^  interfaces:/{ 
                if ($3 == iface) print zone
            }')

        # Check if the IP address and zone are found
        if [ -n "$ip" ] && [ -n "$zone" ]; then
            echo "$interface:$ip:$zone"
            return
        fi
    done

    # If no IP or zone is found, print an error and exit
    echo -e "${RED}No interface with '-inside' found, or no IP address or zone assigned. Exiting.${TEXTRESET}"
    exit 1
}

# Get the private IP address, interface, and zone
interface_details=$(find_interface_details)
interface_name=$(echo "$interface_details" | awk -F: '{print $1}' | sed 's/-inside//')
private_ip=$(echo "$interface_details" | awk -F: '{print $2}')
zone=$(echo "$interface_details" | awk -F: '{print $3}')

echo -e "${GREEN}Found private IP: $private_ip on interface: $interface_name in zone: $zone${TEXTRESET}"

# Update elasticsearch.yml file
echo -e "${YELLOW}Configuring Elasticsearch...${TEXTRESET}"
elasticsearch_yml="/etc/elasticsearch/elasticsearch.yml"

sudo sed -i "/#network.host: 192.168.0.1/a network.bind_host: [\"127.0.0.1\", \"$private_ip\"]" "$elasticsearch_yml"

# Append security and discovery configuration
echo -e "\ndiscovery.type: single-node" | sudo tee -a "$elasticsearch_yml" > /dev/null
sudo sed -i "s/^cluster.initial_master_nodes/#cluster.initial_master_nodes/" "$elasticsearch_yml"

echo -e "${GREEN}Elasticsearch configuration updated successfully.${TEXTRESET}"

# Configure JVM heap size
echo -e "${YELLOW}Configuring JVM heap size...${TEXTRESET}"
jvm_options="/etc/elasticsearch/jvm.options.d/jvm-heap.options"
sudo mkdir -p /etc/elasticsearch/jvm.options.d
echo -e "-Xms3g\n-Xmx3g" | sudo tee "$jvm_options" > /dev/null

echo -e "${GREEN}JVM heap size configured successfully.${TEXTRESET}"

# Configure firewall rules
echo -e "${YELLOW}Configuring firewall rules...${TEXTRESET}"
sudo firewall-cmd --permanent --zone="$zone" --change-interface="$interface_name"
sudo firewall-cmd --permanent --zone="$zone" --add-service=elasticsearch
sudo firewall-cmd --permanent --zone="$zone" --add-service=kibana
sudo firewall-cmd --permanent --zone="$zone" --add-port=5601/tcp
sudo firewall-cmd --reload

echo -e "${GREEN}Firewall rules configured successfully.${TEXTRESET}"

echo -e "${GREEN}Setup completed. Please review configurations and start Elasticsearch when ready.${TEXTRESET}"

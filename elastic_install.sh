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

# Function to reload systemd daemon
reload_daemon() {
    echo -e "${YELLOW}Reloading systemd daemon...${TEXTRESET}"
    if sudo systemctl daemon-reload; then
        echo -e "${GREEN}Systemd daemon reloaded successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to reload systemd daemon.${TEXTRESET}"
        exit 1
    fi
}

# Function to enable and start Elasticsearch service
enable_start_elasticsearch() {
    echo -e "${YELLOW}Enabling and starting Elasticsearch service...${TEXTRESET}"
    if sudo systemctl enable elasticsearch --now; then
        echo -e "${GREEN}Elasticsearch service enabled and start command issued.${TEXTRESET}"
    else
        echo -e "${RED}Failed to enable and start Elasticsearch service.${TEXTRESET}"
        exit 1
    fi
}

# Function to check the status of Elasticsearch service
check_status() {
    echo -e "${YELLOW}Checking Elasticsearch service status...${TEXTRESET}"
    while true; do
        status=$(sudo systemctl is-active elasticsearch)
        if [ "$status" == "active" ]; then
            echo -e "${GREEN}Elasticsearch service is active and running.${TEXTRESET}"
            break
        else
            echo -e "${YELLOW}Waiting for Elasticsearch service to start...${TEXTRESET}"
            sleep 5
        fi
    done
}

# Main script execution
main() {
    reload_daemon
    enable_start_elasticsearch
    check_status

    # Continue with further steps if needed
    echo -e "${GREEN}Elasticsearch is running. Proceeding with further actions...${TEXTRESET}"
    # Add additional script actions here
}

# Run the main function
main


echo -e "${GREEN}Generating Password for the elastic account.${TEXTRESET}"
echo -e "${Yellow}This will be forced to reset when first logging in.${TEXTRESET}"
# Function to generate a random password
generate_password() {
    # Generate a 6-character password with upper and lowercase letters
    tr -dc 'A-Za-z' </dev/urandom | head -c 6
}

# Function to reset the password for the elastic user
reset_elastic_password() {
    local password="$1"
    echo -e "${YELLOW}Resetting password for the elastic user...${TEXTRESET}"

    # Use here-document to provide input to the password reset command
    sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i <<EOF
y
$password
$password
EOF

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Password for the elastic user successfully reset.${TEXTRESET}"
        echo -e "${YELLOW}The Password is:${TEXTRESET}"
        echo -e "$password"
        echo -e "${RED}You will need this password for the next step.${TEXTRESET}"
        read -p "Press Enter Once you have it written down"
    else
        echo -e "${RED}Failed to reset password for the elastic user.${TEXTRESET}"
        exit 1
    fi
}

# Main script execution
main() {
    # Generate a password
    password=$(generate_password)
    echo -e "${GREEN}Generated password: $password${TEXTRESET}"

    # Reset the password
    reset_elastic_password "$password"

    # Store the password in a file
    echo "$password" | sudo tee /root/elastic_password > /dev/null
    echo -e "${GREEN}Password stored in /root/elastic_password.${TEXTRESET}"
}

# Run the main function
main

# Function to test Elasticsearch response
test_elasticsearch() {
    local cert_path="/etc/elasticsearch/certs/http_ca.crt"
    local url="https://localhost:9200"

    echo -e "${YELLOW}Testing Elasticsearch response...${TEXTRESET}"

    # Prompt for the password of the elastic user
    read -sp "Enter password for elastic user: " password
    echo

    # Perform the query using curl
    response=$(sudo curl --cacert "$cert_path" -u elastic:"$password" "$url" 2>/dev/null)

    # Check if the response contains expected data
    if echo "$response" | grep -q '"tagline" : "You Know, for Search"'; then
        echo -e "${GREEN}Elasticsearch is responding to queries.${TEXTRESET}"
        echo "$response"
    else
        echo -e "${RED}Failed to get a valid response from Elasticsearch.${TEXTRESET}"
        exit 1
    fi
}

# Main script execution
main() {
    test_elasticsearch
}

# Run the main function
main

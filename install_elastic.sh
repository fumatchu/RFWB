install_elastic() {
    # Function to show a spinning cursor
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

    # Inform the user that the process is starting
    clear
    echo -e "${GREEN}Installing Elasticsearch and Kibana...${TEXTRESET}"
    echo -e "${YELLOW}Downloading packages this may take a few minutes...${TEXTRESET}"

    # Step 1: Import the Elastic GPG key
    echo -e "Importing the Elastic GPG key...${TEXTRESET}"
    (sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch) & spinner $!
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Elastic GPG key imported successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to import Elastic GPG key.${TEXTRESET}"
        exit 1
    fi

    # Step 2: Create the Elasticsearch repository file
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

    # Define the log file to capture the installation output
    INSTALL_LOG="/tmp/elastic_install.log"

    # Step 3: Install Elasticsearch and Kibana
    echo -e "${GREEN}Installing Elasticsearch and Kibana...${TEXTRESET}"

    # Run the installation, capturing the output with tee to both the screen and log file
    (sudo dnf install --enablerepo=elasticsearch elasticsearch kibana -y | tee "$INSTALL_LOG") & spinner $!
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Elasticsearch and Kibana installed successfully.${TEXTRESET}"

        # Define the file to store the security configuration information
        SECURITY_INFO_FILE="/root/elastic_security_info.txt"

        # Extract the security configuration information from the installation log
        awk '/--------------------------- Security autoconfiguration information ------------------------------/,/-------------------------------------------------------------------------------------------------/' "$INSTALL_LOG" > "$SECURITY_INFO_FILE"

        # Check if the file was created and contains the expected information
        if [ -s "$SECURITY_INFO_FILE" ]; then
            echo "Security configuration information captured and stored in $SECURITY_INFO_FILE."

            # Extract the generated password for the elastic built-in superuser
            PASSWORD=$(grep "The generated password for the elastic built-in superuser is :" "$SECURITY_INFO_FILE" | awk -F': ' '{print $2}' | tr -d '[:space:]')

            # Define the file to store the password
            PASSWORD_FILE="/root/elastic_password"

            # Store the password in the file
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

    # Clean up the installation log file
    rm -f "$INSTALL_LOG"

    # Define the Elasticsearch configuration paths
    ELASTIC_YML="/etc/elasticsearch/elasticsearch.yml"
    JVM_OPTIONS_DIR="/etc/elasticsearch/jvm.options.d"
    JVM_HEAP_OPTIONS="$JVM_OPTIONS_DIR/jvm-heap.options"

    # Function to configure Elasticsearch
    configure_elasticsearch() {
        echo -e "Backing up the original Elasticsearch configuration...${TEXTRESET}"
        sudo cp "$ELASTIC_YML" "${ELASTIC_YML}.bak"
        echo -e "Updating the Elasticsearch configuration...${TEXTRESET}"

        # Update xpack.security.enabled to true
        if grep -q "^xpack.security.enabled:" "$ELASTIC_YML"; then
            sudo sed -i 's/^xpack.security.enabled:.*/xpack.security.enabled: true/' "$ELASTIC_YML"
        else
            echo "xpack.security.enabled: true" | sudo tee -a "$ELASTIC_YML" >/dev/null
        fi

        # Update xpack.security.http.ssl.enabled to false
        if grep -q "^xpack.security.http.ssl:" "$ELASTIC_YML"; then
            sudo sed -i '/^xpack.security.http.ssl:/,/^ *keystore.path:/{s/^ *enabled:.*/  enabled: false/}' "$ELASTIC_YML"
        else
            echo -e "xpack.security.http.ssl:\n  enabled: false" | sudo tee -a "$ELASTIC_YML" >/dev/null
        fi

        # Update xpack.security.transport.ssl.enabled to false
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

    # Function to set JVM heap size
    configure_jvm_heap() {
        sudo mkdir -p "$JVM_OPTIONS_DIR"
        echo "-Xms3g" | sudo tee "$JVM_HEAP_OPTIONS" >/dev/null
        echo "-Xmx3g" | sudo tee -a "$JVM_HEAP_OPTIONS" >/dev/null
    }

    # Main configuration execution
    echo -e "Configuring Elasticsearch...${TEXTRESET}"
    configure_elasticsearch
    echo -e "Configuring JVM heap size...${TEXTRESET}"
    configure_jvm_heap

    # Function to find the network interface
    find_interface() {
        interface=$(nmcli device status | awk '/-inside/ {print $1}')
        if [ -z "$interface" ]; then
            echo -e "${RED}Error: No interface with a connection ending in '-inside' found.${TEXTRESET}"
            exit 1
        fi
        echo "$interface"
    }

    # Function to configure nftables rules
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

    # Configure nftables
    interface=$(find_interface)
    configure_nftables "$interface"
    echo -e "${GREEN}Firewall configuration for port 5601 complete.${TEXTRESET}"

    # Function to reload systemd daemon
    reload_daemon() {
        echo -e "Reloading systemd daemon...${TEXTRESET}"
        if sudo systemctl daemon-reload; then
            echo -e "${GREEN}Systemd daemon reloaded successfully.${TEXTRESET}"
        else
            echo -e "${RED}Failed to reload systemd daemon.${TEXTRESET}"
            exit 1
        fi
    }

    # Function to enable and start Elasticsearch service
    enable_start_elasticsearch() {
        echo -e "Enabling and starting Elasticsearch service...${TEXTRESET}"
        if sudo systemctl enable elasticsearch --now; then
            echo -e "${GREEN}Elasticsearch service enabled and start command issued.${TEXTRESET}"
        else
            echo -e "${RED}Failed to enable and start Elasticsearch service.${TEXTRESET}"
            exit 1
        fi
    }

    # Function to check the status of Elasticsearch service
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

    # Enable and check Elasticsearch service
    reload_daemon
    enable_start_elasticsearch
    check_status

    # Function to test Elasticsearch response
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

    # Test Elasticsearch
    test_elasticsearch
    echo -e  "${GREEN}Elasticsearch Install Complete...${TEXTRESET}"
}
install_elastic

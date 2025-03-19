#!/bin/bash
# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
RESET='\033[0m'
FQDN=(hostname -I)
# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

#Install EVEBOX
install_eve() {
    clear
    echo -e "${GREEN}Installing EVEBOX for Suricata...${TEXTRESET}"
    sleep 4

    # Add the EveBox repository using rpm
    rpm -Uvh https://evebox.org/files/rpm/stable/evebox-release.noarch.rpm

    # Install SQLite
    dnf install -y sqlite

    # Install EveBox using dnf
    dnf install -y evebox

    # Define configuration file path
    CONFIG_FILE="/etc/evebox/evebox.yaml"

    # Backup existing configuration file if it exists
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "Backing up existing configuration file..."
        cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
    fi

    # Write new configuration to evebox.yaml including all remarks
    echo -e "Writing new configuration to ${GREEN}$CONFIG_FILE...${TEXTRESET}"
    cat <<EOL > $CONFIG_FILE
# This is a minimal evebox.yaml for Elasticsearch and SQLite.

http:
  ## By default, EveBox binds to localhost. Uncomment this line to open
  ## it up.
  host: "0.0.0.0"

  tls:
    # By default TLS is enabled and a self-signed certificate will
    # be created. Uncomment and set this to false to disable TLS.
    enabled: false

# By default authentication is enabled, uncomment this line to disable
# authentication.
#authentication: false

data-directory: /var/lib/evebox

database:
  type: sqlite

  #elasticsearch:
   # url: http://127.0.0.1:9200

    ## If using the Filebeat Suricata module, you'll probably want to
    ## change the index to "filebeat".
    #index: logstash

    # If using the Filebeat Suricata module this needs to be true.
    #ecs: false

    ## If your Elasticsearch is using a self-signed certificate,
    ## you'll likely need to set this to true.
    #disable-certificate-check: false

    ## If your Elasticsearch requires a username and password, provide
    ## them here.
    #username:
    #password:

  retention:
    # Only keep events for the past 7 days.
    # - SQLite only
    # - Default 7 days
    # - Set to 0 to disable
    days: 7

    # Maximum database size.
    # - SQLite only
    # - No default
    size: "20 GB"

# The server can process events itself when using SQLite or a classic
# Logstash style Elasticsearch template.
input:
  enabled: true

  # Suricata EVE file patterns to look for and read.
  paths:
    - "/var/log/suricata/eve.json"
    - "/var/log/suricata/eve.*.json"
EOL

    # Change permissions of /var/log/suricata to 774 recursively
    echo -e "Changing permissions of /var/log/suricata to 774 recursively..."
    chmod -R 774 /var/log/suricata

    # Create evebox-agent systemd service
    echo -e "${GREEN}Creating evebox-agent systemd service...${TEXTRESET}"
    cat <<EOF > /etc/systemd/system/evebox-agent.service
[Unit]
Description=EveBox Agent
After=network.target

[Service]
ExecStart=/usr/bin/evebox agent --server http://127.0.0.1:5636 /var/log/suricata/eve.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd to recognize the new service
    systemctl daemon-reload
    # Add group permissions to eve and suricata
    sudo usermod -aG suricata evebox
    sudo usermod -aG evebox suricata
    #Make sure logrotate is happy
    sudo chown -R suricata:suricata /var/log/suricata
    sudo chmod 750 /var/log/suricata
    sudo find /var/log/suricata -type f -exec chmod 640 {} \;
    #restart suricata
    systemctl restart suricata
    # Enable and start the EveBox and evebox-agent services
    echo -e "Enabling and starting the EveBox and evebox-agent services..."
    systemctl enable evebox
    systemctl start evebox
    systemctl enable evebox-agent
    systemctl start evebox-agent

    # Check if services are running
    if systemctl is-active --quiet evebox && systemctl is-active --quiet evebox-agent; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] EveBox and EveBox Agent services are running."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to start EveBox or EveBox Agent services. Please check the logs for more details."
        exit 1
    fi

    # Function to add a rule to nftables for port 5636
    configure_nftables() {
        echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring nftables..."

        # Find interfaces ending with '-inside'
        inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

        if [ -z "$inside_interfaces" ]; then
            echo -e "[${RED}ERROR${TEXTRESET}] No interface with '-inside' profile found. Exiting..."
            exit 1
        fi

        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Inside interfaces found: ${GREEN}$inside_interfaces${TEXTRESET}"

        sudo systemctl enable nftables
        sudo systemctl start nftables

        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 5636 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 5636 accept
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow TCP on port 5636 for interface ${GREEN}$iface${TEXTRESET}"
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow TCP on port 5636 for interface ${GREEN}$iface${TEXTRESET}"
            fi
        done

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

    # Configure nftables to allow TCP traffic on port 5636
    configure_nftables

    # Capture administrator credentials from /var/log/messages
    echo -e "Capturing administrator credentials from /var/log/messages..."
    credentials=$(grep "Created administrator username and password" /var/log/messages | tail -n 1)

    if [[ $credentials =~ username=([a-zA-Z0-9]+),\ password=([a-zA-Z0-9]+) ]]; then
        admin_user="${BASH_REMATCH[1]}"
        admin_pass="${BASH_REMATCH[2]}"
        echo "username=$admin_user, password=$admin_pass" > /root/evebox_credentials
        echo -e "${GREEN}Credentials captured and saved to /root/evebox_credentials.${TEXTRESET}"
        echo -e "Your username is: $admin_user and your password is: $admin_pass"
    else
        echo -e "${RED}Failed to capture administrator credentials from logs.${TEXTRESET}"
    fi

    echo -e "${GREEN}EveBox and evebox-agent service setup complete.${TEXTRESET}"
    read -p "Press Enter when ready"
}

#Set Avahi on the inside interfaces
install_avahi() {
clear
echo -e "${GREEN}Configuring and installing Avahi...${TEXTRESET}"
sleep 4
# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Function to find sub-interfaces based on main interface
find_sub_interfaces() {
    local main_interface="$1"
    nmcli -t -f DEVICE device status | grep -E "^${main_interface}\.[0-9]+" | awk '{print $1}'
}

# Find inside and outside interfaces
INSIDE_INTERFACE=$(find_interface "-inside")
OUTSIDE_INTERFACE=$(find_interface "-outside")

echo -e "${GREEN}Inside interface:${TEXTRESET} $INSIDE_INTERFACE"
echo -e "${GREEN}Outside interface:${TEXTRESET} $OUTSIDE_INTERFACE"

# Find sub-interfaces for the inside interface
SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

# Install Avahi and Avahi Tools
echo -e "Installing Avahi and Avahi Tools..."
sudo yum install -y avahi avahi-tools

# Configure Avahi to enable mDNS reflection on internal interfaces
echo -e "Configuring Avahi to enable mDNS reflection..."
# Backup existing configuration
sudo cp /etc/avahi/avahi-daemon.conf /etc/avahi/avahi-daemon.conf.bak

# Create a list of interfaces for Avahi to listen on
INTERFACES="$INSIDE_INTERFACE"
for sub_interface in $SUB_INTERFACES; do
    INTERFACES+=",${sub_interface}"
done

# Modify Avahi configuration
sudo bash -c "cat > /etc/avahi/avahi-daemon.conf <<EOL
[server]
use-ipv4=yes
use-ipv6=yes
allow-interfaces=$INTERFACES

[reflector]
enable-reflector=yes
EOL"

# Start and enable Avahi service
echo -e "Starting and enabling Avahi service..."
sudo systemctl start avahi-daemon
sudo systemctl enable avahi-daemon

# Configure nftables to allow mDNS traffic on internal interfaces only
echo -e "${GREEN}Configuring nftables to allow mDNS traffic...${TEXTRESET}"
# Ensure nftables table and chain exist
sudo nft add table inet filter 2>/dev/null
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null

# Allow mDNS traffic on internal interfaces
sudo nft add rule inet filter input iifname "$INSIDE_INTERFACE" udp dport 5353 accept
for sub_interface in $SUB_INTERFACES; do
    sudo nft add rule inet filter input iifname "$sub_interface" udp dport 5353 accept
done

# Save the current ruleset
echo -e "${GREEN}Saving the current nftables ruleset...${TEXTRESET}"
sudo nft list ruleset >/etc/sysconfig/nftables.conf

# Enable and start nftables service to ensure configuration is loaded on boot
echo -e "${GREEN}Enabling nftables service...${TEXTRESET}"
sudo systemctl enable nftables
sudo systemctl start nftables

echo -e "${GREEN}Avahi is configured for mDNS reflection only on internal interfaces.${TEXTRESET}"
sleep 4
}

install_qos() {
    clear
    echo -e "${GREEN}Installing QOS for Voice...${TEXTRESET}"
    sleep 4

    # File paths
    CONFIG_FILE="/etc/rfwb-qos.conf"
    SCRIPT_FILE="/usr/local/bin/rfwb-qos.sh"
    SERVICE_FILE="/etc/systemd/system/rfwb-qos.service"
    TIMER_FILE="/etc/systemd/system/rfwb-qos.timer"
    LOG_FILE="/var/log/rfwb-qos.log"
    ERROR_LOG_FILE="/var/log/rfwb-qos-errors.log"

    # Load configuration function
    load_config() {
        if [[ ! -f "$CONFIG_FILE" ]]; then
            echo "Configuration file not found. Creating a default configuration."
            create_config 10  # Create a default config with 20% bandwidth reservation
        fi

        percentage_bandwidth=0
        adjust_interval_hours=0.25  # Default value is 15 minutes (0.25 hours)
        wifi_calling_ports=""
        sip_ports=""
        rtp_ports=""
        rtsp_ports=""
        h323_port=""
        webrtc_ports=""
        mpeg_ts_port=""

        while IFS='= ' read -r key value; do
            if [[ $key =~ ^[a-zA-Z_]+$ ]]; then
                value="${value//\"/}"
                declare "$key=$value"
            fi
        done < "$CONFIG_FILE"
    }

    # Create configuration file function
    create_config() {
        local percentage_bandwidth=$1
        echo -e "Creating configuration file at ${YELLLOW}$CONFIG_FILE${TEXTRESET} with ${YELLOW}${percentage_bandwidth}%${TEXTRESET} reserved bandwidth..." | tee -a $LOG_FILE
        cat <<EOF > $CONFIG_FILE
# /etc/rfwb-qos.conf

percentage_bandwidth = $percentage_bandwidth
adjust_interval_hours = 0.25

wifi_calling_ports = 500,4500
sip_ports = 5060
rtp_ports = 10000-20000
rtsp_ports = 554,8554
h323_port = 1720
webrtc_ports = 16384-32767
mpeg_ts_port = 1234
EOF
        echo -e "${GREEN}Configuration file created.${TEXTRESET}" | tee -a $LOG_FILE
    }

    # Create systemd timer function
    create_timer() {
        local interval=$1
        local interval_minutes=$(echo "$interval * 60" | bc)

        cat <<EOF > $TIMER_FILE
[Unit]
Description=Run RFWB QoS Service every ${interval_minutes} minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=${interval_minutes}min
Persistent=true

[Install]
WantedBy=timers.target
EOF
        echo -e "Systemd timer created with an interval of every ${YELLOW}${interval_minutes}${TEXTRESET} minutes." | tee -a $LOG_FILE
    }

    # Configure QoS function
    configure_qos() {
        load_config
        local OUTSIDE_INTERFACE=$(find_interface "-outside")

        if [ -z "$OUTSIDE_INTERFACE" ]; then
            echo "No outside interface found." | tee -a $ERROR_LOG_FILE
            exit 1
        fi

        echo "Running speed test to measure current throughput..." | tee -a $LOG_FILE
        speedtest_output=$(speedtest --format=json 2>>$ERROR_LOG_FILE)

        if [ $? -ne 0 ]; then
            echo "Speedtest failed. Check the network connection and speedtest-cli installation." | tee -a $ERROR_LOG_FILE
            exit 1
        fi

        DOWNLOAD_SPEED=$(echo "$speedtest_output" | jq '.download.bandwidth')
        UPLOAD_SPEED=$(echo "$speedtest_output" | jq '.upload.bandwidth')

        DOWNLOAD_SPEED_KBIT=$(($DOWNLOAD_SPEED * 8 / 1000))
        UPLOAD_SPEED_KBIT=$(($UPLOAD_SPEED * 8 / 1000))

        echo -e "${GREEN}Current download speed is ${DOWNLOAD_SPEED_KBIT} kbit/s.${TEXTRESET}" | tee -a $LOG_FILE
        echo -e "${GREEN}Current upload speed is ${UPLOAD_SPEED_KBIT} kbit/s.${TEXTRESET}" | tee -a $LOG_FILE

        # Adjust r2q value based on download speed
        if [ "$DOWNLOAD_SPEED_KBIT" -lt 10000 ]; then
            R2Q_VALUE=1
        elif [ "$DOWNLOAD_SPEED_KBIT" -lt 100000 ]; then
            R2Q_VALUE=2
        else
            R2Q_VALUE=10
        fi

        echo -e "${GREEN}Setting r2q value to $R2Q_VALUE based on the download throughput.${TEXTRESET}" | tee -a $LOG_FILE

        # Determine download and upload ceilings
        CEIL_DOWNLOAD=$(($DOWNLOAD_SPEED_KBIT / 1000 - 1))
        CEIL_UPLOAD=$(($UPLOAD_SPEED_KBIT / 1000 - 1))

        RESERVED_DOWNLOAD_BANDWIDTH=$(($CEIL_DOWNLOAD * 1000 * $percentage_bandwidth / 100))
        RESERVED_UPLOAD_BANDWIDTH=$(($CEIL_UPLOAD * 1000 * $percentage_bandwidth / 100))

        echo "Configuring QoS on $OUTSIDE_INTERFACE..." | tee -a $LOG_FILE
        tc qdisc del dev $OUTSIDE_INTERFACE root 2>>$ERROR_LOG_FILE || true
        tc qdisc add dev $OUTSIDE_INTERFACE root handle 1: htb default 20 r2q $R2Q_VALUE 2>>$ERROR_LOG_FILE

        # Create classes for download and upload
        tc class add dev $OUTSIDE_INTERFACE parent 1: classid 1:1 htb rate ${CEIL_DOWNLOAD}Mbit ceil ${CEIL_DOWNLOAD}Mbit 2>>$ERROR_LOG_FILE
        tc class add dev $OUTSIDE_INTERFACE parent 1: classid 1:2 htb rate ${CEIL_UPLOAD}Mbit ceil ${CEIL_UPLOAD}Mbit 2>>$ERROR_LOG_FILE

        # Apply port-specific QoS rules
        echo "Applying port-specific QoS rules..." | tee -a $LOG_FILE
        for port in ${wifi_calling_ports//,/ }; do
            tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:1
        done

        for port in ${sip_ports//,/ }; do
            tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:1
        done

        # Add similar rules for other port types (rtp_ports, rtsp_ports, etc.)
        echo "QoS configuration applied to $OUTSIDE_INTERFACE." | tee -a $LOG_FILE
        tc -s class show dev $OUTSIDE_INTERFACE | tee -a $LOG_FILE
    }

    # Find the network interface function
    find_interface() {
        local suffix="$1"
        nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
    }


    # Check and create the configuration file if necessary
    load_config

    # Create timer based on the loaded configuration
    create_timer $adjust_interval_hours

    # Determine and verify network interfaces
    echo "Determining network interfaces..." | tee -a $LOG_FILE
    INSIDE_INTERFACE=$(find_interface "-inside")
    OUTSIDE_INTERFACE=$(find_interface "-outside")

    if [ -z "$OUTSIDE_INTERFACE" ]; then
        echo -e "${RED}No outside interface found. Exiting.${TEXTRESET}" | tee -a $LOG_FILE
        exit 1
    fi

    echo -e "${GREEN}Selected outside interface: $OUTSIDE_INTERFACE${TEXTRESET}" | tee -a $LOG_FILE

    read -p "Enter the percentage of bandwidth you want to reserve for voice applications: " PERCENTAGE

    echo -e "Setting up with $PERCENTAGE% reserved bandwidth." | tee -a $LOG_FILE

    create_config $PERCENTAGE

    # Create the QoS adjustment script
    echo -e "Creating QoS adjustment script at $SCRIPT_FILE..." | tee -a $LOG_FILE
    cat <<'EOF' > $SCRIPT_FILE
#!/bin/bash

CONFIG_FILE="/etc/rfwb-qos.conf"
LOG_FILE="/var/log/rfwb-qos.log"
ERROR_LOG_FILE="/var/log/rfwb-qos-errors.log"

load_config() {
    percentage_bandwidth=0
    adjust_interval_hours=0.25  # Default value is 15 minutes (0.25 hours)
    wifi_calling_ports=""
    sip_ports=""
    rtp_ports=""
    rtsp_ports=""
    h323_port=""
    webrtc_ports=""
    mpeg_ts_port=""

    while IFS='= ' read -r key value; do
        if [[ $key =~ ^[a-zA-Z_]+$ ]]; then
            value="${value//\"/}"
            declare "$key=$value"
        fi
    done < "$CONFIG_FILE"
}

find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

configure_qos() {
    load_config
    local OUTSIDE_INTERFACE=$(find_interface "-outside")

    if [ -z "$OUTSIDE_INTERFACE" ]; then
        echo "No outside interface found." | tee -a $ERROR_LOG_FILE
        exit 1
    fi

    echo "Running speed test to measure current throughput..." | tee -a $LOG_FILE
    speedtest_output=$(speedtest --format=json 2>>$ERROR_LOG_FILE)

    if [ $? -ne 0 ]; then
        echo "Speedtest failed. Check the network connection and speedtest-cli installation." | tee -a $ERROR_LOG_FILE
        exit 1
    fi

    DOWNLOAD_SPEED=$(echo "$speedtest_output" | jq '.download.bandwidth')
    UPLOAD_SPEED=$(echo "$speedtest_output" | jq '.upload.bandwidth')

    DOWNLOAD_SPEED_KBIT=$(($DOWNLOAD_SPEED * 8 / 1000))
    UPLOAD_SPEED_KBIT=$(($UPLOAD_SPEED * 8 / 1000))

    echo -e "${GREEN}Current download speed is ${DOWNLOAD_SPEED_KBIT} kbit/s.${TEXTRESET}" | tee -a $LOG_FILE
    echo -e "${GREEN}Current upload speed is ${UPLOAD_SPEED_KBIT} kbit/s.${TEXTRESET}" | tee -a $LOG_FILE

    if [ "$DOWNLOAD_SPEED_KBIT" -lt 10000 ]; then
        R2Q_VALUE=1
    elif [ "$DOWNLOAD_SPEED_KBIT" -lt 100000 ]; then
        R2Q_VALUE=2
    else
        R2Q_VALUE=10
    fi

    echo -e "${GREEN}Setting r2q value to $R2Q_VALUE based on the download throughput.${TEXTRESET}" | tee -a $LOG_FILE

    CEIL_DOWNLOAD=$(($DOWNLOAD_SPEED_KBIT / 1000 - 1))
    CEIL_UPLOAD=$(($UPLOAD_SPEED_KBIT / 1000 - 1))

    RESERVED_DOWNLOAD_BANDWIDTH=$(($CEIL_DOWNLOAD * 1000 * $percentage_bandwidth / 100))
    RESERVED_UPLOAD_BANDWIDTH=$(($CEIL_UPLOAD * 1000 * $percentage_bandwidth / 100))

    echo "Configuring QoS on $OUTSIDE_INTERFACE..." | tee -a $LOG_FILE
    tc qdisc del dev $OUTSIDE_INTERFACE root 2>>$ERROR_LOG_FILE || true
    tc qdisc add dev $OUTSIDE_INTERFACE root handle 1: htb default 20 r2q $R2Q_VALUE 2>>$ERROR_LOG_FILE

    tc class add dev $OUTSIDE_INTERFACE parent 1: classid 1:1 htb rate ${CEIL_DOWNLOAD}Mbit ceil ${CEIL_DOWNLOAD}Mbit 2>>$ERROR_LOG_FILE
    tc class add dev $OUTSIDE_INTERFACE parent 1: classid 1:2 htb rate ${CEIL_UPLOAD}Mbit ceil ${CEIL_UPLOAD}Mbit 2>>$ERROR_LOG_FILE

    echo "Applying port-specific QoS rules..." | tee -a $LOG_FILE
    for port in ${wifi_calling_ports//,/ }; do
        tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:1
    done

    for port in ${sip_ports//,/ }; do
        tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:1
    done

    echo "QoS configuration applied to $OUTSIDE_INTERFACE." | tee -a $LOG_FILE
    tc -s class show dev $OUTSIDE_INTERFACE | tee -a $LOG_FILE
}

configure_qos
EOF
    chmod +x $SCRIPT_FILE
    echo -e "${GREEN}QoS adjustment script created.${TEXTRESET}" | tee -a $LOG_FILE

    # Create the systemd service
    echo -e "${GREEN}Creating systemd service at $SERVICE_FILE...${TEXTRESET}" | tee -a $LOG_FILE
    cat <<EOF > $SERVICE_FILE
[Unit]
Description=RFWB QoS Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$SCRIPT_FILE
Type=simple
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
    echo -e "${GREEN}Systemd service created.${TEXTRESET}" | tee -a $LOG_FILE

    # Enable and start the service and timer
    echo "Enabling and starting the RFWB QoS service and timer..." | tee -a $LOG_FILE
    systemctl daemon-reload
    systemctl enable rfwb-qos.service
    systemctl start rfwb-qos.service
    systemctl enable rfwb-qos.timer
    systemctl start rfwb-qos.timer
    echo -e "${GREEN}Service and timer enabled and started.${TEXTRESET}" | tee -a $LOG_FILE

    echo -e "${GREEN}Installation of QOS for Voice Complete. ${TEXTRESET}" | tee -a $LOG_FILE
    sleep 4
}

#Function to install Netdata
install_netdata() {
    clear
    echo -e "${GREEN}Installing Netdata...${TEXTRESET}"
    sleep 4
    if ! sudo dnf -y update; then
        echo -e "${RED}System update failed. Exiting.${TEXTRESET}"
        exit 1
    fi

    if ! sudo dnf -y install epel-release; then
        echo -e "${RED}EPEL repository installation failed. Exiting.${TEXTRESET}"
        exit 1
    fi

    if ! sudo dnf config-manager --set-enabled crb; then
        echo -e "${RED}Failed to enable CodeReady Builder repository. Exiting.${TEXTRESET}"
        exit 1
    fi

    if ! sudo dnf -y install wget; then
        echo -e "${RED}Required packages installation failed. Exiting.${TEXTRESET}"
        exit 1
    fi

    if wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh; then
        if ! sh /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry --non-interactive; then
            echo -e "${RED}Netdata installation failed. Exiting.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${RED}Failed to download Netdata installation script. Exiting.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Cleaning up temporary files...${TEXTRESET}"
    rm -f /tmp/netdata-kickstart.sh

    echo -e "${GREEN}Netdata installation completed successfully.${TEXTRESET}"

    inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    if [ -z "$inside_interfaces" ]; then
        echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"

    sudo systemctl enable nftables
    sudo systemctl start nftables

    if ! sudo nft list tables | grep -q 'inet filter'; then
        sudo nft add table inet filter
    fi

    if ! sudo nft list chain inet filter input &>/dev/null; then
        sudo nft add chain inet filter input { type filter hook input priority 0 \; }
    fi

    for iface in $inside_interfaces; do
        if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 19999 accept"; then
            sudo nft add rule inet filter input iifname "$iface" tcp dport 19999 accept
            echo -e "${GREEN}Rule added: Allow Netdata on port 19999 for interface $iface${TEXTRESET}"
        else
            echo "Rule already exists: Allow Netdata on port 19999 for interface $iface"
        fi
    done

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
    echo -e "${GREEN}Netdata Install Complete...${TEXTRESET}"
    sleep 4
}

#Function to install snmpd
install_snmpd() {
    clear
    echo -e "${GREEN}Installing and configuring SNMP Daemon...${TEXTRESET}"
    sleep 4
    # Function to validate IP address or network
    function validate_ip_or_network() {
        local ip_network=$1
        if [[ $ip_network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$ ]]; then
            IFS='/' read -r ip prefix <<<"$ip_network"
            for octet in $(echo $ip | tr '.' ' '); do
                if ((octet < 0 || octet > 255)); then
                    echo -e "${RED}Invalid IP address or network: $ip_network${TEXTRESET}"
                    return 1
                fi
            done
            if [ -n "$prefix" ] && ((prefix < 0 || prefix > 32)); then
                echo -e "${RED}Invalid prefix length: $prefix${TEXTRESET}"
                return 1
            fi
            return 0
        else
            echo -e "${RED}Invalid IP address or network format: $ip_network${TEXTRESET}"
            return 1
        fi
    }

    # Function to locate the server's private IP address using nmcli
    find_private_ip() {
        # Find the interface ending with -inside
        interface=$(nmcli device status | awk '/-inside/ {print $1}')

        if  [ -z "$interface" ]; then
            echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
            exit 1
        fi

        # Extract the private IP address for the found interface
        ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

        if [ -z "$ip" ]; then
            echo -e "${RED}Error: No IP address found for the interface $interface.${TEXTRESET}"
            exit 1
        fi

        echo "$interface"
    }

    # Install SNMP daemon
    yum install -y net-snmp net-snmp-utils

    # Ask user for SNMP version
    echo "Select SNMP version to run:"
    echo "1) SNMPv1"
    echo "2) SNMPv2c"
    echo "3) SNMPv3"
    read -p "Enter the number corresponding to your choice (1, 2, or 3): " snmp_version
    while ! [[ "$snmp_version" =~ ^[1-3]$ ]]; do
        echo -e "${RED}Invalid selection. Please enter 1, 2, or 3.${TEXTRESET}"
        read -p "Enter the number corresponding to your choice (1, 2, or 3): " snmp_version
    done

    # Ask for SNMP community string if SNMPv1 or SNMPv2c is selected
    if [ "$snmp_version" == "1" ] || [ "$snmp_version" == "2" ]; then
        read -p "Enter the SNMP community string (default is 'public'): " community_string
        community_string=${community_string:-public}
    fi

    # If SNMPv3 is selected, gather additional credentials
    if [ "$snmp_version" == "3" ]; then
        read -p "Enter SNMPv3 username: " snmpv3_user
        read -p "Enter SNMPv3 authentication protocol (MD5/SHA): " auth_protocol
        read -sp "Enter SNMPv3 authentication password: " auth_pass
        echo
        read -p "Enter SNMPv3 privacy protocol (DES/AES): " priv_protocol
        read -sp "Enter SNMPv3 privacy password: " priv_pass
        echo
    fi

    # Ask user for IP address or network
    read -p "Enter the IP address or network (e.g., 192.168.1.0/24) allowed to monitor this device: " allowed_network
    while ! validate_ip_or_network "$allowed_network"; do
        read -p "Please enter a valid IP address or network: " allowed_network
    done

    # Ask for system location and contact
    read -p "Enter system location: " syslocation
    read -p "Enter system contact: " syscontact

    # Configure firewall using nftables
    inside_interfaces=$(nmcli device status | awk '/-inside/ {print $1}')
    for iface in $inside_interfaces; do
        # Check and add rule for SNMP (UDP) on port 161
        if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 161 accept"; then
            sudo nft add rule inet filter input iifname "$iface" udp dport 161 accept
            echo -e "${GREEN}Rule added: Allow SNMP (UDP) on interface $iface${TEXTRESET}"
        else
            echo "Rule already exists: Allow SNMP (UDP) on interface $iface"
        fi
    done

    # Check and handle rfwb-portscan service
    rfwb_status=$(systemctl is-active rfwb-portscan)
    if [ "$rfwb_status" == "active" ]; then
        systemctl stop rfwb-portscan
    fi

    # Save nftables configuration
    nft list ruleset >/etc/sysconfig/nftables.conf

    # Restart rfwb-portscan service if it was active
    if [ "$rfwb_status" == "active" ]; then
        systemctl start rfwb-portscan
    fi

    # Show the added rules in the input chain
    sudo nft list chain inet filter input

    # Backup existing configuration
    cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.backup

    # Create a new configuration file based on user input and the provided template
    cat <<EOF >/etc/snmp/snmpd.conf
###############################################################################
# System contact information
syslocation $syslocation
syscontact $syscontact

###############################################################################
# Access Control
###############################################################################
com2sec notConfigUser  $allowed_network   ${community_string:-public}

# SNMPv3 user setup
$(if [ "$snmp_version" == "3" ]; then
        echo "createUser $snmpv3_user $auth_protocol \"$auth_pass\" $priv_protocol \"$priv_pass\""
        echo "rouser $snmpv3_user"
    fi)

# Views and Access
group notConfigGroup v1 notConfigUser
group notConfigGroup v2c notConfigUser
view systemview included .1.3.6.1.2.1.1
view systemview included .1.3.6.1.2.1.25.1.1
view systemview included .1
access notConfigGroup "" any noauth exact systemview none none

###############################################################################
# Additional SNMP Views
###############################################################################
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteIfIndex
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric1
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric2
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric3
view rwview included ip.ipRouteTable.ipRouteEntry.ipRouteMetric4

###############################################################################
# Process checks.
###############################################################################
# Ensure nftables is running
proc nftables

###############################################################################
# Load Average Checks
###############################################################################
load 12 14 14

###############################################################################
# Disk checks
###############################################################################
disk / 10000000  # Ensure at least 10GB of space

###############################################################################
# Extensible sections.
###############################################################################
# Uncomment and modify the following examples as needed:
# exec echotest /bin/echo hello world
# exec shelltest /bin/sh /tmp/shtest
EOF

    # Start and enable SNMP service
    echo -e "${GREEN}Starting SNMP service...${TEXTRESET}"
    systemctl start snmpd
    systemctl enable snmpd

    # Validate that the service is running
    if systemctl status snmpd | grep "active (running)" >/dev/null; then
        echo -e "${GREEN}SNMP service is running successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to start SNMP service. Please check the configuration.${TEXTRESET}"
    fi
    # Continue with the rest of the script
    echo -e "${GREEN}SNMP Daemon Install Complete...${TEXTRESET}"
    sleep 4
}

#Function to install rfwb-portscan detection
install_portscan() {
# Script to set up nftables for detecting and blocking port scans on Red Hat systems
clear
echo -e "${GREEN}Installing RFWB-Portscan Detection engine...${TEXTRESET}"
sleep 4

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Install nftables if not already installed
if ! command -v nft &>/dev/null; then
    echo "Installing nftables..."
    yum install -y nftables
fi

# Create or update the configuration file for user settings
CONFIG_FILE="/etc/rfwb-portscan.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    cat <<EOF >"$CONFIG_FILE"
# Configuration file for RFWB-Portscan service

# Maximum number of retries to obtain an external IP address. Set to 0 for infinite retries.
MAX_RETRIES=10

# Initial delay in seconds before retrying to obtain the external IP address.
INITIAL_DELAY=10

# Multiplier to increase the delay after each failed attempt (exponential backoff).
RETRY_MULTIPLIER=2

# Ports to monitor for port scan detection. Separate ports with commas.
MONITORED_PORTS="20, 21, 23, 25, 53, 67, 68, 69, 110, 111, 119, 135, 137, 138, 139, 143, 161, 162, 179, 389, 445, 465, 514, 515, 587, 631, 636, 993, 995"

# Timeout for dynamically blocked IPs. Use 's' for seconds, 'm' for minutes, 'h' for hours, 'd' for days.
# Set to '0' for no timeout (indefinitely).
BLOCK_TIMEOUT="30m"
EOF
fi

# Load configuration settings
source "$CONFIG_FILE"

# Ensure the hosts.blocked file exists
BLOCKED_FILE="/etc/nftables/hosts.blocked"
if [ ! -f "$BLOCKED_FILE" ]; then
    touch "$BLOCKED_FILE"
fi

# Ensure the ignore networks configuration file exists and populate with RFC 1918 networks
IGNORE_NETWORKS_FILE="/etc/nftables/ignore_networks.conf"
if [ ! -f "$IGNORE_NETWORKS_FILE" ]; then
    echo "Creating ignore networks configuration file with RFC 1918 networks."
    cat <<EOF >"$IGNORE_NETWORKS_FILE"
# Ignore file for rfwb-nft-portscan
# The port scan detection will ignore any IP addresses or networks placed into this file
# Network example
# 192.168.210.0/24
# Host example 192.168.210.10/32
# Entries must be one per line
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
EOF

    # Verify if the file was created and populated correctly
    if [ -f "$IGNORE_NETWORKS_FILE" ]; then
        echo "Ignore networks configuration file created successfully."
    else
        echo "Failed to create ignore networks configuration file."
        exit 1
    fi
else
    echo "Ignore networks configuration file already exists."
fi

# Verify file content
echo "Current contents of $IGNORE_NETWORKS_FILE:"
cat "$IGNORE_NETWORKS_FILE"

# Ensure the ignore ports configuration file exists
IGNORE_PORTS_FILE="/etc/nftables/ignore_ports.conf"
if [ ! -f "$IGNORE_PORTS_FILE" ]; then
    echo "Creating ignore ports configuration file."
    echo "# Ports to ignore for port scan detection. Separate ports with commas." > "$IGNORE_PORTS_FILE"
    echo "22, 80, 443" >> "$IGNORE_PORTS_FILE"  # Example default ports to ignore
fi

# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Determine the outside interface
OUTSIDE_INTERFACE=$(find_interface "-outside")

if [[ -z "$OUTSIDE_INTERFACE" ]]; then
    echo "Error: Could not determine the outside interface. Please check your connection names."
    exit 1
fi

# Retry mechanism to get the external IP address with exponential backoff
EXTERNAL_IP=""
attempt=1
delay=$INITIAL_DELAY

while :; do
    EXTERNAL_IP=$(ip -4 addr show "$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
    if [[ -n "$EXTERNAL_IP" ]]; then
        break
    fi
    if [[ $MAX_RETRIES -ne 0 && $attempt -gt $MAX_RETRIES ]]; then
        echo "Error: Failed to determine the external IP address after $MAX_RETRIES attempts. Exiting."
        exit 1
    fi
    echo "Attempt $attempt: Could not determine the external IP address for interface $OUTSIDE_INTERFACE. Retrying in $delay seconds..."
    sleep "$delay"
    ((attempt++))
    delay=$((delay * RETRY_MULTIPLIER))
done

echo "Protecting outside interface: $OUTSIDE_INTERFACE with IP: $EXTERNAL_IP"

# Load ignore networks from the configuration file
IGNORE_NETWORKS=$(cat "$IGNORE_NETWORKS_FILE")
echo "Using ignore networks: $IGNORE_NETWORKS"

# Prepare elements string for blocked IPs set if not empty
ELEMENTS=""
if [ -s "$BLOCKED_FILE" ]; then
    ELEMENTS=$(sed ':a;N;$!ba;s/\n/, /g' "$BLOCKED_FILE")
fi

# Create nftables configuration directory
NFT_CONF_DIR="/etc/nftables"
mkdir -p "$NFT_CONF_DIR"

# Define the path to the nftables configuration file
NFT_CONF_FILE="$NFT_CONF_DIR/portscan.conf"

# Create a pre-start script to log the outside interface and IP
PRE_START_SCRIPT="/usr/local/bin/rfwb-portscan-prestart.sh"
cat <<EOF >"$PRE_START_SCRIPT"
#!/bin/bash

# Configuration  for retry mechanism
MAX_RETRIES=10
INITIAL_DELAY=5
RETRY_MULTIPLIER=2
LOG_FILE="/var/log/rfwb-portscan.log"

# Initialize log file
echo "Starting rfwb-portscan pre-start script at \$(date)" > "\$LOG_FILE"

OUTSIDE_INTERFACE=""
EXTERNAL_IP=""
attempt=1
delay=\$INITIAL_DELAY

while :; do
    OUTSIDE_INTERFACE=\$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="-outside" '\$2 ~ suffix {print \$1}')
    EXTERNAL_IP=\$(ip -4 addr show "\$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

    # Log the current state
    echo "\$(date): Attempt \$attempt - Interface: \$OUTSIDE_INTERFACE, IP: \$EXTERNAL_IP" >> "\$LOG_FILE"

    # Check if nftables service is active
    if ! systemctl is-active --quiet nftables; then
        echo "\$(date): nftables service is not active. Waiting for nftables service..." >> "\$LOG_FILE"
        systemctl start nftables
        sleep "\$delay"
        ((attempt++))
        delay=\$((delay * RETRY_MULTIPLIER))
        continue
    fi

    if [[ -n "\$OUTSIDE_INTERFACE" && -n "\$EXTERNAL_IP" ]]; then
        echo "\$(date): Successfully determined interface and IP." >> "\$LOG_FILE"
        break
    fi

    if [[ \$attempt -ge \$MAX_RETRIES ]]; then
        echo "\$(date): Error: Could not determine the outside interface or external IP address after \$attempt attempts. Exiting." >> "\$LOG_FILE"
        exit 1
    fi

    echo "\$(date): Attempt \$attempt failed. Retrying in \$delay seconds..." >> "\$LOG_FILE"
    sleep "\$delay"
    ((attempt++))
    delay=\$((delay * RETRY_MULTIPLIER))
done

echo "\$(date): Starting service: Protecting outside interface: \$OUTSIDE_INTERFACE with IP: \$EXTERNAL_IP" >> "\$LOG_FILE"
logger "rfwb-portscan: Protecting outside interface: \$OUTSIDE_INTERFACE with IP: \$EXTERNAL_IP"
EOF

# Make the pre-start script executable
chmod +x "$PRE_START_SCRIPT"

# Create a stop script to clean up nftables configuration
STOP_SCRIPT="/usr/local/bin/rfwb-portscan-stop.sh"
cat <<'EOF' >"$STOP_SCRIPT"
#!/bin/bash
echo "Flushing and removing dynamic block set, and resetting hosts.blocked file."

# Flush all rules in the input chain to remove references to the set
nft flush chain inet portscan input

# Delete the dynamic block set
nft delete set inet portscan dynamic_block

# Delete the table to remove all configurations
nft delete table inet portscan

# Reset the hosts.blocked file
truncate -s 0 /etc/nftables/hosts.blocked

echo "Dynamic block and configurations have been removed."
EOF

# Make the stop script executable
chmod +x "$STOP_SCRIPT"

# Create a custom handler script to manage start action
HANDLER_SCRIPT="/usr/local/bin/rfwb-portscan-handler.sh"
cat <<EOF >"$HANDLER_SCRIPT"
#!/bin/bash

# Source configuration file
CONFIG_FILE="/etc/rfwb-portscan.conf"
if [ -f "\$CONFIG_FILE" ]; then
    source "\$CONFIG_FILE"
else
    echo "Configuration file \$CONFIG_FILE not found. Using default settings."
fi

OUTSIDE_INTERFACE="\$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="-outside" '\$2 ~ suffix {print \$1}')"
EXTERNAL_IP="\$(ip -4 addr show "\$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)"

if [[ -z "\$OUTSIDE_INTERFACE" || -z "\$EXTERNAL_IP" ]]; then
    echo "Error: Could not determine the outside interface or external IP address. Exiting."
    exit 1
fi

# Function to generate nftables configuration
generate_nft_config() {
    # Load ignored ports from the configuration file, filtering out comments and empty lines
    IGNORED_PORTS=\$(grep -v '^#' "/etc/nftables/ignore_ports.conf" | tr -d '[:space:]' | tr ',' ', ')

    # Log the ports being ignored
    echo "Ignored ports: \$IGNORED_PORTS"

    # Create nftables configuration file
    cat <<EOL >"/etc/nftables/portscan.conf"
table inet portscan {
  set dynamic_block {
    type ipv4_addr
    flags timeout
    timeout $BLOCK_TIMEOUT
  }

  chain input {
    type filter hook input priority filter; policy accept;

    # Allow established and related connections
    ct state established,related accept

    # Drop packets from dynamically blocked IPs
    ip saddr @dynamic_block drop

     # Accept packets to ignored ports
    ip daddr $EXTERNAL_IP tcp dport == { \$IGNORED_PORTS } accept

    # Use configured ports for detection
    ip daddr $EXTERNAL_IP tcp dport { $MONITORED_PORTS } ct state new limit rate 10/minute burst 20 packets log prefix "Port Scan Detected: " counter


    # Detect SYN packets from untrusted sources on the outside interface
    iifname "$OUTSIDE_INTERFACE" tcp flags syn limit rate 10/minute burst 20 packets log prefix "Port Scan Detected: " counter
  }
}
EOL

    # Log the creation of the configuration file
    if [ -f "/etc/nftables/portscan.conf" ]; then
        echo "Configuration file created: /etc/nftables/portscan.conf"
    else
        echo "Error: Failed to create configuration file: /etc/nftables/portscan.conf"
        exit 1
    fi
}

# Flush existing rules to prevent duplicates
if nft list tables | grep -q  "inet portscan"; then
    nft delete table inet portscan
fi

# Regenerate and apply nftables configuration
generate_nft_config
if /usr/sbin/nft -f "/etc/nftables/portscan.conf"; then
    echo "nftables configuration applied successfully."
else
    echo "Error: Failed to apply nftables configuration."
    exit 1
fi

# Verify that the nftables configuration is applied
if ! nft list tables | grep -q "inet portscan"; then
    echo "Error: The portscan table is not initialized. Exiting."
    exit 1
fi
EOF

# Make the handler script executable
chmod +x "$HANDLER_SCRIPT"

# Create systemd service file
SYSTEMD_SERVICE_FILE="/etc/systemd/system/rfwb-portscan.service"
cat <<EOL >"$SYSTEMD_SERVICE_FILE"
[Unit]
Description=Port Scan Detection Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=$PRE_START_SCRIPT
ExecStart=$HANDLER_SCRIPT start
ExecStop=$STOP_SCRIPT
Type=oneshot
RemainAfterExit=yes
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable rfwb-portscan.service
systemctl start rfwb-portscan.service

echo "nftables port scan detection and blocking service has been installed and started for the outside interface."
echo "Blocked IPs are logged to $BLOCKED_FILE."

# Setup logging notifications
echo "Port scan events will be logged with the prefix 'Port Scan Detected:' in the system logs."
echo "To view these logs, you can use a command such as: journalctl -xe | grep 'Port Scan Detected'"

echo -e "${GREEN}Rocky Firewall Builder Port Scan Detection Complete...${TEXTRESET}"
sleep 4

 #Install the monitoring service for RFWB
 #!/bin/bash

# Define variables
SCRIPT_PATH="/usr/local/bin/rfwb-ps-mon.sh"
SERVICE_PATH="/etc/systemd/system/rfwb-ps-mon.service"
IGNORE_NETWORKS_FILE="/etc/nftables/ignore_networks.conf"
BLOCKED_FILE="/etc/nftables/hosts.blocked"

# Create the monitoring script
cat << 'EOF' > $SCRIPT_PATH
#!/bin/bash

# Ensure these variables are set
IGNORE_NETWORKS_FILE="/etc/nftables/ignore_networks.conf"
BLOCKED_FILE="/etc/nftables/hosts.blocked"

# Read ignore networks into a variable
IGNORE_NETWORKS=$(cat "$IGNORE_NETWORKS_FILE")

# Function to append unique IPs to the blocked file, ignoring networks from ignore_networks.conf
append_blocked_ip() {
    local ip="$1"
    for ignore_network in $IGNORE_NETWORKS; do
        if ipcalc -c "$ip" "$ignore_network" >/dev/null 2>&1; then
            echo "Ignoring IP $ip from scanning"
            return
        fi
    done
    if ! grep -q "^$ip$" "$BLOCKED_FILE"; then
        echo "$ip" >>"$BLOCKED_FILE"
        echo "Blocked IP $ip added to $BLOCKED_FILE"
        # Ensure the table and set are correctly initialized before adding elements
        if nft list tables | grep -q "inet portscan"; then
            nft add element inet portscan dynamic_block { $ip }
        else
            echo "Error: The portscan table or dynamic_block set is not initialized."
        fi
    fi
}

# Start monitoring logs from now
journalctl -k --since "now" -f | while read -r line; do
    if [[ "$line" == *"Port Scan Detected:"* ]]; then
        ip=$(echo "$line" | grep -oP 'SRC=\d+\.\d+\.\d+\.\d+' | cut -d '=' -f 2)
        if [[ -n "$ip" ]]; then
            append_blocked_ip "$ip"
        fi
    fi
done
EOF

# Make the script executable
chmod +x $SCRIPT_PATH

# Test the script manually
echo "Testing the script manually..."
$SCRIPT_PATH &
pid=$!
sleep 5
kill $pid  # Terminate the test process

# Create the systemd service unit file
cat << EOF > $SERVICE_PATH
[Unit]
Description=RFWB Port Scan Monitor
After=rfwb-portscan.service
Requires=rfwb-portscan.service

[Service]
Type=simple
ExecStart=$SCRIPT_PATH
ExecStop=/usr/bin/kill \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=rfwb-ps-mon

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd to recognize the new service
systemctl daemon-reload

# Enable the service to start on boot
systemctl enable rfwb-ps-mon.service

# Start the service
systemctl start rfwb-ps-mon.service

# Confirm the service status
echo "Verifying the service status..."
systemctl status rfwb-ps-mon.service

sleep 4

}

# Function to install ddns
install_ddclient() {
    clear
    echo -e "${GREEN}Installing ddns client (ddclient)...${TEXTRESET}"
    sleep 2
    dnf -y install ddclient
    echo -e "${GREEN}ddns client (ddclient) installation complete.${TEXTRESET}"
    sleep 4
}

#Function to install BIND and KEA 

# Function to install BIND
install_bind() {
    clear
    echo -e "${GREEN}Installing BIND...${TEXTRESET}"
    sleep 2
    dnf -y install bind
    echo -e "${GREEN}BIND installation complete.${TEXTRESET}"

    # Function to locate the inside interface and its sub-interfaces
    find_inside_interfaces() {
        main_interface=$(nmcli device status | awk '/-inside/ {print $1}')

        if [ -z "$main_interface" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        sub_interfaces=$(nmcli device status | awk -v main_intf="$main_interface" '$1 ~ main_intf "\\." {print $1}')
        inside_interfaces="$main_interface $sub_interfaces"

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for DNS on the inside interfaces
    setup_nftables_for_dns() {
        sudo systemctl enable nftables
        sudo systemctl start nftables

        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 53 accept"; then
                sudo nft add rule inet filter input iifname "$iface" udp dport 53 accept
                echo -e "${GREEN}Rule added: Allow DNS (UDP) on interface $iface${TEXTRESET}"
            else
                echo "Rule already exists: Allow DNS (UDP) on interface $iface"
            fi
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 53 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 53 accept
                echo -e "${GREEN}Rule added: Allow DNS (TCP) on interface $iface${TEXTRESET}"
            else
                echo "Rule already exists: Allow DNS (TCP) on interface $iface"
            fi
        done

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

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_dns

    echo -e "${GREEN}BIND Install Complete...${TEXTRESET}"
    sleep 4
}

# Function to install ISC KEA
install_isc_kea() {
    clear
    echo -e "${GREEN}Installing ISC KEA...${TEXTRESET}"
    sleep 2
    dnf -y install epel-release
    curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-2-6/cfg/setup/bash.rpm.sh' | sudo bash
    sudo dnf -y update
    dnf -y install isc-kea
    echo -e "${GREEN}ISC KEA installation complete.${TEXTRESET}"

    # Function to locate the inside interfaces
    find_inside_interfaces() {
        main_interface=$(nmcli device status | awk '/-inside/ {print $1}')

        if [ -z "$main_interface" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        sub_interfaces=$(nmcli device status | awk -v main_intf="$main_interface" '$1 ~ main_intf "\\." {print $1}')
        inside_interfaces="$main_interface $sub_interfaces"

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for DHCP on the inside interfaces
    setup_nftables_for_dhcp() {
        sudo systemctl enable nftables
        sudo systemctl start nftables

        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 67 accept"; then
                sudo nft add rule inet filter input iifname "$iface" udp dport 67 accept
                echo -e "${GREEN}Rule added: Allow DHCP (IPv4) on interface $iface${TEXTRESET}"
            else
                echo "Rule already exists: Allow DHCP (IPv4) on interface $iface"
            fi
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" udp dport 547 accept"; then
                sudo nft add rule inet filter input iifname "$iface" udp dport 547 accept
                echo -e "${GREEN}Rule added: Allow DHCP (IPv6) on interface $iface${TEXTRESET}"
            else
                echo "Rule already exists: Allow DHCP (IPv6) on interface $iface"
            fi
        done

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

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_dhcp

    echo -e "${GREEN}ISC-KEA Install Complete...${TEXTRESET}"
    sleep 4
}

# Master function to run both installations
install_net_services() {
    install_bind
    install_isc_kea
}

# Call the master function to execute both install scripts

# Function to install COCKPIT
install_cockpit() {
    clear
    echo -e "${GREEN}Installing Cockpit...${TEXTRESET}"
    sleep 2
    dnf -y install cockpit cockpit-storaged cockpit-files tuned
    echo -e "${GREEN}Cockpit installation complete.${TEXTRESET}"

    # Function to locate the inside interfaces
    find_inside_interfaces() {
        # Find all active interfaces with a name ending in '-inside'
        inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

        if [ -z "$inside_interfaces" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for Cockpit on the inside interfaces
    setup_nftables_for_cockpit() {
        # Ensure the nftables service is enabled and started
        sudo systemctl enable nftables
        sudo systemctl start nftables

        # Create a filter table if it doesn't exist
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        # Create an input chain if it doesn't exist
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        # Add rules to allow Cockpit on the inside interfaces using port 9090
        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 9090 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 9090 accept
                echo -e "${GREEN}Rule added: Allow Cockpit on port 9090 for interface $iface${TEXTRESET}"
            else
                echo "Rule already exists: Allow Cockpit on port 9090 for interface $iface"
            fi
        done
        # Check and handle rfwb-portscan service
        rfwb_status=$(systemctl is-active rfwb-portscan)
        if [ "$rfwb_status" == "active" ]; then
            systemctl stop rfwb-portscan
        fi
        # Save the current nftables configuration
        sudo nft list ruleset >/etc/sysconfig/nftables.conf
        # Restart the nftables service to apply changes
        sudo systemctl restart nftables
        # Restart rfwb-portscan service if it was active
        if [ "$rfwb_status" == "active" ]; then
            systemctl start rfwb-portscan
        fi
        # Show the added rules in the input chain
        sudo nft list chain inet filter input
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_cockpit

    # Enable and start cockpit.socket
    systemctl enable --now cockpit.socket
    systemctl start cockpit.socket

    # Continue with the rest of the script
    echo -e "${GREEN}Cockpit Install Complete...${TEXTRESET}"
    sleep 4
}

# Function to install NTOPNG
install_ntopng() {
    clear
    echo -e "${GREEN}Installing ntopng...${TEXTRESET}"
    sleep 2
    curl https://packages.ntop.org/centos-stable/ntop.repo >/etc/yum.repos.d/ntop.repo
    dnf -y config-manager --set-enabled crb
    dnf -y install epel-release
    dnf -y clean all
    dnf -y update
    dnf -y install pfring-dkms n2disk nprobe ntopng cento ntap
    echo -e "${GREEN}Enabling ntopng at boot up${TEXTRESET}"
    systemctl enable ntopng

    # Path to the configuration file
    CONFIG_FILE="/etc/ntopng/ntopng.conf"

    # Check if the configuration file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}Configuration file $CONFIG_FILE does not exist. Exiting...${TEXTRESET}"
        exit 1
    fi

    # Modify the line in the configuration file
    echo -e "$Modifying ${GREEN}$CONFIG_FILE...${TEXTRESET}"
    sed -i 's|^-G=/var/run/ntopng.pid|-G=/var/tmp/ntopng.pid --community|' "$CONFIG_FILE"

    # Verify the change
    if grep -q "^-G=/var/tmp/ntopng.pid --community" "$CONFIG_FILE"; then
        echo -e "Modification successful: -G=/var/tmp/ntopng.pid --community"
    else
        echo -e "${RED}Modification failed. Please check the file manually.${TEXTRESET}"
        exit 1
    fi

    # Enable ntopng service
    echo -e "Enabling ntopng service..."
    systemctl enable ntopng

    # Start ntopng service
    echo -e "Starting ntopng service..."
    systemctl start ntopng

    # Validate ntopng service is running
    if systemctl is-active --quiet ntopng; then
        echo -e "${GREEN}ntopng service is running.${TEXTRESET}"
    else
        echo -e "${RED}Failed to start ntopng service. Please check the service status manually.${TEXTRESET}"
        exit 1
    fi

    # Function to locate the inside interfaces
    find_inside_interfaces() {
        # Find all active interfaces with a name ending in '-inside'
        inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

        if [ -z "$inside_interfaces" ]; then
            echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
            exit 1
        fi

        echo -e "${GREEN}Inside interfaces found: $inside_interfaces${TEXTRESET}"
    }

    # Function to set up nftables rules for ntopng on the inside interfaces
    setup_nftables_for_ntopng() {
        # Ensure the nftables service is enabled and started
        sudo systemctl enable nftables
        sudo systemctl start nftables

        # Create a filter table if it doesn't exist
        if ! sudo nft list tables | grep -q 'inet filter'; then
            sudo nft add table inet filter
        fi

        # Create an input chain if it doesn't exist
        if ! sudo nft list chain inet filter input &>/dev/null; then
            sudo nft add chain inet filter input { type filter hook input priority 0 \; }
        fi

        # Add rules to allow ntopng on the inside interfaces using port 3000
        for iface in $inside_interfaces; do
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 3000 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 3000 accept
                echo -e "${GREEN}Rule added: Allow ntopng on port 3000 for interface $iface${TEXTRESET}"
            else
                echo "Rule already exists: Allow ntopng on port 3000 for interface $iface"
            fi
        done
        # Check and handle rfwb-portscan service
        rfwb_status=$(systemctl is-active rfwb-portscan)
        if [ "$rfwb_status" == "active" ]; then
            systemctl stop rfwb-portscan
        fi
        # Save the current nftables configuration
        sudo nft list ruleset >/etc/sysconfig/nftables.conf
        # Restart the nftables service to apply changes
        sudo systemctl restart nftables
        # Restart rfwb-portscan service if it was active
        if [ "$rfwb_status" == "active" ]; then
            systemctl start rfwb-portscan
        fi
        # Show the added rules in the input chain
        sudo nft list chain inet filter input
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_ntopng

    # Continue with the rest of the script
    echo -e "${GREEN}ntopng Install Complete...${TEXTRESET}"
    sleep 4
}
# Function to install Suricata
install_suricata() {
    clear
    echo -e "Installing Suricata Engine${RESET}"
    sleep 2
    # Function to check if the system has at least 8 GB of RAM
    check_ram() {
        # Get the total memory in KB
        total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        # Convert the memory to GB and round up
        total_mem_gb=$(echo "$total_mem_kb / 1024 / 1024" | bc -l | awk '{print ($1 == int($1)) ? $1 : int($1) + 1}')

        # Check if the memory is at least 8 GB
        if ((total_mem_gb >= 8)); then
            echo -e "${GREEN}RAM Check: Passed (Total RAM: ${total_mem_gb} GB)${RESET}"
            sleep 1
            return 0
        else
            needed_ram=$((8 - total_mem_gb))
            echo -e "${RED}RAM Check: Failed (Total RAM: ${total_mem_gb} GB)${RESET}"
            echo -e "Additional RAM needed: ${needed_ram} GB${RESET}"
            return 1
        fi
    }

    # Function to check if the system has at least 2 CPUs
    check_cpus() {
        # Get the number of CPUs
        cpu_count=$(grep -c ^processor /proc/cpuinfo)

        # Check if the CPU count is at least 2
        if [ "$cpu_count" -ge 2 ]; then
            echo -e "${GREEN}CPU Check: Passed (Total CPUs: ${cpu_count})${RESET}"
            sleep 1
            return 0
        else
            needed_cpus=$((2 - cpu_count))
            echo -e "${RED}CPU Check: Failed (Total CPUs: ${cpu_count})${RESET}"
            echo -e "Additional CPUs needed: ${needed_cpus}${RESET}"
            return 1
        fi
    sleep 4
    }

    # Run checks
    check_ram
    ram_status=$?

    check_cpus
    cpu_status=$?

    # Evaluate results
    echo -e "${CYAN}\nSummary:${RESET}"
    if [ "$ram_status" -eq 0 ] && [ "$cpu_status" -eq 0 ]; then
        echo -e "${GREEN}System meets the minimum requirements.${RESET}"
        sleep 3
    else
        echo -e "${RED}System does not meet the minimum requirements (8GB of RAM 2 CPU).${RESET}"
        [ "$ram_status" -ne 0 ] && echo -e "Please add more RAM.${RESET}"
        [ "$cpu_status" -ne 0 ] && echo -e "Please add more CPUs.${RESET}"
        sleep 3
        exit 1
    fi

    # Update the server
    clear
    echo -e "Updating the server...${TEXTRESET}"
    if sudo dnf update -y; then
        echo -e "${GREEN}Server updated successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update the server.${TEXTRESET}"
        exit 1
    fi

    # Install essential packages
    clear
    echo -e "Installing essential suricata packages...${TEXTRESET}"
    sleep 2
    if sudo dnf install -y yum-utils bc nano curl wget policycoreutils-python-utils; then
        echo -e "${GREEN}Essential packages installed successfully.${TEXTRESET}"
        sleep 2
    else
        echo -e "${RED}Failed to install essential packages.${TEXTRESET}"
        exit 1
    fi

    # Install Suricata
    clear
    echo -e "Installing Suricata...${TEXTRESET}"
    sleep 2
    # Enable copr command for dnf
    echo -e "Enabling dnf copr command...${TEXTRESET}"
    if sudo dnf install -y 'dnf-command(copr)'; then
        echo -e "${GREEN}dnf copr command enabled.${TEXTRESET}"
    else
        echo -e "${RED}Failed to enable dnf copr command.${TEXTRESET}"
        exit 1
    fi

    # Enable the OISF repository for Suricata
    echo -e "Enabling OISF Suricata repository...${TEXTRESET}"
    if echo 'y' | sudo dnf copr enable @oisf/suricata-7.0; then
        echo -e "${GREEN}OISF Suricata repository enabled.${TEXTRESET}"
    else
        echo -e "${RED}Failed to enable OISF Suricata repository.${TEXTRESET}"
        exit 1
    fi

    # Add the EPEL repository
    echo -e "Adding EPEL repository...${TEXTRESET}"
    if sudo dnf install -y epel-release dnf-plugins-core; then
        echo -e "${GREEN}EPEL repository added successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to add EPEL repository.${TEXTRESET}"
        exit 1
    fi

    # Install Suricata
    echo -e "Installing Suricata package...${TEXTRESET}"
    if sudo dnf install -y suricata; then
        echo -e "${GREEN}Suricata installed successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to install Suricata.${TEXTRESET}"
        exit 1
    fi

    # Enable Suricata service
    echo -e "Enabling Suricata service...${TEXTRESET}"
    if sudo systemctl enable suricata; then
        echo -e "${GREEN}Suricata service enabled.${TEXTRESET}"
    else
        echo -e "${RED}Failed to enable Suricata service.${TEXTRESET}"
        exit 1
    fi

    # Configure Suricata
    echo -e "Configuring Suricata...${TEXTRESET}"

    # Backup the original Suricata configuration file
    sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

    # Enable Community ID in suricata.yaml
    echo -e "Enabling Community ID feature in Suricata...${TEXTRESET}"
    sudo sed -i 's/# \(community-id:\) false/\1 true/' /etc/suricata/suricata.yaml

    # Detect the inside network interface using nmcli and awk
    INSIDE_INTERFACE=$(nmcli connection show --active | awk '/-inside/ {print $4}')

    if [ -z "$INSIDE_INTERFACE" ]; then
        echo -e "${RED}No inside interface found. Please ensure your interface names follow the expected pattern.${TEXTRESET}"
        exit 1
    fi

    echo -e "${GREEN}Detected inside interface: $INSIDE_INTERFACE${TEXTRESET}"

    # Update the pcap interface in suricata.yaml
    echo -e "Updating pcap interface to use $INSIDE_INTERFACE...${TEXTRESET}"
    sudo sed -i "/# Cross platform libpcap capture support/,/interface:/ s/interface: eth0/interface: $INSIDE_INTERFACE/" /etc/suricata/suricata.yaml

    # Update the af-packet interface in suricata.yaml
    echo -e "Updating af-packet interface to use $INSIDE_INTERFACE...${TEXTRESET}"
    sudo sed -i "/# Linux high speed capture support/,/af-packet:/ {n; s/interface: eth0/interface: $INSIDE_INTERFACE/}" /etc/suricata/suricata.yaml

    # Update the inside interface in /etc/sysconfig/suricata
    echo -e "Updating inside interface in /etc/sysconfig/suricata...${TEXTRESET}"
    sudo sed -i "s/eth0/$INSIDE_INTERFACE/g" /etc/sysconfig/suricata

    # Configure directory permissions for Suricata
    echo -e "Configuring directory permissions for Suricata...${TEXTRESET}"
    sudo chgrp -R suricata /etc/suricata
    sudo chgrp -R suricata /var/lib/suricata
    sudo chgrp -R suricata /var/log/suricata
    sudo chmod -R g+r /etc/suricata/
    sudo chmod -R g+rw /var/lib/suricata
    sudo chmod -R g+rw /var/log/suricata

    # Add current user to the suricata group
    echo -e "Adding current user to the suricata group...${TEXTRESET}"
    sudo usermod -a -G suricata $USER

    # Validate that the user was added to the suricata group
    echo -e "Validating user group membership...${TEXTRESET}"
    if id -nG "$USER" | grep -qw "suricata"; then
        echo -e "${GREEN}User $USER is successfully added to the suricata group.${TEXTRESET}"
    else
        echo -e "${RED}Failed to add user $USER to the suricata group.${TEXTRESET}"
        exit 1
    fi
    # Run suricata-update update-sources
    echo -e "Running suricata-update update-sources...${TEXTRESET}"
    if sudo suricata-update update-sources; then
        echo -e "${GREEN}suricata-update update-sources completed successfully.${TEXTRESET}"
    else
        echo -e "${RED}Failed to run suricata-update.${TEXTRESET}"
        exit 1
    fi
   # Run suricata-update
echo -e "Running suricata-update...${TEXTRESET}"
# Set trap to ignore SIGINT
trap '' SIGINT
if sudo suricata-update; then
    echo -e "suricata-update completed ${GREEN}successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to run suricata-update.${TEXTRESET}"
    exit 1
fi

# Loop to allow adding additional rule sources
while true; do
    echo -e "Do you want to add additional rule sources? (y/n)${TEXTRESET}"
    read -p "Your choice: " add_rules

    if [[ "$add_rules" == "y" || "$add_rules" == "Y" ]]; then
        echo -e "Listing available rule sources...${TEXTRESET}"
        sudo suricata-update list-sources

        echo -e "Please enter the source names you want to add, separated by spaces:${TEXTRESET}"
        
        # Ignore Ctrl+C during the read command
        trap '' SIGINT
        read -r rule_sources
        # Reapply default behavior for Ctrl+C after read
        trap - SIGINT

        for source in $rule_sources; do
            echo -e "Adding source $source...${TEXTRESET}"
            sudo suricata-update enable-source "$source"
        done

    else
        break
    fi
done

    # Run suricata-update after the loop
    echo -e "[${YELLOW}INFO${TEXTRESET}] Running suricata-update..."
    if sudo suricata-update; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] suricata-update completed successfully."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to run suricata-update.${TEXTRESET}"
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Suricata has been configured with the inside interface ${GREEN}$INSIDE_INTERFACE${TEXTRESET} and proper permissions."
    # Inform the user that the configuration validation is starting
    echo -e "[${YELLOW}INFO${TEXTRESET}] Validating Suricata configuration..."

    # Define the command to run Suricata with the test configuration
    COMMAND="suricata -T -c /etc/suricata/suricata.yaml -v"

    # Execute the command and capture the output
    OUTPUT=$($COMMAND 2>&1)

    # Define the success message to look for
    SUCCESS_MESSAGE="Notice: suricata: Configuration provided was successfully loaded. Exiting."

    # Check if the output contains the success message
    if echo "$OUTPUT" | grep -q "$SUCCESS_MESSAGE"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Suricata configuration was loaded successfully.${TEXTRESET}"

    else
        echo -e "[${RED}ERROR${TEXTRESET}] Suricata configuration test failed.${TEXTRESET}"
        echo "Output:"
        echo "$OUTPUT"
        exit 1
    fi
    # Start the Suricata service
    echo -e "Starting Suricata service..."
    sudo systemctl start suricata

    # Show the status of the Suricata service
    echo -e "[${YELLOW}INFO${TEXTRESET}] Checking Suricata service status..."
    status_output=$(sudo systemctl status suricata --no-pager)

    # Display the status output
    echo "$status_output"

    #Delay checking the log file for xseconds
    sleep 10

    # Function to check for permission errors and fix them
    check_and_fix_permissions() {
        # Capture the status output from the Suricata service
        status_output=$(sudo systemctl status suricata --no-pager)

        # Check for permission denied errors in the status output
        if echo "$status_output" | grep -qE "E: logopenfile: Error opening file: \"/var/log/suricata/fast.log\": Permission denied|W: runmodes: output module \"fast\": setup failed|E: logopenfile: Error opening file: \"/var/log/suricata/eve.json\": Permission denied|W: runmodes: output module \"eve-log\": setup failed|E: logopenfile: Error opening file: \"/var/log/suricata/stats.log\": Permission denied|W: runmodes: output module \"stats\": setup failed"; then
            # Display the specific lines indicating permission errors
            echo -e "[${RED}ERROR${TEXTRESET}] Detected permission issues in the following log entries:"
            echo "$status_output" | grep -E "E: logopenfile: Error opening file: \"/var/log/suricata/fast.log\": Permission denied|W: runmodes: output module \"fast\": setup failed|E: logopenfile: Error opening file: \"/var/log/suricata/eve.json\": Permission denied|W: runmodes: output module \"eve-log\": setup failed|E: logopenfile: Error opening file: \"/var/log/suricata/stats.log\": Permission denied|W: runmodes: output module \"stats\": setup failed"
            return 1
        else
            return 0
        fi
    }

    # Initialize attempt counter
    attempts=0

    # Define the maximum number of attempts
    max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        check_and_fix_permissions
        if [ $? -eq 0 ]; then
            echo -e "\n[${GREEN}SUCCESS${TEXTRESET}] Suricata service is running without permission issues."
            # Proceed without exiting to continue the script
            break
        else
            echo -e "\n[${RED}ERROR${TEXTRESET}] There are permission issues with Suricata log files."
            echo -e "[${YELLOW}INFO${TEXTRESET}] Attempting to fix permissions (Attempt $((attempts + 1)) of $max_attempts)..."
            sudo chown -R suricata:suricata /var/log/suricata
            echo -e "[${YELLOW}INFO${TEXTRESET}] Permissions have been reset. Restarting Suricata service..."
            sudo systemctl restart suricata
            sleep 10
            # Check again after attempting to fix permissions
            echo -e "[${YELLOW}INFO${TEXTRESET}] Re-checking Suricata service status..."
            check_and_fix_permissions
            if [ $? -eq 0 ]; then
                echo -e "\n[${GREEN}SUCCESS${TEXTRESET}] Permissions successfully fixed."
                break
            else
                echo -e "\n[${RED}ERROR${TEXTRESET}] Permission issues still exist after attempting to fix them."
            fi
        fi
        attempts=$((attempts + 1))
    done

    if [ $attempts -eq $max_attempts ]; then
        echo -e "\n[${RED}ERROR${TEXTRESET}] Failed to resolve permission issues after $max_attempts attempts."
        exit 1
    fi

    # Inform the user about the test
    echo -e "[${YELLOW}INFO${TEXTRESET}] Testing Suricata rule..."
    echo -e "[${YELLOW}INFO${TEXTRESET}] Waiting for the engine to start..."
    # Total duration for the progress bar
    duration=60

    # Total number of steps in the progress bar
    steps=30

    # Calculate the sleep duration between each step
    sleep_duration=$(echo "$duration/$steps" | bc -l)

    # Initialize the progress bar
    progress=""

    echo -e "Progress:"

    # Loop to update the progress bar
    for ((i = 0; i <= steps; i++)); do
        # Calculate percentage
        percent=$((i * 100 / steps))

        # Add a '#' to the progress bar for each step
        progress+="#"

        # Print the progress bar
        printf "\r[%-30s] %d%%" "$progress" "$percent"

        # Sleep for the calculated duration
        sleep "$sleep_duration"
    done

    # Move to the next line after completion
    echo -e "\n[${GREEN}SUCCESS${TEXTRESET}]"
    # Run the curl command and capture the response
    response=$(curl -s http://testmynids.org/uid/index.html)

    # Run the curl command and capture the response
    response=$(curl -s http://testmynids.org/uid/index.html)
    # Validate the response
    expected_response="uid=0(root) gid=0(root) groups=0(root)"
    if [ "$response" == "$expected_response" ]; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Expected response received:${TEXTRESET}"
        echo -e "${GREEN}$response${TEXTRESET}"
        echo -e "Please Wait..."
        sleep 10 
        # Capture the last line of the fast.log containing the specified ID
        last_log_line=$(grep 2100498 /var/log/suricata/fast.log | tail -n 1)
        echo -e "Last log line with ID 2100498: ${last_log_line}${TEXTRESET}" # Debug: Print the last line for verification

        # Check the log line for the classification
        if echo "$last_log_line" | grep -q "\[Classification: Potentially Bad Traffic\]"; then
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Suricata rule was successful. The classification '[Classification: Potentially Bad Traffic]' was found in the log entry with ${YELLOW}ID 2100498.${TEXTRESET}"
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Suricata rule failed. The expected classification was not found in the log entry with ID 2100498."
            sleep 5
            exit 1
        fi
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Curl command failed. The expected response was not received."
        sleep 5
        exit 1
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Suricata Install Complete..."
    sleep 4
}

# Use dialog to prompt the user
cmd=(dialog --separate-output --checklist "Select services to install:" 22 90 16)
options=(
    1 "Install BIND and ISC KEA DHCP" off
    2 "Install Cockpit" off
    3 "Install ntopng" off
    4 "Install DDNS Client" off
    5 "Install Suricata (Only Suricata Engine)" off
    6 "Install RFWB Portscan detection" off
    7 "Install SNMP Daemon" off
    8 "Install Netdata" off
    9 "Install/Configure QOS for VOICE" off
   10 "Install mDNS Reflector (Avahi)" off
   11 "Install EVEBOX for Suricata" off
)
choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)

clear

for choice in $choices; do
    case $choice in
    1)
        install_net_services
        ;;
    2)
        install_cockpit
        ;;
    3)
        install_ntopng
        ;;
    4)
        install_ddclient
        ;;
    5)
        install_suricata
        ;;
    6)
        install_portscan
        ;;
    7)
        install_snmpd
        ;;
    8)
        install_netdata
        ;;
    9)
        install_qos
        ;;
    10)
        install_avahi
        ;;
    11)
        install_eve
        ;;
    esac
done


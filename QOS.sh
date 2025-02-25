#!/bin/bash

# Define color variables
GREEN="\033[0;32m"
RED="\033[0;31m"
TEXTRESET="\033[0m"

# Define the configuration and script paths
CONFIG_FILE="/etc/rfwb-qos.conf"
SCRIPT_FILE="/usr/local/bin/rfwb-qos.sh"
SERVICE_FILE="/etc/systemd/system/rfwb-qos.service"
LOG_FILE="/var/log/rfwb-qos.log"
ERROR_LOG_FILE="/var/log/rfwb-qos-errors.log"

# Function to create a configuration file with default settings
create_config() {
    echo -e "${GREEN}Creating configuration file at $CONFIG_FILE...${TEXTRESET}" | tee -a $LOG_FILE
    cat <<EOF > $CONFIG_FILE
# /etc/rfwb-qos.conf

percentage_bandwidth = 10
adjust_interval_hours = 4

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

# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Step 1: Perform initial setup and get user input
initial_setup() {
    echo "Determining network interfaces..." | tee -a $LOG_FILE
    INSIDE_INTERFACE=$(find_interface "-inside")
    OUTSIDE_INTERFACE=$(find_interface "-outside")

    if [ -z "$OUTSIDE_INTERFACE" ]; then
        echo -e "${RED}No outside interface found. Exiting.${TEXTRESET}" | tee -a $LOG_FILE
        exit 1
    fi

    echo -e "${GREEN}Selected outside interface: $OUTSIDE_INTERFACE${TEXTRESET}" | tee -a $LOG_FILE

    echo "Running speed test to measure current throughput. This may take a moment..." | tee -a $LOG_FILE
    speedtest_output=$(speedtest --format=json 2>>$ERROR_LOG_FILE)

    if [ $? -ne 0 ]; then
        echo -e "${RED}Speedtest failed. Check the network connection and speedtest-cli installation.${TEXTRESET}" | tee -a $ERROR_LOG_FILE
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

    read -p "Enter the percentage of bandwidth you want to reserve for voice and video applications: " PERCENTAGE

    echo -e "${GREEN}Setting up with $PERCENTAGE% reserved bandwidth.${TEXTRESET}" | tee -a $LOG_FILE

    create_config
}

# Step 3: Create the QoS adjustment script
create_script() {
    echo -e "${GREEN}Creating QoS adjustment script at $SCRIPT_FILE...${TEXTRESET}" | tee -a $LOG_FILE
    cat <<'EOF' > $SCRIPT_FILE
#!/bin/bash

CONFIG_FILE="/etc/rfwb-qos.conf"
LOG_FILE="/var/log/rfwb-qos.log"
ERROR_LOG_FILE="/var/log/rfwb-qos-errors.log"

# Function to load configuration
load_config() {
    percentage_bandwidth=0
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

# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Function to perform QoS configuration
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

    # Round down to the nearest Mbps
    CEIL_DOWNLOAD=$(($DOWNLOAD_SPEED_KBIT / 1000 - 1))
    CEIL_UPLOAD=$(($UPLOAD_SPEED_KBIT / 1000 - 1))

    echo "Rounded down ceiling for download is ${CEIL_DOWNLOAD} Mbit/s." | tee -a $LOG_FILE
    echo "Rounded down ceiling for upload is ${CEIL_UPLOAD} Mbit/s." | tee -a $LOG_FILE

    RESERVED_DOWNLOAD_BANDWIDTH=$(($CEIL_DOWNLOAD * 1000 * $percentage_bandwidth / 100))
    RESERVED_UPLOAD_BANDWIDTH=$(($CEIL_UPLOAD * 1000 * $percentage_bandwidth / 100))

    echo "Configuring QoS on $OUTSIDE_INTERFACE..." | tee -a $LOG_FILE
    tc qdisc del dev $OUTSIDE_INTERFACE root 2>>$ERROR_LOG_FILE || true
    tc qdisc add dev $OUTSIDE_INTERFACE root handle 1: htb default 20 r2q 2 2>>$ERROR_LOG_FILE
    tc class add dev $OUTSIDE_INTERFACE parent 1: classid 1:1 htb rate ${CEIL_DOWNLOAD}Mbit ceil ${CEIL_DOWNLOAD}Mbit 2>>$ERROR_LOG_FILE
    tc class add dev $OUTSIDE_INTERFACE parent 1:1 classid 1:10 htb rate ${RESERVED_DOWNLOAD_BANDWIDTH}kbit ceil ${RESERVED_DOWNLOAD_BANDWIDTH}kbit 2>>$ERROR_LOG_FILE

    echo "QoS configuration applied to $OUTSIDE_INTERFACE." | tee -a $LOG_FILE
    tc -s class show dev $OUTSIDE_INTERFACE | tee -a $LOG_FILE
}

configure_qos
EOF
    chmod +x $SCRIPT_FILE
    echo -e "${GREEN}QoS adjustment script created.${TEXTRESET}" | tee -a $LOG_FILE
}

# Step 4: Create the systemd service
create_service() {
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
}

# Step 5: Enable and start the service
enable_service() {
    echo "Enabling and starting the RFWB QoS service..." | tee -a $LOG_FILE
    systemctl daemon-reload
    systemctl enable rfwb-qos.service
    systemctl start rfwb-qos.service
    echo -e "${GREEN}Service enabled and started.${TEXTRESET}" | tee -a $LOG_FILE
}

# Execute the steps
initial_setup
create_script
create_service
enable_service

echo -e "${GREEN}Installation complete.${TEXTRESET}" | tee -a $LOG_FILE

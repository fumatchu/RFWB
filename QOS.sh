#!/bin/bash

# Define the configuration and script paths
CONFIG_FILE="/etc/rfwb-qos.conf"
SCRIPT_FILE="/usr/local/bin/rfwb-qos.sh"
SERVICE_FILE="/etc/systemd/system/rfwb-qos.service"

# Function to load configuration
load_config() {
    # Initialize all expected variables to avoid unset variable issues
    percentage_bandwidth=0
    adjust_interval_hours=0
    wifi_calling_ports=""
    sip_ports=""
    rtp_ports=""
    rtsp_ports=""
    h323_port=""
    webrtc_ports=""
    mpeg_ts_port=""

    while IFS='= ' read -r key value; do
        if [[ $key =~ ^[a-zA-Z_]+$ ]]; then
            value="${value//\"/}"  # Remove any surrounding quotes
            declare "$key=$value"
        fi
    done < "$CONFIG_FILE"
}

# Step 1: Perform initial setup and get user input
initial_setup() {
    echo "Determining network interfaces..." | tee >(logger)
    INSIDE_INTERFACE=$(find_interface "-inside")
    OUTSIDE_INTERFACE=$(find_interface "-outside")

    echo "Selected outside interface: $OUTSIDE_INTERFACE"

    echo "Running speed test to measure current throughput. This may take a moment..."
    speedtest --format=json > speedtest_result.json

    DOWNLOAD_SPEED=$(jq '.download.bandwidth' speedtest_result.json)
    UPLOAD_SPEED=$(jq '.upload.bandwidth' speedtest_result.json)

    DOWNLOAD_SPEED_KBIT=$(($DOWNLOAD_SPEED * 8 / 1000))
    UPLOAD_SPEED_KBIT=$(($UPLOAD_SPEED * 8 / 1000))

    echo "Current download speed is ${DOWNLOAD_SPEED_KBIT} kbit/s."
    echo "Current upload speed is ${UPLOAD_SPEED_KBIT} kbit/s."

    if [ "$DOWNLOAD_SPEED_KBIT" -lt 10000 ]; then
        R2Q_VALUE=1
    elif [ "$DOWNLOAD_SPEED_KBIT" -lt 100000 ]; then
        R2Q_VALUE=2
    else
        R2Q_VALUE=10
    fi

    echo "Setting r2q value to $R2Q_VALUE based on the download throughput."

    read -p "Enter the percentage of bandwidth you want to reserve for voice and video applications: " PERCENTAGE

    rm -f speedtest_result.json

    echo "Setting up with $PERCENTAGE% reserved bandwidth."

    create_config $PERCENTAGE
}

# Step 2: Create the configuration file
create_config() {
    local percentage_bandwidth=$1
    echo "Creating configuration file at $CONFIG_FILE..."
    cat <<EOF > $CONFIG_FILE
# /etc/rfwb-qos.conf

percentage_bandwidth = $percentage_bandwidth
adjust_interval_hours = 4

wifi_calling_ports = 500,4500
sip_ports = 5060
rtp_ports = 10000-20000
rtsp_ports = 554,8554
h323_port = 1720
webrtc_ports = 16384-32767
mpeg_ts_port = 1234
EOF
    echo "Configuration file created."
}

# Step 3: Create the QoS adjustment script
create_script() {
    echo "Creating QoS adjustment script at $SCRIPT_FILE..."
    cat <<'EOF' > $SCRIPT_FILE
#!/bin/bash

CONFIG_FILE="/etc/rfwb-qos.conf"

# Function to load configuration
load_config() {
    # Initialize all expected variables to avoid unset variable issues
    percentage_bandwidth=0
    adjust_interval_hours=0
    wifi_calling_ports=""
    sip_ports=""
    rtp_ports=""
    rtsp_ports=""
    h323_port=""
    webrtc_ports=""
    mpeg_ts_port=""

    while IFS='= ' read -r key value; do
        if [[ $key =~ ^[a-zA-Z_]+$ ]]; then
            value="${value//\"/}"  # Remove any surrounding quotes
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

    echo "Running speed test to measure current throughput..."
    speedtest --format=json > speedtest_result.json

    DOWNLOAD_SPEED=$(jq '.download.bandwidth' speedtest_result.json)
    UPLOAD_SPEED=$(jq '.upload.bandwidth' speedtest_result.json)

    DOWNLOAD_SPEED_KBIT=$(($DOWNLOAD_SPEED * 8 / 1000))
    UPLOAD_SPEED_KBIT=$(($UPLOAD_SPEED * 8 / 1000))

    echo "Current download speed is ${DOWNLOAD_SPEED_KBIT} kbit/s."
    echo "Current upload speed is ${UPLOAD_SPEED_KBIT} kbit/s."

    if [ "$DOWNLOAD_SPEED_KBIT" -lt 10000 ]; then
        R2Q_VALUE=1
    elif [ "$DOWNLOAD_SPEED_KBIT" -lt 100000 ]; then
        R2Q_VALUE=2
    else
        R2Q_VALUE=10
    fi

    RESERVED_DOWNLOAD_BANDWIDTH=$(($DOWNLOAD_SPEED_KBIT * $percentage_bandwidth / 100))
    RESERVED_UPLOAD_BANDWIDTH=$(($UPLOAD_SPEED_KBIT * $percentage_bandwidth / 100))

    echo "Configuring QoS on $OUTSIDE_INTERFACE..."
    tc qdisc del dev $OUTSIDE_INTERFACE root 2>>/var/log/messages || true
    tc qdisc add dev $OUTSIDE_INTERFACE root handle 1: htb default 20 r2q $R2Q_VALUE 2>>/var/log/messages
    tc class add dev $OUTSIDE_INTERFACE parent 1: classid 1:1 htb rate ${DOWNLOAD_SPEED_KBIT}kbit 2>>/var/log/messages
    tc class add dev $OUTSIDE_INTERFACE parent 1:1 classid 1:10 htb rate ${RESERVED_DOWNLOAD_BANDWIDTH}kbit ceil ${RESERVED_DOWNLOAD_BANDWIDTH}kbit 2>>/var/log/messages

    IFS=',' read -ra PORTS <<< "$wifi_calling_ports,$sip_ports"
    for port in "${PORTS[@]}"; do
        tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:10 2>>/var/log/messages
    done

    IFS='-' read -r start end <<< "$rtp_ports"
    for port in $(seq $start $end); do
        tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:10 2>>/var/log/messages
    done

    IFS=',' read -ra PORTS <<< "$rtsp_ports,$h323_port,$mpeg_ts_port"
    for port in "${PORTS[@]}"; do
        tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:10 2>>/var/log/messages
    done

    IFS='-' read -r start end <<< "$webrtc_ports"
    for port in $(seq $start $end); do
        tc filter add dev $OUTSIDE_INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport $port 0xffff flowid 1:10 2>>/var/log/messages
    done

    echo "QoS configuration applied to $OUTSIDE_INTERFACE."

    # Remove the speedtest result file
    rm -f speedtest_result.json
}

# Determine the current hour without a leading zero
current_hour=$(date +%-H)

# Run QoS adjustments during peak hours (16-23) or based on the adjust_interval_hours
if (( adjust_interval_hours > 0 && ((current_hour >= 16 && current_hour <= 23) || (current_hour % adjust_interval_hours == 0)) )); then
    configure_qos
fi
EOF
    chmod +x $SCRIPT_FILE
    echo "QoS adjustment script created."
}

# Step 4: Create the systemd service
create_service() {
    echo "Creating systemd service at $SERVICE_FILE..."
    cat <<EOF > $SERVICE_FILE
[Unit]
Description=RFWB QoS Service
After=network.target

[Service]
ExecStart=$SCRIPT_FILE
Type=simple
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    echo "Systemd service created."
}

# Step 5: Enable and start the service
enable_service() {
    echo "Enabling and starting the RFWB QoS service..."
    systemctl daemon-reload
    systemctl enable rfwb-qos.service
    systemctl start rfwb-qos.service
    echo "Service enabled and started."
}

# Function to find the network interface based on connection name ending
find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

# Execute the steps
initial_setup
create_script
create_service
enable_service

echo "Installation complete."

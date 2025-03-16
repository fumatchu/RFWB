#!/bin/bash

# Define color codes for output formatting
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

clear
echo -e "${YELLOW}=== Wi-Fi Access Point Testing Script ===${TEXTRESET}"

# Step 1: Ensure required packages are installed
REQUIRED_PKGS=("hostapd" "iw" "iproute" "bridge-utils")

echo -e "${YELLOW}Checking required packages...${TEXTRESET}"
for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! rpm -q "$pkg" &>/dev/null; then
        echo -e "${RED}$pkg is not installed. Installing now...${TEXTRESET}"
        sudo dnf install -y "$pkg"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully installed $pkg.${TEXTRESET}"
        else
            echo -e "${RED}Failed to install $pkg. Exiting.${TEXTRESET}"
            exit 1
        fi
    else
        echo -e "${GREEN}$pkg is already installed.${TEXTRESET}"
    fi
done

# Step 2: Find a wireless interface
echo -e "${YELLOW}Scanning for wireless interfaces...${TEXTRESET}"
WIFI_IFACE=$(iw dev | awk '/Interface/ {print $2}' | head -n 1)

if [[ -z "$WIFI_IFACE" ]]; then
    echo -e "${RED}No wireless interface found. Please check your hardware.${TEXTRESET}"
    exit 1
else
    echo -e "${GREEN}Found wireless interface: $WIFI_IFACE${TEXTRESET}"
fi

# Step 3: Stop any running `hostapd` or `wpa_supplicant` processes
echo -e "${YELLOW}Stopping any running hostapd or wpa_supplicant processes...${TEXTRESET}"
sudo systemctl stop hostapd wpa_supplicant
sudo pkill -9 hostapd
sudo pkill -9 wpa_supplicant
sudo killall -q hostapd
sudo killall -q wpa_supplicant
sleep 2

# Double-check and force kill if needed
if pgrep -x "hostapd" > /dev/null; then
    echo -e "${RED}hostapd is still running! Force killing...${TEXTRESET}"
    sudo pkill -9 hostapd
fi
if pgrep -x "wpa_supplicant" > /dev/null; then
    echo -e "${RED}wpa_supplicant is still running! Force killing...${TEXTRESET}"
    sudo pkill -9 wpa_supplicant
fi
sleep 1  # Ensure processes have completely stopped

# Step 4: Reset Wi-Fi interface
echo -e "${YELLOW}Resetting Wi-Fi interface...${TEXTRESET}"
sudo ip link set "$WIFI_IFACE" down
sudo iw dev "$WIFI_IFACE" set type managed
sudo ip link set "$WIFI_IFACE" up
sleep 1

# Step 5: Switch Wi-Fi to AP mode
echo -e "${YELLOW}Configuring $WIFI_IFACE as an Access Point...${TEXTRESET}"
sudo ip link set "$WIFI_IFACE" down
sudo iw dev "$WIFI_IFACE" set type __ap
sudo ip link set "$WIFI_IFACE" up
sleep 1

# Step 6: Create TEMPORARY `hostapd` configuration for TEST SSID
echo -e "${YELLOW}Starting TEST SSID (RFWB-Setup)...${TEXTRESET}"
cat <<EOF | sudo tee /etc/hostapd/hostapd-test.conf > /dev/null
interface=$WIFI_IFACE
driver=nl80211
ssid=RFWB-Setup
hw_mode=g
channel=6
auth_algs=1
wpa=0
EOF

# Step 7: Start hostapd quietly in the background
echo -e "${YELLOW}Starting hostapd in quiet mode...${TEXTRESET}"
sudo hostapd -dd /etc/hostapd/hostapd-test.conf &> /tmp/hostapd-test.log &
HOSTAPD_PID=$!

# Wait 5 seconds to collect logs
sleep 5

# Step 8: Check for probe requests in logs
echo -e "${YELLOW}Checking for Wi-Fi probe requests...${TEXTRESET}"
if grep -q "WLAN_FC_STYPE_PROBE_REQ" /tmp/hostapd-test.log; then
    echo -e "${GREEN}Wi-Fi probe requests detected! AP is broadcasting.${TEXTRESET}"
else
    echo -e "${RED}No probe requests detected. There may be an issue.${TEXTRESET}"
    echo -e "${YELLOW}Check logs: sudo cat /tmp/hostapd-test.log${TEXTRESET}"
    sudo pkill -9 hostapd
    exit 1
fi

# Step 9: Ask the user if they see the test SSID
echo -e "\n${YELLOW}Please check your Wi-Fi on another device.${TEXTRESET}"
echo -e "You should see an SSID named: ${GREEN}RFWB-Setup${TEXTRESET}"
read -p "Do you see 'RFWB-Setup' in your Wi-Fi networks? (yes/no): " SSID_VISIBLE

# Step 10: Full Cleanup
echo -e "${YELLOW}Stopping test SSID and cleaning up...${TEXTRESET}"
sudo pkill -9 hostapd
sudo killall -q hostapd
sudo rm -f /etc/hostapd/hostapd-test.conf /tmp/hostapd-test.log

# Ensure no lingering processes
if pgrep -x "hostapd" > /dev/null; then
    echo -e "${RED}WARNING: hostapd is still running! Forcing stop...${TEXTRESET}"
    sudo pkill -9 hostapd
fi

# Reset Wi-Fi interface back to normal
echo -e "${YELLOW}Resetting Wi-Fi interface to managed mode...${TEXTRESET}"
sudo ip link set "$WIFI_IFACE" down
sudo iw dev "$WIFI_IFACE" set type managed
sudo ip link set "$WIFI_IFACE" up
sleep 1

if [[ "$SSID_VISIBLE" =~ ^[Yy] ]]; then
    echo -e "${GREEN}Test successful! System is ready for actual AP setup.${TEXTRESET}"
else
    echo -e "${RED}Error: The test SSID was not detected. Exiting setup.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}Wi-Fi AP Testing Complete. System is clean and ready for configuration.${TEXTRESET}"

#!/bin/bash

clear
echo "=== Wi-Fi Access Point Configuration Script ==="

# Step 1: Find Wireless Interface
echo "Scanning for wireless interfaces..."
WIFI_IFACE=$(iw dev | awk '$1=="Interface"{print $2}')

if [[ -z "$WIFI_IFACE" ]]; then
    echo "No wireless interfaces found! Exiting."
    exit 1
fi

echo "Found wireless interface: $WIFI_IFACE"

# Step 2: Check Wi-Fi Capabilities
echo "Checking Wi-Fi capabilities for $WIFI_IFACE..."

VLAN_SUPPORT=$(iw list | grep -q "AP/VLAN" && echo "Supported" || echo "Not Supported")
WPA2_SUPPORT=$(iw list | grep -q "CCMP-128" && echo "Yes" || echo "No")
WPA3_SUPPORT=$(iw list | grep -q "GCMP-256" && echo "Yes" || echo "No")
MULTI_SSID_SUPPORT=$(iw list | grep -q "valid interface combinations" && echo "Supported" || echo "Not Supported")

echo "- VLAN Bridging (AP/VLAN Mode): $VLAN_SUPPORT"
echo "- WPA2 Support: $WPA2_SUPPORT"
echo "- WPA3 Support: $WPA3_SUPPORT"
echo "- Multiple SSIDs: $MULTI_SSID_SUPPORT"

# Step 3: Detect Supported Frequency Bands
echo "Detecting supported frequency bands..."

BANDS=""
if iw list | grep -q "2412.0 MHz"; then BANDS+=" 2.4GHz"; fi
if iw list | grep -q "5180.0 MHz"; then BANDS+=" 5GHz"; fi
if iw list | grep -q "5955.0 MHz"; then BANDS+=" 6GHz"; fi

if [[ -z "$BANDS" ]]; then
    echo "Error: No supported frequency bands detected!"
    exit 1
else
    echo "- Supported Bands:$BANDS"
fi

# Step 4: Scan for Channel Congestion & Pick Best Channel
echo "Scanning for channel congestion..."
declare -A CHANNEL_USAGE

IW_SCAN_OUTPUT=$(iw dev "$WIFI_IFACE" scan | grep "DS Parameter set: channel" | awk '{print $5}')

for CHANNEL in $IW_SCAN_OUTPUT; do
    ((CHANNEL_USAGE[$CHANNEL]++))
done

BEST_24GHZ=6  # Default fallback
BEST_5GHZ=36  # Default fallback

for CH in {1..11}; do
    if [[ -z "${CHANNEL_USAGE[$CH]}" ]]; then
        BEST_24GHZ=$CH
        break
    fi
done

for CH in {36,40,44,48,149,153,157,161}; do
    if [[ -z "${CHANNEL_USAGE[$CH]}" ]]; then
        BEST_5GHZ=$CH
        break
    fi
done

echo "- Recommended Channel (2.4GHz): $BEST_24GHZ"
echo "- Recommended Channel (5GHz): $BEST_5GHZ"

# Step 5: Ensure Wi-Fi Interface is in AP Mode
echo "Ensuring Wi-Fi interface is in AP mode..."

# Stop any conflicting processes
echo "Stopping conflicting processes..."
sudo pkill -9 hostapd
sudo pkill -9 wpa_supplicant

# Using the working method for AP mode
echo "Configuring $WIFI_IFACE as an Access Point..."
sudo ip link set "$WIFI_IFACE" down
sudo iw dev "$WIFI_IFACE" set type __ap
sudo ip link set "$WIFI_IFACE" up
sleep 1

# Verify the mode
MODE_CHECK=$(iw dev "$WIFI_IFACE" info | grep -o "type AP")
if [[ "$MODE_CHECK" == "type AP" ]]; then
    echo "- Interface is correctly set to AP mode."
else
    echo "Error: Interface could not be set to AP mode. Retrying..."

    # Step 6: Detect and Reload Wi-Fi Driver Dynamically
    DRIVER=$(basename $(readlink /sys/class/net/$WIFI_IFACE/device/driver))

    if [[ -n "$DRIVER" ]]; then
        echo "Reloading Wi-Fi driver: $DRIVER..."
        sudo modprobe -r "$DRIVER"
        sudo modprobe "$DRIVER"
    else
        echo "Error: Could not detect driver for $WIFI_IFACE. Exiting."
        exit 1
    fi

    # Attempt to set AP mode again
    sudo ip link set "$WIFI_IFACE" down
    sudo iw dev "$WIFI_IFACE" set type __ap
    sudo ip link set "$WIFI_IFACE" up
    sleep 1

    # Re-check if AP mode was set
    MODE_CHECK=$(iw dev "$WIFI_IFACE" info | grep -o "type AP")
    if [[ "$MODE_CHECK" == "type AP" ]]; then
        echo "- Interface successfully switched to AP mode after driver reload."
    else
        echo "Error: Interface could NOT be set to AP mode even after driver reload. Exiting."
        exit 1
    fi
fi

echo "Wi-Fi Access Point Configuration Check Completed Successfully."

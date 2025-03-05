#!/bin/bash

# Define the pattern to search for in the systemctl output
pattern="DHCPSRV_OPEN_SOCKET_FAIL failed to open socket: the interface"

# Run the systemctl status command and search for the pattern
status_output=$(systemctl status kea-dhcp4 2>&1)

# Check if the output contains the error message
if echo "$status_output" | grep -q "$pattern"; then
    # Extract the interface name from the error message
    interface=$(echo "$status_output" | grep "$pattern" | sed -n 's/.*interface \(.*\) is not running.*/\1/p')

    # Log the restart action to /var/log/messages
    logger "rfwb: kea-dhcp4 down to network interface delay from boot...Restarting kea-dhcp4 Service"

    # Restart the kea-dhcp4 service
    systemctl restart kea-dhcp4

    # Confirm the action
    echo "Restarted kea-dhcp4 service due to interface $interface not running."
else
    echo "No issues detected with kea-dhcp4 service."
fi

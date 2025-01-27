#!/bin/bash

# Define color codes for formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m' # Text Reset
echo -e "${YELLOW}Checking Hardware Requirements...${RESET}"
dnf -y install bc
# Function to check if the system has at least 8 GB of RAM
check_ram() {
    # Get the total memory in KB
    total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    # Convert the memory to GB and round up
    total_mem_gb=$(echo "$total_mem_kb / 1024 / 1024" | bc -l | awk '{print ($1 == int($1)) ? $1 : int($1) + 1}')

    # Check if the memory is at least 8 GB
    if (( total_mem_gb >= 8 )); then
        echo -e "${GREEN}RAM Check: Passed (Total RAM: ${total_mem_gb} GB)${RESET}"
        return 0
    else
        needed_ram=$((8 - total_mem_gb))
        echo -e "${RED}RAM Check: Failed (Total RAM: ${total_mem_gb} GB)${RESET}"
        echo -e "${YELLOW}Additional RAM needed: ${needed_ram} GB${RESET}"
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
        return 0
    else
        needed_cpus=$((2 - cpu_count))
        echo -e "${RED}CPU Check: Failed (Total CPUs: ${cpu_count})${RESET}"
        echo -e "${YELLOW}Additional CPUs needed: ${needed_cpus}${RESET}"
        return 1
    fi
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
    sleep 2
else
    echo -e "${RED}System does not meet the minimum requirements.${RESET}"
    [ "$ram_status" -ne 0 ] && echo -e "${YELLOW}Please add more RAM.${RESET}"
    [ "$cpu_status" -ne 0 ] && echo -e "${YELLOW}Please add more CPUs.${RESET}"
    sleep 2
    exit 1
fi

# Update the server
echo -e "${YELLOW}Updating the server...${TEXTRESET}"
if sudo dnf update -y; then
    echo -e "${GREEN}Server updated successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to update the server.${TEXTRESET}"
    exit 1
fi

# Install essential packages
echo -e "${YELLOW}Installing essential packages...${TEXTRESET}"
if sudo dnf install -y yum-utils bc nano curl wget policycoreutils-python-utils; then
    echo -e "${GREEN}Essential packages installed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to install essential packages.${TEXTRESET}"
    exit 1
fi

# Install Suricata
echo -e "${YELLOW}Installing Suricata...${TEXTRESET}"

# Enable copr command for dnf
echo -e "${YELLOW}Enabling dnf copr command...${TEXTRESET}"
if sudo dnf install -y 'dnf-command(copr)'; then
    echo -e "${GREEN}dnf copr command enabled.${TEXTRESET}"
else
    echo -e "${RED}Failed to enable dnf copr command.${TEXTRESET}"
    exit 1
fi

# Enable the OISF repository for Suricata
echo -e "${YELLOW}Enabling OISF Suricata repository...${TEXTRESET}"
if echo 'y' | sudo dnf copr enable @oisf/suricata-7.0; then
    echo -e "${GREEN}OISF Suricata repository enabled.${TEXTRESET}"
else
    echo -e "${RED}Failed to enable OISF Suricata repository.${TEXTRESET}"
    exit 1
fi

# Add the EPEL repository
echo -e "${YELLOW}Adding EPEL repository...${TEXTRESET}"
if sudo dnf install -y epel-release dnf-plugins-core; then
    echo -e "${GREEN}EPEL repository added successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to add EPEL repository.${TEXTRESET}"
    exit 1
fi

# Install Suricata
echo -e "${YELLOW}Installing Suricata package...${TEXTRESET}"
if sudo dnf install -y suricata; then
    echo -e "${GREEN}Suricata installed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to install Suricata.${TEXTRESET}"
    exit 1
fi

# Enable Suricata service
echo -e "${YELLOW}Enabling Suricata service...${TEXTRESET}"
if sudo systemctl enable suricata; then
    echo -e "${GREEN}Suricata service enabled.${TEXTRESET}"
else
    echo -e "${RED}Failed to enable Suricata service.${TEXTRESET}"
    exit 1
fi

# Configure Suricata
echo -e "${YELLOW}Configuring Suricata...${TEXTRESET}"

# Backup the original Suricata configuration file
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

# Enable Community ID in suricata.yaml
echo -e "${YELLOW}Enabling Community ID feature in Suricata...${TEXTRESET}"
sudo sed -i 's/# \(community-id:\) false/\1 true/' /etc/suricata/suricata.yaml

# Detect the inside network interface using nmcli and awk
INSIDE_INTERFACE=$(nmcli connection show --active | awk '/-inside/ {print $4}')

if [ -z "$INSIDE_INTERFACE" ]; then
    echo -e "${RED}No inside interface found. Please ensure your interface names follow the expected pattern.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}Detected inside interface: $INSIDE_INTERFACE${TEXTRESET}"

# Update the pcap interface in suricata.yaml
echo -e "${YELLOW}Updating pcap interface to use $INSIDE_INTERFACE...${TEXTRESET}"
sudo sed -i "/# Cross platform libpcap capture support/,/interface:/ s/interface: eth0/interface: $INSIDE_INTERFACE/" /etc/suricata/suricata.yaml

# Update the af-packet interface in suricata.yaml
echo -e "${YELLOW}Updating af-packet interface to use $INSIDE_INTERFACE...${TEXTRESET}"
sudo sed -i "/# Linux high speed capture support/,/af-packet:/ {n; s/interface: eth0/interface: $INSIDE_INTERFACE/}" /etc/suricata/suricata.yaml

# Update the inside interface in /etc/sysconfig/suricata
echo -e "${YELLOW}Updating inside interface in /etc/sysconfig/suricata...${TEXTRESET}"
sudo sed -i "s/eth0/$INSIDE_INTERFACE/g" /etc/sysconfig/suricata

# Configure directory permissions for Suricata
echo -e "${YELLOW}Configuring directory permissions for Suricata...${TEXTRESET}"
sudo chgrp -R suricata /etc/suricata
sudo chgrp -R suricata /var/lib/suricata
sudo chgrp -R suricata /var/log/suricata
sudo chmod -R g+r /etc/suricata/
sudo chmod -R g+rw /var/lib/suricata
sudo chmod -R g+rw /var/log/suricata

# Add current user to the suricata group
echo -e "${YELLOW}Adding current user to the suricata group...${TEXTRESET}"
sudo usermod -a -G suricata $USER

# Validate that the user was added to the suricata group
echo -e "${YELLOW}Validating user group membership...${TEXTRESET}"
if id -nG "$USER" | grep -qw "suricata"; then
    echo -e "${GREEN}User $USER is successfully added to the suricata group.${TEXTRESET}"
else
    echo -e "${RED}Failed to add user $USER to the suricata group.${TEXTRESET}"
    exit 1
fi

# Run suricata-update
echo -e "${YELLOW}Running suricata-update...${TEXTRESET}"
if sudo suricata-update; then
    echo -e "${GREEN}suricata-update completed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to run suricata-update.${TEXTRESET}"
    exit 1
fi

# Loop to allow adding additional rule sources
while true; do
    echo -e "${YELLOW}Do you want to add additional rule sources? (y/n)${TEXTRESET}"
    read -p "Your choice: " add_rules

    if [[ "$add_rules" == "y" || "$add_rules" == "Y" ]]; then
        echo -e "${YELLOW}Listing available rule sources...${TEXTRESET}"
        sudo suricata-update list-sources

        echo -e "${YELLOW}Please enter the source names you want to add, separated by spaces:${TEXTRESET}"
        read -r rule_sources

        for source in $rule_sources; do
            echo -e "${YELLOW}Adding source $source...${TEXTRESET}"
            sudo suricata-update enable-source "$source"
        done

    else
        break
    fi
done

# Run suricata-update after the loop
echo -e "${YELLOW}Running suricata-update...${TEXTRESET}"
if sudo suricata-update; then
    echo -e "${GREEN}suricata-update completed successfully.${TEXTRESET}"
else
    echo -e "${RED}Failed to run suricata-update.${TEXTRESET}"
fi

echo -e "${GREEN}Suricata has been configured with the inside interface $INSIDE_INTERFACE and proper permissions.${TEXTRESET}"
# Inform the user that the configuration validation is starting
echo -e "${YELLOW}Validating Suricata configuration...${TEXTRESET}"

# Define the command to run Suricata with the test configuration
COMMAND="suricata -T -c /etc/suricata/suricata.yaml -v"

# Execute the command and capture the output
OUTPUT=$($COMMAND 2>&1)

# Define the success message to look for
SUCCESS_MESSAGE="Notice: suricata: Configuration provided was successfully loaded. Exiting."

# Check if the output contains the success message
if echo "$OUTPUT" | grep -q "$SUCCESS_MESSAGE"; then
    echo -e "${GREEN}Success: Suricata configuration was loaded successfully.${TEXTRESET}"

else
    echo -e "${RED}Error: Suricata configuration test failed.${TEXTRESET}"
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi
# Start the Suricata service
echo -e "${YELLOW}Starting Suricata service...${TEXTRESET}"
sudo systemctl start suricata

# Show the status of the Suricata service
echo -e "${YELLOW}Checking Suricata service status...${TEXTRESET}"
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
    if echo "$status_output" | grep -qE "E: logopenfile: Error opening file: \"/var/log/suricata/fast.log\": Permission denied|W: runmodes: output module \"fast\": s
etup failed|E: logopenfile: Error opening file: \"/var/log/suricata/eve.json\": Permission denied|W: runmodes: output module \"eve-log\": setup failed|E: logopenfile
: Error opening file: \"/var/log/suricata/stats.log\": Permission denied|W: runmodes: output module \"stats\": setup failed"; then
        # Display the specific lines indicating permission errors
        echo -e "${RED}Detected permission issues in the following log entries:${TEXTRESET}"
        echo "$status_output" | grep -E "E: logopenfile: Error opening file: \"/var/log/suricata/fast.log\": Permission denied|W: runmodes: output module \"fast\": s
etup failed|E: logopenfile: Error opening file: \"/var/log/suricata/eve.json\": Permission denied|W: runmodes: output module \"eve-log\": setup failed|E: logopenfile
: Error opening file: \"/var/log/suricata/stats.log\": Permission denied|W: runmodes: output module \"stats\": setup failed"
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
        echo -e "\n${GREEN}Suricata service is running without permission issues.${TEXTRESET}"
        # Proceed without exiting to continue the script
        break
    else
        echo -e "\n${RED}Warning: There are permission issues with Suricata log files.${TEXTRESET}"
        echo -e "${YELLOW}Attempting to fix permissions (Attempt $((attempts + 1)) of $max_attempts)...${TEXTRESET}"
        sudo chown -R suricata:suricata /var/log/suricata
        echo -e "${YELLOW}Permissions have been reset. Restarting Suricata service...${TEXTRESET}"
        sudo systemctl restart suricata
        sleep 10
        # Check again after attempting to fix permissions
        echo -e "${YELLOW}Re-checking Suricata service status...${TEXTRESET}"
        check_and_fix_permissions
        if [ $? -eq 0 ]; then
            echo -e "\n${GREEN}Permissions successfully fixed. Suricata service is running without issues.${TEXTRESET}"
            break
        else
            echo -e "\n${RED}Permission issues still exist after attempting to fix them.${TEXTRESET}"
        fi
    fi
    attempts=$((attempts + 1))
done

if [ $attempts -eq $max_attempts ]; then
    echo -e "\n${RED}Failed to resolve permission issues after $max_attempts attempts. Please check the system configuration manually.${TEXTRESET}"
    exit 1
fi


# Inform the user about the test
echo -e "${YELLOW}Testing Suricata rule...${TEXTRESET}"
echo -e "${YELLOW}Waiting for the engine to start...${TEXTRESET}"
# Total duration for the progress bar
duration=15

# Total number of steps in the progress bar
steps=30

# Calculate the sleep duration between each step
sleep_duration=$(echo "$duration/$steps" | bc -l)

# Initialize the progress bar
progress=""

echo -e "Progress:"

# Loop to update the progress bar
for ((i=0; i<=steps; i++)); do
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
echo -e "\nDone!"
# Run the curl command and capture the response
response=$(curl -s http://testmynids.org/uid/index.html)


# Run the curl command and capture the response
response=$(curl -s http://testmynids.org/uid/index.html)
# Validate the response
expected_response="uid=0(root) gid=0(root) groups=0(root)"
if [ "$response" == "$expected_response" ]; then
    echo -e "${GREEN}Curl command was successful. Expected response received:${TEXTRESET}"
    echo -e "${GREEN}$response${TEXTRESET}"
    sleep 5
    # Capture the last line of the fast.log containing the specified ID
    last_log_line=$(grep 2100498 /var/log/suricata/fast.log | tail -n 1)
    echo -e "${YELLOW}Last log line with ID 2100498: ${last_log_line}${TEXTRESET}"  # Debug: Print the last line for verification

    # Check the log line for the classification
    if echo "$last_log_line" | grep -q "\[Classification: Potentially Bad Traffic\]"; then
        echo -e "${GREEN}Suricata rule was successful. The classification '[Classification: Potentially Bad Traffic]' was found in the log entry with ID 2100498.${TEXTRESET}"
    else
        echo -e "${RED}Suricata rule failed. The expected classification was not found in the log entry with ID 2100498.${TEXTRESET}"
        exit 1
    fi
else
    echo -e "${RED}Curl command failed. The expected response was not received.${TEXTRESET}"
    exit 1
fi

echo -e "${GREEN}Script completed successfully.${TEXTRESET}"

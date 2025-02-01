#!/bin/bash
# Define color codes for formatting output
RESET="\033[0m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
USER=$(whoami)
INTERFACE=$(nmcli | grep "connected to" | cut -d " " -f4)
DETECTIP=$(nmcli -f ipv4.method con show $INTERFACE)
NMCLIIP=$(nmcli | grep inet4 | sed '$d'| cut -c7- |cut -d / -f1)
FQDN=$(hostname)
# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "${GREEN}Running as root user.${RESET}"
else
  echo -e "${RED}This program must be run as root.${RESET}"
  echo "Exiting..."
  exit 1
fi

# Extract the major OS version from /etc/redhat-release
if [ -f /etc/redhat-release ]; then
  MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
else
  echo -e "${RED}/etc/redhat-release file not found. Cannot determine OS version.${RESET}"
  echo "Exiting the installer..."
  exit 1
fi

# Checking for version information
if [ "$MAJOROS" -ge 9 ]; then
  echo -e "${GREEN}Detected compatible OS version: Rocky 9.x or greater${RESET}"
else
  echo -e "${RED}Sorry, but this installer only works on Rocky 9.X or greater${RESET}"
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${RESET} or later"
  echo "Exiting the installer..."
  exit 1
fi
#Detect Static or DHCP (IF not Static, change it)
cat <<EOF
Checking for static IP Address
EOF
sleep 1s

if [ -z "$INTERFACE" ]; then
  "Usage: $0 <interface>"
  exit 1
fi
# Function to validate IP address in CIDR notation
validate_cidr() {
  local cidr=$1
  local n="(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
  local m="(3[0-2]|[1-2]?[0-9])"
  [[ $cidr =~ ^$n(\.$n){3}/$m$ ]]
}

# Function to validate an IP address in dotted notation
validate_ip() {
  local ip=$1
  local n="(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
  [[ $ip =~ ^$n(\.$n){3}$ ]]
}

# Function to validate FQDN
validate_fqdn() {
  local fqdn=$1
  [[ $fqdn =~ ^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}
clear
if [ "$DETECTIP" = "ipv4.method:                            auto" ]; then
  while true; do
    echo -e "${RED}Interface $INTERFACE is using DHCP${TEXTRESET}"

    # Validate IPADDR
    read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
    while ! validate_cidr "$IPADDR"; do
      echo -e "${RED}The entry is not in valid CIDR notation. Please Try again${TEXTRESET}"
      read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
    done

    # Validate GW
    read -p "Please provide a Default Gateway Address: " GW
    while ! validate_ip "$GW"; do
      echo -e "${RED}The entry is not a valid IP address. Please Try again${TEXTRESET}"
      read -p "Please provide a Default Gateway Address: " GW
    done

    # Validate HOSTNAME
    validate_fqdn() {
  local fqdn="$1"

  # Check if the FQDN is valid using a regular expression
  if [[ "$fqdn" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; then
    return 0
  else
    return 1
  fi
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"

  # Check if the hostname is not the same as any part of the domain
  if [[ "$domain" =~ (^|\.)"$hostname"(\.|$) ]]; then
    return 1
  else
    return 0
  fi
}

read -p "Please provide the FQDN for this machine: " HOSTNAME

while ! validate_fqdn "$HOSTNAME" || ! check_hostname_in_domain "$HOSTNAME"; do
  echo -e "${RED}The entry is not a valid FQDN, or the hostname is repeated in the domain name (This is not Supported). Please Try again${TEXTRESET}"
  read -p "Please provide the FQDN for this machine: " HOSTNAME
done


    # Validate DNSSERVER
    read -p "Please provide an upstream DNS IP for resolution: " DNSSERVER
    while ! validate_ip "$DNSSERVER"; do
      echo -e "${RED}The entry is not a valid IP address. Please Try again${TEXTRESET}"
      read -p "Please provide an upstream DNS IP for resolution: " DNSSERVER
    done

    # Validate DNSSEARCH
    read -p "Please provide the domain search name: " DNSSEARCH
    while [ -z "$DNSSEARCH" ]; do
      echo -e "${RED}The response cannot be blank. Please Try again${TEXTRESET}"
      read -p "Please provide the domain search name: " DNSSEARCH
    done

    clear

echo -e "The following changes to the system will be configured:"
echo -e "IP address: ${GREEN}$IPADDR${TEXTRESET}"
echo -e "Gateway: ${GREEN}$GW${TEXTRESET}"
echo -e "DNS Search: ${GREEN}$DNSSEARCH${TEXTRESET}"
echo -e "DNS Server: ${GREEN}$DNSSERVER${TEXTRESET}"
echo -e "HOSTNAME: ${GREEN}$HOSTNAME${TEXTRESET}"



    # Ask the user to confirm the changes
    read -p "Are these settings correct? (y/n): " CONFIRM
    if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
      nmcli con mod $INTERFACE ipv4.address $IPADDR
      nmcli con mod $INTERFACE ipv4.gateway $GW
      nmcli con mod $INTERFACE ipv4.method manual
      nmcli con mod $INTERFACE ipv4.dns-search $DNSSEARCH
      nmcli con mod $INTERFACE ipv4.dns $DNSSERVER
      hostnamectl set-hostname $HOSTNAME
      echo -e "/root/RFWB/rfwb_install.sh" >>/root/.bash_profile
      echo -e "The System must reboot for the changes to take effect."
      echo -e "${RED}Please log back in as root.${TEXTRESET}"
      echo -e "The installer will continue when you log back in."
      echo -e "If using SSH, please use the IP Address: $IPADDR"
      echo -e "${RED}Rebooting${TEXTRESET}"
      sleep 2
      reboot
      break
    else
      echo -e "${RED}Reconfiguring Interface${TEXTRESET}"
      sleep 2
      clear
    fi
  done
else
  echo -e "${GREEN}Interface $INTERFACE is using a static IP address${TEXTRESET}"
  sleep 2
fi
clear
if [ "$FQDN" = "localhost.localdomain" ]; then

echo -e "${RED}This system is still using the default hostname (localhost.localdomain)${TEXTRESET}"

  # Validate HOSTNAME
    validate_fqdn() {
  local fqdn="$1"

  # Check if the FQDN is valid using a regular expression
  if [[ "$fqdn" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; then
    return 0
  else
    return 1
  fi
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"

  # Check if the hostname is not the same as any part of the domain
  if [[ "$domain" =~ (^|\.)"$hostname"(\.|$) ]]; then
    return 1
  else
    return 0
  fi
}

read -p "Please provide the FQDN for this machine: " HOSTNAME

while ! validate_fqdn "$HOSTNAME" || ! check_hostname_in_domain "$HOSTNAME"; do
  echo -e "${RED}The entry is not a valid FQDN, or the hostname is repeated in the domain name (This is not Supported). Please Try again${TEXTRESET}"
  read -p "Please provide the FQDN for this machine: " HOSTNAME
done

  hostnamectl set-hostname $HOSTNAME

echo -e "The System must reboot for the changes to take effect."
echo -e "${RED}Please log back in as root.${TEXTRESET}"
echo -e "The installer will continue when you log back in."
echo -e "If using SSH, please use the IP Address: ${NMCLIIP}"

  read -p "Press Enter to Continue"
  clear
  echo "/root/RFWB/rfwb_install.sh" >>/root/.bash_profile
  reboot
  exit

fi
clear
clear
echo -e "${GREEN}
                               .*((((((((((((((((*
                         .(((((((((((((((((((((((((((/
                      ,((((((((((((((((((((((((((((((((((.
                    (((((((((((((((((((((((((((((((((((((((/
                  (((((((((((((((((((((((((((((((((((((((((((/
                .((((((((((((((((((((((((((((((((((((((((((((((
               ,((((((((((((((((((((((((((((((((((((((((((((((((.
               ((((((((((((((((((((((((((((((/   ,(((((((((((((((
              /((((((((((((((((((((((((((((.        /((((((((((((*
              ((((((((((((((((((((((((((/              (((((((((((
              ((((((((((((((((((((((((                   *(((((((/
              /((((((((((((((((((((*                        (((((*
               ((((((((((((((((((             (((*            ,((
               .((((((((((((((.            /((((((((
                 ((((((((((/             (((((((((((((/
                  *((((((.            /((((((((((((((((((.
                    *(*            ,(((((((((((((((((((((((,
                                 (((((((((((((((((((((((/
                              /((((((((((((((((((((((.
                                ,((((((((((((((,
${RESET}"
echo -e ${GREEN}Rocky Linux${RESET} ${RED}Firewall${RESET} ${YELLOW}Builder${RESET}

# Use echo to interpret colors correctly
echo -e "
This script can be used to create a SOHO firewall implementation on Rocky Linux with IPS/IDS and other network processes:
-BIND
-ISC-KEA (DHCP)
-Webmin
-Cockpit
-ntopng
-DDNS for DDNS registration
-Suricata (stand alone)
-Suricata with Elastic/Kibana/Filebeat for Dashboard analytics of Alerts and Events (2CPU 8GB of RAM)

The process of this program is the following:
#1-Make sure you have ${YELLOW}two HARDWARE/VIRTUAL interfaces${RESET} on your system that are detected by nmcli
#2-The ${YELLOW}FIRST, connected interface${RESET} will be designated as your inside interface (This interface you are probably SSH'd into)
Your Internet facing interface ${YELLOW}SHOULD BE UNPLUGGED${RESET} right now

We prep the inside interface then proceed to install the applications of your choice
All downloads and configuration will happen through the inside interface
After your applications have been installed and configured to listen on the inside interface, we will then configure the outside interface
This is when you will plug the outside (internet facing) interface into the external connection, Cable modem, etc that you want to use.
We will configure that outside interface and harden all communications on that outside interface.
After that, the system will prompt you to reboot and you will be ready to go!
"

read -p "Press Enter to start the installer"
clear
#Check for Network Connectivity
echo "Checking for Internet Connectivity"
echo " "
sleep 3
# Function to check DNS resolution
check_dns_resolution() {
    local domain=$1
    ping -c 1 $domain &> /dev/null
    return $?
}

# Function to ping an address
ping_address() {
    local address=$1
    ping -c 1 $address &> /dev/null
    return $?
}

# Flag to track if any test fails
test_failed=false

# Check DNS resolution for google.com
echo "Checking DNS resolution for google.com via ping..."
if check_dns_resolution "google.com"; then
    echo "DNS resolution for google.com is successful."
else
    echo "DNS resolution for google.com failed."
    test_failed=true
fi

# Ping 8.8.8.8
echo "Trying to ping 8.8.8.8..."
if ping_address "8.8.8.8"; then
    echo "Successfully reached 8.8.8.8."
else
    echo "Cannot reach 8.8.8.8."
    test_failed=true
fi

# Provide final results summary
echo
echo "===== TEST RESULTS ====="
echo -e "DNS Resolution for google.com: $(if check_dns_resolution "google.com"; then echo "${GREEN}Passed"${TEXTRESET}; else echo -e "${RED}Failed"${TEXTRESET}; fi)"
echo -e "Ping to 8.8.8.8: $(if ping_address "8.8.8.8"; then echo "${GREEN}Passed"${TEXTRESET}; else echo -e "${RED}Failed"${TEXTRESET}; fi)"
echo "========================"
echo

# Prompt the user only if any test fails
if $test_failed; then
    read -p "One or more tests failed. Do you want to continue the script? (y/n): " user_input
    if [[ $user_input == "y" || $user_input == "Y" ]]; then
        echo "Continuing the script with failures"
        sleep 1
        # Place additional script logic here
    else
        echo "Please make sure that you have full Connectivty to the Internet Before Proceeding."
        exit 1
    fi
else
    echo "All tests passed successfully."
    sleep 3
    # Continue with the script or exit as needed
fi

echo -e ${GREEN}"Updating system${TEXTRESET}"
sleep 2
dnf -y update
dnf -y install net-tools dmidecode ipcalc bind-utils
echo -e ${GREEN}"Installing Speedtest${TEXTRESET}"
echo -e ${YELLOW}"The Installer will answer all questions for you ${RED}DO NOT type YES${TEXTRESET}"
#!/usr/bin/env bash

# Check if expect is installed
if ! command -v expect &> /dev/null; then
    echo -e ${YELLOW}"Expect is not installed. Installing now...${TEXTRESET}"
    dnf -y install expect
fi

# Run the package installation script and install speedtest
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh | sudo bash
dnf -y install speedtest

# Create an expect script to automate the interaction with speedtest
/usr/bin/expect <<EOF
    spawn speedtest
    expect "Do you accept the license? \\[type YES to accept\\]:"
    send "YES\r"
    expect eof
EOF
#!/bin/bash
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)

echo -e ${GREEN}"Checking for Virtualtization Platform${TEXTRESET}"
#Checking for VM platform-Install client
echo ${GREEN}"Installing VMGuest${TEXTRESET}"
if [ "$HWKVM" = "KVM" ]; then
  echo -e ${GREEN}"KVM Platform detected ${TEXTRESET}"
  echo "Installing qemu-guest-agent"
  sleep 1
  dnf -y install qemu-guest-agent
else
  echo "Not KVM Platform"
fi

#Checking for VM platform-Install client
if [ "$HWVMWARE" = "VMware" ]; then
  echo -e ${GREEN}"VMWARE Platform detected ${TEXTRESET}"
  echo "Installing open-vm-tools"
  sleep 1
  dnf -y install open-vm-tools
else
  echo "Not VMware Platform"
fi
clear
#Configure the ZONE for the inside interface
# Ensure necessary commands are installed
if ! command -v nmcli &> /dev/null; then
  echo -e "${RED}nmcli is not installed. Please install it and try again.${TEXTRESET}"
  exit 1
fi

if ! systemctl is-active --quiet firewalld; then
  echo -e "${RED}firewalld is not running. Please start it and try again.${TEXTRESET}"
  exit 1
fi

# Get all active connections managed by NetworkManager
active_connection=$(nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active | grep ":802-3-ethernet:" | grep ":activated")

if [ -z "$active_connection" ]; then
  echo -e "${RED}No active ethernet connections found. Exiting...${TEXTRESET}"
  exit 1
fi

# Parse the active connection details
IFS=: read -r name device type state <<< "$active_connection"

echo -e "${GREEN}Active internal network connection found:${TEXTRESET} $device ($name)"

# Update the connection profile name to include '-inside'
new_profile_name="${name}-inside"
echo -e "${YELLOW}Updating connection profile name to: $new_profile_name${TEXTRESET}"
nmcli connection modify "$name" connection.id "$new_profile_name"
nmcli connection reload

# Display initial ASCII representation of the connection
echo -e "${GREEN}Initial Connection Diagram:${TEXTRESET}"
echo "  +-------------------+"
echo "  |  Internal Network |"
echo "  +-------------------+"
echo "           |"
echo "           |"
echo "       +--------+"
echo "       | $device |"
echo "       +--------+"
echo "           |"
echo "           |"
echo "       +---------+"
echo "       | Firewall |"
echo "       +---------+"
echo



# Ask user if they want to set this connection to the 'Internal' zone
echo -e "It's HIGHLY suggested this interface be in the Firewall zone \"internal\""
read -p "Do you want to set this connection to the 'Internal' zone in firewalld? (y/n): " user_confirm

selected_zone=""

if [[ "$user_confirm" == "y" ]]; then
  selected_zone="internal"
  echo -e "${GREEN}Setting $device to the 'internal' zone...${TEXTRESET}"
  firewall-cmd --zone=internal --change-interface="$device" --permanent
else
  echo -e "${YELLOW}Available firewalld zones:${TEXTRESET}"
  available_zones=$(firewall-cmd --get-zones)

  # List available zones
  for zone in $available_zones; do
    echo -e "${YELLOW}- $zone${TEXTRESET}"
  done

  # Ask user to choose a different zone
  read -p "Please enter the zone you would like to use for $device: " selected_zone

  # Apply the chosen zone
  if echo "$available_zones" | grep -qw "$selected_zone"; then
    echo -e "${GREEN}Setting $device to the '$selected_zone' zone...${TEXTRESET}"
    firewall-cmd --zone="$selected_zone" --change-interface="$device" --permanent
  else
    echo -e "${RED}Invalid zone selected. No changes were made.${TEXTRESET}"
    exit 1
  fi
fi

firewall-cmd --reload
systemctl restart NetworkManager

# Display current zone configuration for the interface
echo -e "${YELLOW}Current firewalld zone configuration for $device:${TEXTRESET}"
firewall-cmd --get-active-zones | grep -A1 "$device"

echo -e "${GREEN}Completed configuration of network zones.${TEXTRESET}"

# Display the updated ASCII representation of the connection with the zone applied
echo -e "${GREEN}Updated Connection Diagram with Zone Applied:${TEXTRESET}"
echo "  +-------------------+"
echo "  |  Internal Network |"
echo "  +-------------------+"
echo "           |"
echo "           |"
echo "   +-----------------+"
echo "   | $selected_zone Zone |"
echo "   +-----------------+"
echo "           |"
echo "           |"
echo "       +--------+"
echo "       | $device |"
echo "       +--------+"
echo "           |"
echo "           |"
echo "       +---------+"
echo "       | Firewall |"
echo "       +---------+"
echo
echo -e "${GREEN}The Inside interface has been configured.${TEXTRESET}"

cat <<EOF
Your inside interface can still be set to DHCP or if you have alrady statically assigend the interface, that's OK.
We will come back later and setup vlans, and routing if needed. For now we will use the inside interface to deploy applications
and update the system.
EOF

read -p "Press Enter to install applications and services"
/root/RFWB/pkg_install_gui.sh

echo -e "Continue script"

#!/bin/bash
# Define color codes for formatting output

RESET="\033[0m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
USER=$(whoami)
INTERFACE=$(nmcli | grep "connected to" | cut -d " " -f4)
DETECTIP=$(nmcli -f ipv4.method con show $INTERFACE)
NMCLIIP=$(nmcli | grep inet4 | sed '$d' | cut -c7- | cut -d / -f1)
FQDN=$(hostname)
clear
# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user."
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Exiting..."
  exit 1
fi

# Extract the major OS version from /etc/redhat-release
if [ -f /etc/redhat-release ]; then
  MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
else
  echo -e "[${RED}ERROR${TEXTRESET}] /etc/redhat-release file not found. Cannot determine OS version."
  echo "Exiting the installer..."
  exit 1
fi

# Checking for version information
if [ "$MAJOROS" -ge 9 ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected compatible OS version: Rocky 9.x or greater"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Sorry, but this installer only works on Rocky 9.X or greater"
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET} or later"
  echo "Exiting the installer..."
  exit 1
fi

#Detect Static or DHCP (IF not Static, change it)
clear
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
if [ "$DETECTIP" = "ipv4.method:                            auto" ]; then
  while true; do
    echo -e "[${RED}ERROR${TEXTRESET}] Interface $INTERFACE is using DHCP"

    # Validate IPADDR
    read -p "Please provide a static IP address for the ${YELLOW}INSIDE INTERFACE${TEXTRESET} in CIDR format (i.e 192.168.24.2/24): " IPADDR
    while ! validate_cidr "$IPADDR"; do
      echo -e "[${RED}ERROR${TEXTRESET}] The entry is not in valid CIDR notation. Please Try again"
      read -p "Please provide a static IP address in CIDR format (i.e 192.168.24.2/24): " IPADDR
    done

    # Validate GW
    read -p "Please provide a Default Gateway Address: " GW
    while ! validate_ip "$GW"; do
      echo -e "[${RED}ERROR${TEXTRESET}] The entry is not a valid IP address. Please Try again"
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
      echo -e "[${RED}ERROR${TEXTRESET}] The entry is not a valid FQDN, or the hostname is repeated in the domain name (This is not Supported). Please Try again${TEXTRESET}"
      read -p "Please provide the FQDN for this machine: " HOSTNAME
    done

    # Validate DNSSERVER
    read -p "Please provide an upstream DNS IP for resolution: " DNSSERVER
    while ! validate_ip "$DNSSERVER"; do
      echo -e "[${RED}ERROR${TEXTRESET}] The entry is not a valid IP address. Please Try again"
      read -p "Please provide an upstream DNS IP for resolution: " DNSSERVER
    done

    # Validate DNSSEARCH
    read -p "Please provide the domain search name: " DNSSEARCH
    while [ -z "$DNSSEARCH" ]; do
      echo -e "[${RED}ERROR${TEXTRESET}] The Response cannot be blank. Please Try again"
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
      echo -e "${RED}Rebooting...${TEXTRESET}"
      sleep 4
      reboot
      break
    else
      echo -e "${RED}Reconfiguring Interface${TEXTRESET}"
      sleep 2
      clear
    fi
  done
else
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] INSIDE Interface ${GREEN}$INTERFACE${TEXTRESET} is using a static IP address"
  sleep 2
fi
clear
if [ "$FQDN" = "localhost.localdomain" ]; then

  echo -e "[${RED}ERROR${TEXTRESET}]This system is still using the default hostname (localhost.localdomain)"

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
    echo -e "[${RED}ERROR${TEXTRESET}] The entry is not a valid FQDN, or the hostname is repeated in the domain name (This is not Supported). Please Try again"
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
This script can be used to create a SOHO firewall implementation on Rocky Linux with IPS/IDS and other network applications

#1-Make sure you have ${YELLOW}two HARDWARE/VIRTUAL interfaces${RESET} on your system that are detected by nmcli
#2-The ${YELLOW}FIRST, connected interface${RESET} will be designated as your inside interface (This interface you are probably SSH'd into right now)
It's imperative all other interfaces be ${YELLOW}UNPLUGGED${RESET} (We will configure it later)
"

read -p "Press Enter to start the installer"
clear

##Detect interfaces
# Function to print a separator line
print_separator() {
  echo -e "${YELLOW}----------------------------------------${RESET}"
}

# Function to display the result with styling and color
display_result() {
  local message="$1"
  local color="$2"
  echo
  print_separator
  echo -e "${color}${message}${RESET}"
  print_separator
  echo
}

# Get the list of network interfaces excluding the loopback interface (lo)
interfaces=$(ip link show | awk -F: '$0 !~ "lo|vir|br|^[^0-9]"{print $2;getline}')

# Count the number of interfaces
interface_count=$(echo "$interfaces" | wc -l)

# Check if there are at least two interfaces
if [ "$interface_count" -ge 2 ]; then
  display_result "The device has at least two network interfaces:" "$GREEN"
  sleep 2
  echo "$interfaces" | sed 's/^/  - /' # Indent each interface for better readability
else
  display_result "The server has less than two active network interfaces." "$RED"
  echo -e "${RED}Please make sure we can see at least two interfaces on this system.${RESET}"
  exit 1
fi
sleep 2

#Check for Network Connectivity
clear
echo "Checking for Internet Connectivity"
echo " "
sleep 3
# Function to check DNS resolution
check_dns_resolution() {
  local domain=$1
  ping -c 1 $domain &>/dev/null
  return $?
}

# Function to ping an address
ping_address() {
  local address=$1
  ping -c 1 $address &>/dev/null
  return $?
}

# Flag to track if any test fails
test_failed=false

# Check DNS resolution for google.com
echo "Checking DNS resolution for google.com via ping..."
if check_dns_resolution "google.com"; then
  echo "[${GREEN}SUCCESS${TEXTRESET}] DNS resolution for google.com is successful."
else
  echo "[${RED}ERROR${TEXTRESET}] DNS resolution for google.com failed."
  test_failed=true
fi

# Ping 8.8.8.8
echo "Trying to ping 8.8.8.8..."
if ping_address "8.8.8.8"; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] reached 8.8.8.8."
else
  echo -e "[${RED}ERROR${TEXTRESET}] Cannot reach 8.8.8.8."
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
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] All tests passed successfully."
  sleep 3
fi
clear
#Check SElinux
check_and_enable_selinux() {
  # Check current SELinux status
  current_status=$(getenforce)

  if [ "$current_status" == "Enforcing" ]; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] SELinux is already enabled and enforcing."
  else
    echo -e "[${RED}ERROR${TEXTRESET}] SELinux is not enabled. Enabling SELinux..."

    # Modify SELinux configuration to enable it
    sudo sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config

    # Set SELinux to enforcing mode temporarily
    sudo setenforce 1

    # Verify and provide feedback
    if [ "$(getenforce)" == "Enforcing" ]; then
      echo -e "[${GREEN}SUCCESS${TEXTRESET}] SELinux has been successfully enabled and is now enforcing."
    else
      echo -e "[${RED}ERROR${TEXTRESET}] Failed to enable SELinux. Please check the configuration."
      exit 1
    fi
  fi
}

# Execute the function
check_and_enable_selinux
sleep 3
clear
echo -e ${GREEN}"Updating system${TEXTRESET}"
sleep 2
echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling epel-release..."
dnf install -y epel-release dnf-plugins-core >/dev/null 2>&1 &
echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling Code-Ready..."
dnf -y config-manager --set-enabled crb >/dev/null 2>&1 &
echo -e "[${YELLOW}INFO${TEXTRESET}] Installing Updates..."
sleep 1
#Install Core Updates
# Define a temporary file for package names
TEMP_FILE=$(mktemp)

# Step 1: Get the list of packages that need updates and extract package names
dnf check-update | awk '{print $1}' | grep -vE '^$|Obsoleting|Last' | awk -F'.' '{print $1}' | sort -u > "$TEMP_FILE"

# Read the total number of packages
PACKAGE_LIST=($(cat "$TEMP_FILE"))  # Store packages in an array
TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

# Check if there are updates available
if [[ "$TOTAL_PACKAGES" -eq 0 ]]; then
    dialog --msgbox "No updates available!" 10 40
    rm -f "$TEMP_FILE"
    exit 0
fi

# Create a named pipe (FIFO) for real-time updates
PIPE=$(mktemp -u)
mkfifo "$PIPE"

# Start the progress bar in the background
dialog --title "System Update" --gauge "Preparing to install updates..." 10 70 0 < "$PIPE" &
exec 3>"$PIPE"

# Function to update the progress bar
update_progress() {
    local current=$1
    local package_name=$2
    local percent=$(( (current * 100) / TOTAL_PACKAGES ))

    # Format output correctly so both progress and package name appear
    echo "$percent"
    echo "XXX"
    echo "Updating: $package_name"
    echo "XXX"
}

# Step 2: Install each package with progress display
COUNT=0
for PACKAGE in "${PACKAGE_LIST[@]}"; do
    ((COUNT++))

    # Update progress bar with package name and percentage
    update_progress "$COUNT" "$PACKAGE" >&3

    # Install package (live updates)
    dnf -y install "$PACKAGE" >/dev/null 2>&1
done

# Close the pipe
exec 3>&-
rm -f "$PIPE" "$TEMP_FILE"

# Show completion message
dialog --infobox "System update completed successfully!" 10 50
sleep 3
clear
#Install the packages we need 
# Define list of packages to install
PACKAGE_LIST=("ntsysv" "iptraf" "fail2ban" "tuned" "net-tools" "dmidecode" "ipcalc" "bind-utils" "expect" "fail2ban" "jq" "bc" "iproute-tc" "iw" "hostapd" "iotop" "zip" "yum-utils" "bc" "nano" "curl" "wget" "policycoreutils-python-utils" "dnf-automatic")  # Add or modify packages as needed
TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

# Create a named pipe (FIFO) for real-time updates
PIPE=$(mktemp -u)
mkfifo "$PIPE"

# Start the progress bar in the background
dialog --title "System Update-Ancillary Package Install" --gauge "Preparing to install packages..." 10 70 0 < "$PIPE" &
exec 3>"$PIPE"

# Function to update the progress bar with package name
update_progress() {
    local current=$1
    local package_name=$2
    local percent=$(( (current * 100) / TOTAL_PACKAGES ))

    # Format output correctly so both progress and package name appear
    echo "$percent"
    echo "XXX"
    echo "Installing: $package_name"
    echo "XXX"
}

# Begin package installation
COUNT=0
for PACKAGE in "${PACKAGE_LIST[@]}"; do
    ((COUNT++))

    # Update progress bar with package name and percentage
    update_progress "$COUNT" "$PACKAGE" >&3

    # Install package (live updates)
    dnf -y install "$PACKAGE" >/dev/null 2>&1
done

# Close the pipe
exec 3>&-
rm -f "$PIPE"

# Show completion message
dialog --infobox "All packages installed successfully!" 10 50
sleep 2
clear

# Stop slices from appearing in the logs
echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling user lingering to prevent excessive session logs..."
loginctl enable-linger root
echo -e "[${GREEN}SUCCESS${TEXTRESET}] User lingering enabled for 'root'."


#Bracketed pasting...yuck!
sed -i '8i set enable-bracketed-paste off' /etc/inputrc
clear
echo -e ${GREEN}"Installing Speedtest${TEXTRESET}"
sleep 4
#!/usr/bin/env bash

# Check if expect is installed
if ! command -v expect &>/dev/null; then
  echo -e "[${RED}ERROR${TEXTRESET}] Expect is not installed. Installing now..."
  dnf -y install expect
fi

# Run the package installation script and install speedtest
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh | sudo bash
dnf -y install speedtest
clear
echo -e ${YELLOW}"The following question will be answered for you ${RED}Interaction not required${TEXTRESET}"
sleep 4
# Create an expect script to automate the interaction with speedtest
/usr/bin/expect <<EOF
    spawn speedtest
    expect "Do you accept the license? \\[type YES to accept\\]:"
    send "YES\r"
    expect eof
EOF
clear
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)

echo -e ${GREEN}"Checking for Virtualtization Platform${TEXTRESET}"
sleep 2 #Checking for VM platform-Install client
echo ${GREEN}"Installing VMGuest${TEXTRESET}"
if [ "$HWKVM" = "KVM" ]; then
  echo -e ${GREEN}"KVM Platform detected ${TEXTRESET}"
  echo "Installing qemu-guest-agent"
  sleep 1
  dnf -y install qemu-guest-agent
else
  echo " "
fi

#Checking for VM platform-Install client
if [ "$HWVMWARE" = "VMware" ]; then
  echo -e ${GREEN}"VMWARE Platform detected ${TEXTRESET}"
  echo "Installing open-vm-tools"
  sleep 1
  dnf -y install open-vm-tools
else
  echo " "
fi
clear
# Function to check and disable firewalld
disable_firewalld() {
  if systemctl is-active --quiet firewalld; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] firewalld is running, disabling it..."
    sudo systemctl stop firewalld
    sudo systemctl disable firewalld
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] firewalld has been stopped and disabled."
  else
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] firewalld is not running.${TEXTRESET}"
  fi
}

# Function to check and enable nftables
enable_nftables() {
  if ! systemctl is-active --quiet nftables; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] nftables is not running, enabling it..."
    sudo systemctl start nftables
    sudo systemctl enable nftables
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables has been started and enabled."
  else
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables is already running."
  fi
}

# Main script execution
disable_firewalld
enable_nftables
sleep 4
clear
#set the inside interface
# Get all active connections managed by NetworkManager
active_connection=$(nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active | grep ":802-3-ethernet:" | grep ":activated")

if [ -z "$active_connection" ]; then
  echo -e "[${RED}ERROR${TEXTRESET}] No active ethernet connections found. Exiting..."
  exit 1
fi

# Parse the active connection details
IFS=: read -r name device type state <<<"$active_connection"

echo -e "[${GREEN}SUCCESS${TEXTRESET}] Active internal network connection found: ${GREEN}$device ($name)${TEXTREST}"

# Check if the connection profile name already has the '-inside' suffix
if [[ "$name" == *-inside ]]; then
  echo -e "[${YELLOW}INFO${TEXTRESET}] The connection profile name already has the '-inside' suffix. No modification needed."
else
  # Update the connection profile name to include '-inside'
  new_profile_name="${name}-inside"
  echo -e "[${YELLOW}INFO${TEXTRESET}] Updating connection profile name to: ${GREEN}$new_profile_name${TEXTRESET}"
  nmcli connection modify "$name" connection.id "$new_profile_name"
  nmcli connection reload
fi

#SET VLANS
echo -e "Considerations:
If you create VLANS, your inside interface IP is untagged right now
The Scripts will allow DNS and DHCP Services on all VLANS by default
All management processes and applications stay on the native (untagged) ip address/interface
For example, if cockpit is installed, you will not be able to access it from any vlan interface you create
unless you manually specify this. 
The goal is to have a Management VLAN. This VLAN is your untagged interface/IP scheme right now

One other consideration.
The device you are using to SSH into this system right now should be in the untagged VLAN network.
If it is not (i.e. you are going over a router interface to SSH this box right now),
If you create a VLAN and activate it in the subnet you will lose connectivity to the machine, and you 
MUST SSH On the interface you created (This is just how arp works). If you do, the installer will restart and you may continue. 
But, remember, you cannot access any of the applications from anything other than the "untagged" network.
If you are setting up Kibana/Elastic for suricata, you will neeed direct access to this untagged network or your setup will fail.

"
# Function to validate IP address format and ensure it's not a network or broadcast address
function validate_ip() {
  local ip="$1"
  local cidr_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
  if [[ $ip =~ $cidr_regex ]]; then
    # Split IP and CIDR parts
    local ip_part="${ip%/*}"
    local cidr_part="${ip#*/}"
    # Validate each octet is between 0-255 and CIDR is between 0-32
    IFS='.' read -r -a octets <<<"$ip_part"
    if [[ ${octets[0]} -le 255 && ${octets[1]} -le 255 && ${octets[2]} -le 255 && ${octets[3]} -le 255 && $cidr_part -le 32 ]]; then
      # Calculate network and broadcast addresses
      local mask=$((0xFFFFFFFF << (32 - cidr_part) & 0xFFFFFFFF))
      local ip_num=$(((${octets[0]} << 24) + (${octets[1]} << 16) + (${octets[2]} << 8) + ${octets[3]}))
      local network=$((ip_num & mask))
      local broadcast=$((network | ~mask & 0xFFFFFFFF))
      if [[ $ip_num -ne $network && $ip_num -ne $broadcast ]]; then
        return 0
      fi
    fi
  fi
  return 1
}

# Function to display a graphical representation of mapped VLANs
function display_vlan_map() {
  echo -e "${GREEN}VLAN Mappings:${TEXTRESET}"
  nmcli -t -f NAME,TYPE,DEVICE connection show --active | grep ":vlan:" | sort | uniq | while IFS=: read -r con_name con_type con_iface; do
    # Extract VLAN ID from the interface name
    vlan_id="${con_iface##*.}"
    # Get the IP address associated with the VLAN
    ip_address=$(nmcli connection show "$con_name" | awk '/ipv4.addresses:/ {print $2}')
    # Get the friendly name (connection id)
    friendly_name=$(nmcli -t -f connection.id connection show "$con_name")

    # Display the VLAN information
    echo "  +-----------------------------+"
    echo "  |  Interface: $con_iface      |"
    echo "  |  VLAN ID: $vlan_id          |"
    echo "  |  IP: $ip_address            |"
    echo "  |  Friendly Name: $friendly_name |"
    echo "  +-----------------------------+"
    echo
  done
}

# Start the VLAN configuration loop
while true; do
  # Display current VLAN mappings
  display_vlan_map

  # Prompt the user for VLAN usage
  read -p "Would you like to configure a VLAN? (y/n): " use_vlan

  if [[ "$use_vlan" == "y" ]]; then
    # List physical network interfaces with connection profile names, excluding loopback and VLANs
    echo -e "${YELLOW}Available physical network interfaces:${TEXTRESET}"
    interfaces=()
    index=1
    while IFS=: read -r profile device; do
      # Exclude interfaces that are VLANs (contain a dot) and loopback (lo)
      if [[ -n "$device" && "$device" != *.* && "$device" != "lo" ]]; then
        interfaces+=("$device")
        echo "$index) $device ($profile)"
        ((index++))
      fi
    done < <(nmcli -t -f NAME,DEVICE connection show --active)

    # Prompt user to select an interface by number
    while true; do
      read -p "Please select an interface by number: " selected_number
      if [[ "$selected_number" =~ ^[0-9]+$ && "$selected_number" -ge 1 && "$selected_number" -le "${#interfaces[@]}" ]]; then
        selected_interface="${interfaces[$((selected_number - 1))]}"
        break
      else
        echo -e "[${RED}ERROR${TEXTRESET}]Invalid selection. Please enter a valid number corresponding to a physical interface."
      fi
    done

    # Prompt for VLAN ID
    while true; do
      read -p "Enter VLAN ID (1-4094): " vlan_id
      if [[ "$vlan_id" -ge 1 && "$vlan_id" -le 4094 ]]; then
        break
      else
        echo -e "[${RED}ERROR${TEXTRESET}] Invalid VLAN ID. Please enter a number between 1 and 4094."
      fi
    done

    # Prompt for IP address and subnet
    while true; do
      read -p "Enter the IP address in CIDR format (e.g., 192.168.21.1/24): " ip_address
      if validate_ip "$ip_address"; then
        break
      else
        echo -e "[${RED}ERROR${TEXTRESET}] Invalid IP address format or it's a network/broadcast address. Please enter a valid host IP in CIDR format."
      fi
    done

    # Prompt for a friendly name for the VLAN interface
    read -p "Enter a friendly name for the VLAN interface: " friendly_name

    # Review selections
    echo -e "You have selected:"
    echo -e "Interface: ${GREEN}$selected_interface${TEXTRESET}"
    echo "VLAN ID: ${GREEN}$vlan_id${TEXTRESET}"
    echo "IP Address: ${GREEN}$ip_address${TEXTRESET}"
    echo "Friendly Name: ${GREEN}$friendly_name${TEXTRESET}"

    # Confirm changes
    read -p "Would you like to apply these changes? (y/n): " apply_changes

    if [[ "$apply_changes" == "y" ]]; then
      # Apply VLAN and IP configuration
      vlan_connection="${selected_interface}.${vlan_id}"
      nmcli connection add type vlan con-name "$vlan_connection" dev "$selected_interface" id "$vlan_id" ip4 "$ip_address"
      # Modify the connection to update the friendly name
      nmcli connection modify "$vlan_connection" connection.id "$friendly_name"
      # Use the updated connection name to bring it up
      nmcli connection up "$friendly_name"
      echo -e "[${GREEN}SUCCESS${TEXTRESET}]VLAN ${GREEN}$vlan_id${TEXTRESET} configured on ${GREEN}$selected_interface${TEXTRESET} with IP ${GREEN}$ip_address${TEXTRESET} and friendly name ${GREEN}'$friendly_name'${TEXTRESET}."
    fi

    # Display updated VLAN mappings
    display_vlan_map

    # Ask if the user wants to add another VLAN
    read -p "Would you like to configure another VLAN? (y/n): " continue_vlan
    if [[ "$continue_vlan" != "y" ]]; then
      break
    fi
  else
    echo -e "[${YELLOW}INFO${TEXTRESET}] VLAN configuration not selected."
    break
  fi
done

#ADD SSH TO THE INTERNAL INTERFACE(S)
# Function to locate the server's private IP address using nmcli
find_private_ip() {
  # Find the interface ending with -inside
  interface=$(nmcli device status | awk '/-inside/ {print $1}')

  if [ -z "$interface" ]; then
    echo -e "${RED}Error: No interface ending with '-inside' found.${TEXTRESET}"
    exit 1
  fi

  # Get the friendly name for the inside interface
  friendly_name=$(nmcli -t -f DEVICE,NAME connection show --active | grep "^$interface:" | cut -d':' -f2)

  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Inside interface found: ${GREEN}$interface ($friendly_name)${TEXTRESET}"
}

# Function to set up nftables rule for SSH on the inside interface and its sub-interfaces
setup_nftables() {
  # Ensure the nftables service is enabled and started
  sudo systemctl enable nftables
  sudo systemctl start nftables
  #Initialize Conf
  nft list ruleset >/etc/sysconfig/nftables.conf
  sudo systemctl restart nftables
  # Create a filter table if it doesn't exist
  if ! sudo nft list tables | grep -q 'inet filter'; then
    sudo nft add table inet filter
  fi

  # Create an input chain if it doesn't exist
  if ! sudo nft list chain inet filter input &>/dev/null; then
    sudo nft add chain inet filter input { type filter hook input priority 0 \; }
  fi

  # Add a rule to allow SSH on the inside interface and any sub-interfaces
  # Find all interfaces related to the main inside interface
  all_interfaces=$(nmcli device status | awk -v intf="$interface" '$1 ~ intf {print $1}')

  for iface in $all_interfaces; do
    # Get the friendly name for each interface
    friendly_name=$(nmcli -t -f DEVICE,NAME connection show --active | grep "^$iface:" | cut -d':' -f2)

    if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 22 accept"; then
      sudo nft add rule inet filter input iifname "$iface" tcp dport 22 accept
      echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow SSH on interface ${GREEN}$iface ($friendly_name)${TEXTRESET}"
    else
      echo -e "[${YELLOW}INFO${TEXTRESET}] Rule already exists: Allow SSH on interface ${GREEN}$iface ($friendly_name)${TEXTRESET}"
    fi
  done

  # Save the current ruleset
  echo -e "[${YELLOW}INFO${TEXTRESET}] Saving the current nftables ruleset..."
  sudo nft list ruleset >/etc/sysconfig/nftables.conf

}

# Restart nftables to apply the changes
echo "Restarting nftables service..."
sudo systemctl restart nftables

echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables configuration completed successfully."

# Main script execution
find_private_ip
setup_nftables
sleep 4
/root/RFWB/set_external.sh
echo " "
read -p "Press Enter to install applications and services"
/root/RFWB/pkg_install_gui.sh
/root/RFWB/config_services.sh
/root/RFWB/enable_start_service_gui.sh

/root/RFWB/post_deploy.sh


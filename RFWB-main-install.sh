#!/usr/bin/env bash
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')
clear
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rocky FirewallBuilder Installation"
# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user."
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Exiting..."
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


# ========= VALIDATION HELPERS =========
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; }
validate_ip()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
validate_fqdn() { [[ "$1" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; }

is_host_ip() {
  local cidr="$1"
  local ip_part="${cidr%/*}"
  local mask="${cidr#*/}"

  IFS='.' read -r o1 o2 o3 o4 <<< "$ip_part"
  ip_dec=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))

  netmask=$(( 0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF ))
  network=$(( ip_dec & netmask ))
  broadcast=$(( network | ~netmask & 0xFFFFFFFF ))

  [[ "$ip_dec" -eq "$network" || "$ip_dec" -eq "$broadcast" ]] && return 1 || return 0
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"
  [[ ! "$domain" =~ (^|\.)"$hostname"(\.|$) ]]
}

# ========= SYSTEM CHECKS =========
check_root_and_os() {
  if [[ "$EUID" -ne 0 ]]; then
    dialog --aspect 9 --title "Permission Denied" --msgbox "This script must be run as root." 7 50
    clear; exit 1
  fi

  if [[ -f /etc/redhat-release ]]; then
    MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
  else
    dialog --title "OS Check Failed" --msgbox "/etc/redhat-release not found. Cannot detect OS." 7 50
    exit 1
  fi

  if [[ "$MAJOROS" -lt 9 ]]; then
    dialog --title "Unsupported OS" --msgbox "This installer requires Rocky Linux 9.x or later." 7 50
    exit 1
  fi
}
# ========= SELINUX CHECK =========
check_and_enable_selinux() {
  local current_status=$(getenforce)

  if [[ "$current_status" == "Enforcing" ]]; then
    dialog --title "SELinux Status" --infobox "SELinux is already enabled and enforcing." 6 50
    sleep 4
  else
    dialog --title "SELinux Disabled" --msgbox "SELinux is not enabled. Enabling SELinux now..." 6 50
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1

    if [[ "$(getenforce)" == "Enforcing" ]]; then
      dialog --title "SELinux Enabled" --msgbox "SELinux has been successfully enabled and is now enforcing." 6 50
    else
      dialog --title "SELinux Error" --msgbox "Failed to enable SELinux. Please check the configuration manually." 6 50
      exit 1
    fi
  fi
}
# ========= NETWORK INTERFACE CHECK =========
network_interface_count() {
  # Get the list of network interfaces excluding loopback, bridges, and virtual interfaces
  interfaces=$(ip link show | awk -F: '$0 !~ "lo|vir|br|^[^0-9]"{gsub(/^[ \t]+/, "", $2); print $2; getline}')
  interface_count=$(echo "$interfaces" | wc -l)

  if [ "$interface_count" -ge 2 ]; then
    interface_list=$(echo "$interfaces" | sed 's/^/ - /')

    # Build the dialog message using printf to preserve line breaks
    dialog --title "Hardware Interface Check" --infobox "$(printf "PASS: At Least 2 Interfaces found\n\n%s\n\n" "$interface_list")" 15 60
    sleep 3
  else
    dialog --title "Hardware Interface Check Failed" \
           --msgbox "Less than two usable network interfaces were found.\n\nPlease make sure this system has at least two active interfaces. That are detected by nmcli." 10 60
    exit 1
  fi
}
# ========= NETWORK DETECTION =========
detect_active_interface() {
  dialog --title "Interface Check" --infobox "Checking active network interface..." 5 50
  sleep 3

  # Attempt 1: Use nmcli to find connected Ethernet
  INTERFACE=$(nmcli -t -f DEVICE,TYPE,STATE device | grep "ethernet:connected" | cut -d: -f1 | head -n1)

  # Attempt 2: Fallback to any interface with an IP if nmcli fails
  if [[ -z "$INTERFACE" ]]; then
    INTERFACE=$(ip -o -4 addr show up | grep -v ' lo ' | awk '{print $2}' | head -n1)
  fi

  # Get the matching connection profile name
  if [[ -n "$INTERFACE" ]]; then
    CONNECTION=$(nmcli -t -f NAME,DEVICE connection show | grep ":$INTERFACE" | cut -d: -f1)
  fi

  # Log to /tmp in case of failure
  echo "DEBUG: INTERFACE=$INTERFACE" >> /tmp/rfwb_debug.log
  echo "DEBUG: CONNECTION=$CONNECTION" >> /tmp/rfwb_debug.log

  if [[ -z "$INTERFACE" || -z "$CONNECTION" ]]; then
    dialog --clear  --no-ok --title "Interface Error" --aspect 9 --msgbox "No active network interface with IP found. Check /tmp/rfwb_debug.log for details." 5 70
    exit 1
  fi

  export INTERFACE CONNECTION
}
# ========= STATIC IP CONFIG =========
prompt_static_ip_if_dhcp() {
  IP_METHOD=$(nmcli -g ipv4.method connection show "$CONNECTION" | tr -d '' | xargs)

  if [[ "$IP_METHOD" == "manual" ]]; then
  dialog --clear --title "Static IP Detected" --infobox "Interface '$INTERFACE' is already using a static IP.\nNo changes needed." 6 70
  sleep 3
  return
elif [[ "$IP_METHOD" == "auto" ]]; then
    while true; do
      while true; do
        IPADDR=$(dialog --title "Static IP" --inputbox "Enter static IP in CIDR format (e.g., 192.168.1.100/24):" 8 60 3>&1 1>&2 2>&3)
        validate_cidr "$IPADDR" && break || dialog --msgbox "Invalid CIDR format. Try again." 6 40
      done

      while true; do
        GW=$(dialog --title "Gateway" --inputbox "Enter default gateway:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$GW" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done

      while true; do
        DNSSERVER=$(dialog --title "DNS Server" --inputbox "Enter Upstream DNS server IP:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$DNSSERVER" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done
      
      while true; do
        HOSTNAME=$(dialog --title "FQDN" --inputbox "Enter FQDN (e.g., host.domain.com):" 8 60 3>&1 1>&2 2>&3)
        if validate_fqdn "$HOSTNAME" && check_hostname_in_domain "$HOSTNAME"; then break
        else dialog --msgbox "Invalid FQDN or hostname repeated in domain. Try again." 7 60
        fi
      done

      while true; do
        DNSSEARCH=$(dialog --title "DNS Search" --inputbox "Enter domain search suffix (e.g., localdomain):" 8 60 3>&1 1>&2 2>&3)
        [[ -n "$DNSSEARCH" ]] && break || dialog --msgbox "Search domain cannot be blank." 6 40
      done

      dialog --title "Confirm Settings" --yesno "Apply these settings?\n\nInterface: $INTERFACE\nIP: $IPADDR\nGW: $GW\nFQDN: $HOSTNAME\nDNS: $DNSSERVER\nSearch: $DNSSEARCH" 12 60

      if [[ $? -eq 0 ]]; then
        nmcli con mod "$CONNECTION" ipv4.address "$IPADDR"
        nmcli con mod "$CONNECTION" ipv4.gateway "$GW"
        nmcli con mod "$CONNECTION" ipv4.method manual
        nmcli con mod "$CONNECTION" ipv4.dns "$DNSSERVER"
        nmcli con mod "$CONNECTION" ipv4.dns-search "$DNSSEARCH"
        hostnamectl set-hostname "$HOSTNAME"
        

        dialog --clear --no-shadow --no-ok --title "Reboot Required" --aspect 9 --msgbox "Network stack set. The System will reboot. Reconnect at: ${IPADDR%%/*}" 5 95
        reboot
      fi
    done
  fi
}
# ========= UI SCREENS =========
show_welcome_screen() {
  clear
  echo -e "${GREEN}
                               .*((((((((((((((((*
                         .(((((((((((((((((((((((((((/
                      ,((((((((((((((((((((((((((((((((((.
                    (((((((((((((((((((((((((((((((((((((((/
                  (((((((((((((((((((((((((((((((((((((((((((/
                .(((((((((((((((((((((((((((((((((((((((((((((
               ,((((((((((((((((((((((((((((((((((((((((((((((((.
               ((((((((((((((((((((((((((((((/   ,(((((((((((((((
              /((((((((((((((((((((((((((((.        /((((((((((((*
              ((((((((((((((((((((((((((/              ((((((((((
              ((((((((((((((((((((((((                   *((((((/
              /((((((((((((((((((((*                        (((((*
               ((((((((((((((((((             (((*            ,((
               .((((((((((((((.            /(((((((
                 ((((((((((/             (((((((((((((/
                  *((((((.            /((((((((((((((((((.
                    *(*)            ,(((((((((((((((((((((((,
                                 (((((((((((((((((((((((/
                              /((((((((((((((((((((((.
                                ,((((((((((((((,
${RESET}"
  echo -e "                         ${GREEN}Rocky Linux${RESET} ${RED}Firewall${RESET} ${YELLOW}Builder${RESET}"

  sleep 2
}



# ========= INTERNET CONNECTIVITY CHECK =========
check_internet_connectivity() {
  dialog --title "Network Test" --infobox "Checking internet connectivity..." 5 50
  sleep 2

  local dns_test="FAILED"
  local ip_test="FAILED"

  if ping -c 1 -W 2 google.com &>/dev/null; then
    dns_test="SUCCESS"
  fi

  if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    ip_test="SUCCESS"
  fi

  dialog --title "Connectivity Test Results" --infobox "DNS Resolution: $dns_test
Direct IP (8.8.8.8): $ip_test " 7 50
  sleep 4

  if [[ "$dns_test" == "FAILED" || "$ip_test" == "FAILED" ]]; then
    dialog --title "Network Warning" --yesno "Internet connectivity issues detected. Do you want to continue?" 7 50
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
  fi
}

# ========= HOSTNAME VALIDATION =========
validate_and_set_hostname() {
  local current_hostname
  current_hostname=$(hostname)

  if [[ "$current_hostname" == "localhost.localdomain" ]]; then
    while true; do
      NEW_HOSTNAME=$(dialog --title "Hostname Configuration" --inputbox \
        "Current hostname is '$current_hostname'. Please enter a new FQDN (e.g., server.example.com):" \
        8 60 3>&1 1>&2 2>&3)

      if validate_fqdn "$NEW_HOSTNAME" && check_hostname_in_domain "$NEW_HOSTNAME"; then
        hostnamectl set-hostname "$NEW_HOSTNAME"
        dialog --title "Hostname Set" --msgbox "Hostname updated to: $NEW_HOSTNAME" 6 50
        break
      else
        dialog --title "Invalid Hostname" --msgbox "Invalid hostname. Please try again." 6 50
      fi
    done
  else
    # Show a temporary info box with current hostname, no OK button
    dialog --title "Hostname Check" --infobox \
      "Hostname set to: $current_hostname" 6 60
    sleep 3
  fi
}

# ========= SYSTEM UPDATE & PACKAGE INSTALL =========
update_and_install_packages() {
  # Simulate progress while enabling EPEL and CRB
  dialog --title "Repository Setup" --gauge "Enabling EPEL and CRB repositories..." 10 60 0 < <(
    (
      (
        dnf install -y epel-release >/dev/null 2>&1
        dnf config-manager --set-enabled crb >/dev/null 2>&1
      ) &
      PID=$!
      PROGRESS=0
      while kill -0 "$PID" 2>/dev/null; do
        echo "$PROGRESS"
        echo "XXX"
        echo "Enabling EPEL and CRB..."
        echo "XXX"
        ((PROGRESS += 5))
        if [[ $PROGRESS -ge 95 ]]; then
          PROGRESS=5
        fi
        sleep 0.5
      done
      echo "100"
      echo "XXX"
      echo "Repositories enabled."
      echo "XXX"
    )
  )

  dialog --title "System Update" --infobox "Checking for updates. This may take a few moments..." 5 70
  sleep 2

  dnf check-update -y &>/dev/null

  TEMP_FILE=$(mktemp)
  dnf check-update | awk '{print $1}' | grep -vE '^$|Obsoleting|Last' | awk -F'.' '{print $1}' | sort -u > "$TEMP_FILE"

  PACKAGE_LIST=($(cat "$TEMP_FILE"))
  TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

  if [[ "$TOTAL_PACKAGES" -eq 0 ]]; then
    dialog --title "System Update" --msgbox "No updates available!" 6 50
    rm -f "$TEMP_FILE"
  else
    PIPE=$(mktemp -u)
    mkfifo "$PIPE"
    dialog --title "System Update" --gauge "Installing updates..." 10 70 0 < "$PIPE" &
    exec 3>"$PIPE"
    COUNT=0
    for PACKAGE in "${PACKAGE_LIST[@]}"; do
      ((COUNT++))
      PERCENT=$(( (COUNT * 100) / TOTAL_PACKAGES ))
      echo "$PERCENT" > "$PIPE"
      echo "XXX" > "$PIPE"
      echo "Updating: $PACKAGE" > "$PIPE"
      echo "XXX" > "$PIPE"
      dnf -y install "$PACKAGE" >/dev/null 2>&1
    done
    exec 3>&-
    rm -f "$PIPE" "$TEMP_FILE"
  fi

  dialog --title "Package Installation" --infobox "Installing required packages..." 5 50
  sleep 2
  PACKAGE_LIST=("ntsysv" "iptraf" "fail2ban" "tuned" "net-tools" "dmidecode" "ipcalc" "bind-utils" "expect" "jq" "bc" "iproute-tc" "iw" "hostapd" "iotop" "zip" "yum-utils" "nano" "curl" "wget" "policycoreutils-python-utils" "dnf-automatic")
  TOTAL_PACKAGES=${#PACKAGE_LIST[@]}

  PIPE=$(mktemp -u)
  mkfifo "$PIPE"
  dialog --title "Installing Dependency Packages" --gauge "Preparing to install packages..." 10 70 0 < "$PIPE" &
  exec 3>"$PIPE"
  COUNT=0
  for PACKAGE in "${PACKAGE_LIST[@]}"; do
    ((COUNT++))
    PERCENT=$(( (COUNT * 100) / TOTAL_PACKAGES ))
    echo "$PERCENT" > "$PIPE"
    echo "XXX" > "$PIPE"
    echo "Installing: $PACKAGE" > "$PIPE"
    echo "XXX" > "$PIPE"
    dnf -y install "$PACKAGE" >/dev/null 2>&1
  done
  exec 3>&-
  rm -f "$PIPE"
  dialog --title "Installation Complete" --infobox "All packages installed successfully!" 6 50
  sleep 3
}
#===========Detect if system is running Virtualization and install Guest=============
# Function to show a dialog infobox
vm_detection() {
show_info() {
    dialog --title "$1" --infobox "$2" 5 60
    sleep 2
}

# Function to show a progress bar during installation
show_progress() {
    (
        echo "10"; sleep 1
        echo "40"; sleep 1
        echo "70"; sleep 1
        echo "100"
    ) | dialog --title "$1" --gauge "$2" 7 60 0
}

# Detect virtualization platform
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)

show_info "Virtualization Check" "Checking for virtualization platform..."

# Install guest agent for KVM
if [ "$HWKVM" = "KVM" ]; then
    show_info "Platform Detected" "KVM platform detected.\nInstalling qemu-guest-agent..."
    show_progress "Installing qemu-guest-agent" "Installing guest tools for KVM..."
    dnf -y install qemu-guest-agent &>/dev/null
fi

# Install guest agent for VMware
if [ "$HWVMWARE" = "VMware" ]; then
    show_info "Platform Detected" "VMware platform detected.\nInstalling open-vm-tools..."
    show_progress "Installing open-vm-tools" "Installing guest tools for VMware..."
    dnf -y install open-vm-tools &>/dev/null
fi
}

#=========== Install yq CLI ==============
install_yq_cli() {
  dialog --title "yq Install" --infobox "Downloading yq from GitHub..." 5 50
  sleep 2
  wget -q https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq

  if [[ -f /usr/bin/yq ]]; then
    chmod +x /usr/bin/yq
    dialog --title "yq Installed" --infobox "yq installed successfully to /usr/bin/yq." 5 50
    sleep 3
  else
    dialog --title "yq Install Error" --msgbox "Failed to download or install yq." 6 50
  fi
}
#===========Install Speed test cli==============
install_speedtest_cli() {
  dialog --title "Speedtest Install" --infobox "Adding Ookla Speedtest repository..." 5 50
  curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh | sudo bash >/dev/null 2>&1


  dialog --title "Speedtest Install" --infobox "Installing speedtest CLI..." 5 50
  dnf -y install speedtest >/dev/null 2>&1
  sleep 1

  dialog --title "Speedtest License" --infobox "Auto-accepting license agreement for speedtest CLI..." 6 60
  echo -e "${YELLOW}The Speedtest Acceptance is automated no Interaction required.. Please Wait${TEXTRESET}"
  /usr/bin/expect <<EOF
    spawn speedtest
    expect "Do you accept the license? \\[type YES to accept\\]:"
    send "YES\r"
    expect eof
EOF

  dialog --title "Speedtest Installed" --infobox "Speedtest CLI installed and initialized successfully." 5 60
  sleep 4
}


# ========= CHECK Firewall States and Services =========
config_fw_service() {
  local FIREWALLD_STATUS=""
  local NFTABLES_STATUS=""
  DEBUG_LOG="/tmp/firewall_config_debug.txt"
  echo "=== Firewall Configuration Log ===" > "$DEBUG_LOG"

  # Disable firewalld if running
  if systemctl is-active --quiet firewalld; then
    echo "[INFO] Disabling firewalld" >> "$DEBUG_LOG"
    systemctl stop firewalld >> "$DEBUG_LOG" 2>&1
    systemctl disable firewalld >> "$DEBUG_LOG" 2>&1
    FIREWALLD_STATUS="Disabled firewalld"
  else
    echo "[INFO] firewalld is not running." >> "$DEBUG_LOG"
    FIREWALLD_STATUS="firewalld was already stopped."
  fi

  # Enable nftables if not running
  if ! systemctl is-active --quiet nftables; then
    echo "[INFO] Enabling nftables" >> "$DEBUG_LOG"
    systemctl start nftables >> "$DEBUG_LOG" 2>&1
    systemctl enable nftables >> "$DEBUG_LOG" 2>&1
    NFTABLES_STATUS="Enabling nftables"
  else
    echo "[INFO] nftables is already running." >> "$DEBUG_LOG"
    NFTABLES_STATUS="nftables was already running."
  fi

  # Show final status to user with infobox
  dialog --title "Firewall Configuration" --infobox \
    "${FIREWALLD_STATUS}\n${NFTABLES_STATUS}" \
    8 60
  sleep 4
}
# ========= SET the inside interface with -inside =========
set_inside_interface() {
  DEBUG_LOG="/tmp/set_inside_interface_debug.txt"
  echo "=== Inside Interface Setup ===" > "$DEBUG_LOG"

  # Get active Ethernet connection
  active_connection=$(nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active \
    | grep ":802-3-ethernet:" \
    | grep ":activated")

  if [ -z "$active_connection" ]; then
    dialog --title "Error: No Ethernet Connection" --msgbox \
      "No active ethernet connections found.\n\nPlease connect to the internal network and try again." 7 60
    echo "[ERROR] No active ethernet connections found." >> "$DEBUG_LOG"
    exit 1
  fi

  # Parse connection info
  IFS=: read -r name device type state <<<"$active_connection"
  echo "[INFO] Active connection: $device ($name)" >> "$DEBUG_LOG"

  # Determine new name
  if [[ "$name" == *-inside ]]; then
    status_msg="The connection profile \"$name\" already ends with '-inside'. No change needed."
    echo "[INFO] Profile already ends with -inside" >> "$DEBUG_LOG"
  else
    new_profile_name="${name}-inside"
    echo "[INFO] Renaming connection $name -> $new_profile_name" >> "$DEBUG_LOG"
    nmcli connection modify "$name" connection.id "$new_profile_name" >> "$DEBUG_LOG" 2>&1
    nmcli connection reload >> "$DEBUG_LOG" 2>&1
    status_msg="Renamed connection \"$name\" to \"$new_profile_name\"."
  fi

  # Show final infobox message
  dialog --title "Inside Interface" --infobox \
    "$status_msg\n\nInterface detected: $device\n\n" 8 60
  sleep 4
}

# ========= SET VLANS IF we need to  =========
vlan_main(){
dialog --yesno "Would you like to configure VLANs on this system?" 7 50
response=$?

if [[ $response -eq 0 ]]; then
  vlan_configurator
else
  echo "Skipping VLAN configuration..."
  sleep 1
fi

}

vlan_configurator() {
  DEBUG_LOG="/tmp/vlan_debug.txt"
  echo "=== VLAN Setup Log ===" > "$DEBUG_LOG"

  dialog --title "VLAN Setup Notice" --msgbox \
"Considerations:

- Your current interface IP is untagged (native VLAN).
- DNS/DHCP will bind to all VLANs by default.
- Management apps (like Cockpit) bind only to untagged IP unless configured.
- Make sure your SSH session is in the untagged VLAN or you may lose access after changes." 20 70

  while true; do
    VLAN_INFO=$(nmcli -t -f NAME,DEVICE,TYPE connection show | grep ":vlan" | while IFS=: read -r name device type; do
      vlan_id="${device##*.}"
      ip=$(nmcli connection show "$name" | awk '/ipv4.addresses:/ {print $2}')
      echo "$device → $name (VLAN $vlan_id, ${ip:-No IP})"
    done)

    echo "$VLAN_INFO" > /tmp/vlan_map.txt
    dialog --title "Current VLAN Mappings" --textbox /tmp/vlan_map.txt 15 70

    dialog --menu "What would you like to do?" 12 50 4 \
      1 "Add a VLAN" \
      2 "Delete a VLAN" \
      3 "Exit" 2> /tmp/vlan_action

    case $(< /tmp/vlan_action) in
      1)
        IFS=$'\n' read -d '' -r -a interfaces < <(nmcli -t -f NAME,DEVICE connection show --active | grep -v '\.' | grep -v ':lo' && printf '\0'
)
        if [[ ${#interfaces[@]} -eq 0 ]]; then
          dialog --msgbox "No physical interfaces available." 5 40
          continue
        fi

        MENU_ITEMS=()
        for entry in "${interfaces[@]}"; do
          name="${entry%%:*}"
          dev="${entry##*:}"
          MENU_ITEMS+=("$dev" "$name")
        done

        dialog --menu "Select an interface for the VLAN:" 15 50 6 "${MENU_ITEMS[@]}" 2> /tmp/interface_choice
        selected_interface=$(< /tmp/interface_choice)

        while true; do
          dialog --inputbox "Enter VLAN ID (1-4094):" 8 40 2> /tmp/vlan_id
          vlan_id=$(< /tmp/vlan_id)

          existing_vlan_ifaces=$(nmcli -t -f DEVICE,TYPE connection show | grep ":vlan" | cut -d: -f1)
          for iface in $existing_vlan_ifaces; do
            if [[ "$iface" == "${selected_interface}.${vlan_id}" ]]; then
              dialog --msgbox "VLAN ID $vlan_id already exists on $selected_interface.\nPlease choose a different VLAN ID." 7 60
              continue 2
            fi
          done

          [[ "$vlan_id" =~ ^[0-9]+$ && "$vlan_id" -ge 1 && "$vlan_id" -le 4094 ]] && break
          dialog --msgbox "Invalid VLAN ID. Must be 1–4094." 5 40
        done

        while true; do
          dialog --inputbox "Enter IP address in CIDR format (e.g. 192.168.50.1/24):" 8 50 "192.168.10.1/24" 2> /tmp/vlan_ip
          vlan_ip=$(< /tmp/vlan_ip)

          if ! validate_cidr "$vlan_ip"; then
            dialog --msgbox "Invalid format. Use IP/CIDR format (e.g. 192.168.50.1/24)." 6 60
            continue
          fi

          if ! is_host_ip "$vlan_ip"; then
            dialog --msgbox "That IP is the network or broadcast address. Choose a valid host IP." 6 60
            continue
          fi

          host_ip="${vlan_ip%/*}"
          if ip -4 addr show | grep -q "$host_ip"; then
            dialog --msgbox "The IP address $host_ip is already assigned.\nPlease choose another." 6 60
            continue
          fi

          if ip -4 addr show | grep -q "$vlan_ip"; then
            dialog --msgbox "This exact CIDR is already in use.\nPlease use a different range." 6 60
            continue
          fi

          new_network=$(ipcalc -n "$vlan_ip" 2>/dev/null | awk -F= '/^NETWORK=/ {print $2}')
          if [[ -z "$new_network" ]]; then
            dialog --msgbox "Failed to calculate network. Please re-enter." 6 50
            continue
          fi

          subnet_in_use=0
          while IFS= read -r existing_ip; do
            existing_cidr=$(echo "$existing_ip" | awk '{print $2}')
            [[ -z "$existing_cidr" ]] && continue
            existing_network=$(ipcalc -n "$existing_cidr" 2>/dev/null | awk -F= '/^NETWORK=/ {print $2}')
            [[ "$existing_network" == "$new_network" ]] && subnet_in_use=1
          done < <(ip -4 addr show | grep -oP 'inet \K[\d./]+')

          if [[ "$subnet_in_use" -eq 1 ]]; then
            dialog --msgbox "The subnet $new_network is already in use.\nYou cannot assign it to multiple VLANs." 6 60
            continue
          fi

          break
        done

        while true; do
          dialog --inputbox "Enter a friendly name for the VLAN:" 8 50 2> /tmp/friendly_name
          friendly_name=$(< /tmp/friendly_name)

          if nmcli -t -f NAME connection show | grep -Fxq "$friendly_name"; then
            dialog --msgbox "The name \"$friendly_name\" already exists. Please choose another." 6 60
          else
            break
          fi
        done

        summary="Interface: $selected_interface
VLAN ID: $vlan_id
IP: $vlan_ip
Name: $friendly_name"

        dialog --yesno "Apply this configuration?\n\n$summary" 12 60 || continue

        vlan_conn="${selected_interface}.${vlan_id}"
        nmcli connection add type vlan con-name "$vlan_conn" dev "$selected_interface" id "$vlan_id" ip4 "$vlan_ip" >> "$DEBUG_LOG" 2>&1
        nmcli connection modify "$vlan_conn" connection.id "$friendly_name" >> "$DEBUG_LOG" 2>&1
        nmcli connection up "$friendly_name" >> "$DEBUG_LOG" 2>&1

        dialog --infobox "VLAN $vlan_id configured on $selected_interface as $friendly_name." 6 50
        sleep 3
        ;;

      2)
        VLAN_CONNS_RAW=($(nmcli -t -f NAME,DEVICE,TYPE connection show | grep ":vlan"))
        if [[ ${#VLAN_CONNS_RAW[@]} -eq 0 ]]; then
          dialog --msgbox "No VLAN connections found to delete." 5 50
          continue
        fi

        MENU_ITEMS=()
        for line in "${VLAN_CONNS_RAW[@]}"; do
          IFS=: read -r name device type <<< "$line"
          vlan_id="${device##*.}"
          ip=$(nmcli connection show "$name" | awk '/ipv4.addresses:/ {print $2}')
          display="${device} → $name (VLAN $vlan_id, ${ip:-No IP})"
          MENU_ITEMS+=("$name" "$display")
        done

        dialog --menu "Select a VLAN to delete:" 18 70 8 "${MENU_ITEMS[@]}" 2> /tmp/delete_choice
        selected_vlan=$(< /tmp/delete_choice)

        dialog --yesno "Are you sure you want to delete VLAN \"$selected_vlan\"?" 7 50 || continue

        nmcli connection delete "$selected_vlan" >> "$DEBUG_LOG" 2>&1
        dialog --infobox "VLAN \"$selected_vlan\" deleted successfully.\nContinuing..." 6 50
        sleep 3
        ;;

      3)
        break
        ;;
    esac
  done
}
# ========= Setup nftables SSH Allow rule inside interface with -inside =========
setup_nftables_inside() {
  # Locate interface ending in -inside
  interface=$(nmcli device status | awk '/-inside/ {print $1}')
  if [ -z "$interface" ]; then
    dialog --title "ERROR" --infobox "No interface ending in '-inside' found. Exiting..." 6 50
    sleep 4
    return 1
  fi

  friendly_name=$(nmcli -t -f DEVICE,NAME connection show --active | grep "^$interface:" | cut -d':' -f2)
  dialog --title "Inside Interface Found" --infobox "Inside interface: $interface\nConnection name: $friendly_name" 6 60
  sleep 4

  # Enable and start nftables
  systemctl enable nftables
  systemctl start nftables
  nft list ruleset > /etc/sysconfig/nftables.conf
  systemctl restart nftables

  # Ensure inet filter table/chain exist
  if ! nft list tables | grep -q 'inet filter'; then
    nft add table inet filter
  fi
  if ! nft list chain inet filter input &>/dev/null; then
    nft add chain inet filter input { type filter hook input priority 0 \; }
  fi

  # Find all related sub-interfaces
  all_interfaces=$(nmcli device status | awk -v intf="$interface" '$1 ~ intf {print $1}')

  for iface in $all_interfaces; do
    friendly_name=$(nmcli -t -f DEVICE,NAME connection show --active | grep "^$iface:" | cut -d':' -f2)

    if ! nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 22 accept"; then
      nft add rule inet filter input iifname "$iface" tcp dport 22 accept
      dialog --title "Rule Added" --infobox "SSH allowed on $iface ($friendly_name)" 6 60
      sleep 4
    else
      dialog --title "Rule Exists" --infobox "SSH rule already present for $iface ($friendly_name)" 6 60
      sleep 4
    fi
  done

  dialog --title "Saving Ruleset" --infobox "Saving nftables rules to /etc/sysconfig/nftables.conf..." 5 70
  nft list ruleset > /etc/sysconfig/nftables.conf
  sleep 4

  dialog --title "nftables Reload" --infobox "Restarting nftables service to apply changes..." 5 70
  systemctl restart nftables
  sleep 4

  dialog --title "Done" --infobox "nftables SSH configuration completed successfully." 5 70
  sleep 4
}

# ========= Make sure connections are set to autoconnect and detect the outside interface=========
setup_outside_interface() {
  local connections
  connections=$(nmcli -t -f NAME,DEVICE,TYPE connection show)

  local checked_list=""
  while IFS=: read -r name device type; do
    if [[ "$type" == "802-3-ethernet" || "$type" == "wifi" ]]; then
      checked_list+="• $device ($name) [Type: $type]\n"
    fi
  done <<< "$connections"

  dialog --title "Checking Autoconnect" --infobox "Checking the following interfaces for autoconnect:\n\n$checked_list" 15 60
  sleep 4

  local result_log=""
  while IFS=: read -r name device type; do
    if [[ "$type" == "802-3-ethernet" || "$type" == "wifi" ]]; then
      autoconnect=$(nmcli -g connection.autoconnect connection show "$name")

      if [[ "$autoconnect" != "yes" ]]; then
        nmcli connection modify "$name" connection.autoconnect yes
        if [[ $? -eq 0 ]]; then
          result_log+="[✓] Enabled autoconnect: $name (Device: $device)\n"
        else
          result_log+="[✗] Failed to enable autoconnect: $name (Device: $device)\n"
        fi
      else
        result_log+="[✓] Already autoconnected: $name (Device: $device)\n"
      fi
    fi
  done <<< "$connections"

  dialog --title "Autoconnect Update" --infobox "$result_log" 20 70
  sleep 4

  local existing_connections
  existing_connections=$(nmcli -t -f DEVICE,STATE dev status | grep ":connected" | cut -d: -f1)

  dialog --title "Connected Interfaces" --infobox "Currently connected interfaces:\n\n$existing_connections" 10 50
  sleep 4

  dialog --clear --title "WAN Auto‑Detect Setup" --msgbox "The next screen will auto‑detect your WAN interface.\n\nPlease make sure that interface is unplugged before you proceed." 8 70

  dialog --title "WAN Setup" --infobox "Please plug in your Internet (WAN) connection.\n\nWaiting for a new interface to come up..." 7 60
  sleep 3

  # Wait for new interface to appear
  local new_connection=""
  while true; do
    current_connections=$(nmcli -t -f DEVICE,STATE dev status | grep ":connected" | cut -d: -f1)
    new_connection=$(comm -13 <(echo "$existing_connections" | sort) <(echo "$current_connections" | sort) | grep -v "^lo$")

    if [[ -n "$new_connection" ]]; then
      break
    fi

    sleep 0.5
  done

  dialog --title "New Connection" --infobox "Detected new connection:\n\n$new_connection" 7 50
  sleep 3

  local current_profile
  current_profile=$(nmcli -t -f NAME,DEVICE connection show --active | grep ":${new_connection}$" | cut -d: -f1)

  if [[ -n "$current_profile" ]]; then
    new_profile_name="${new_connection}-outside"
    nmcli connection modify "$current_profile" connection.id "$new_profile_name"
    nmcli connection reload

    dialog --title "Outside Interface Set" --infobox "Updated profile name to:\n$new_profile_name" 6 50
    sleep 3
  else
    dialog --title "Error" --infobox "Could not find an active profile for $new_connection" 6 50
    sleep 4
  fi
}
# ========= Install the threatlist update script and download NFT rulesets apply them to the tables=========
configure_nftables_threatlists() {
  LOG_TAG="nft-threat-list"
  BLOCK_SET="threat_block"

  THREAT_LIST_FILE="/etc/nft-threat-list/threat_list.txt"
  MANUAL_BLOCK_LIST="/etc/nft-threat-list/manual_block_list.txt"
  COMBINED_BLOCK_LIST="/etc/nft-threat-list/combined_block_list.txt"
  TMP_FILE="/etc/nft-threat-list/threat_list.tmp"
  UPDATE_SCRIPT="/usr/local/bin/update_nft_threatlist.sh"
  CRON_JOB="/etc/cron.d/nft-threat-list"
  LOG_FILE="/var/log/nft-threat-list.log"

  dialog --title "NFTables Setup" --infobox "Installing NFTables Threat List Updater..." 5 60
  sleep 2

  # Create necessary files
  mkdir -p /etc/nft-threat-list
  touch "$THREAT_LIST_FILE" "$TMP_FILE" "$LOG_FILE"

  # Manual block list template
  cat <<EOF > "$MANUAL_BLOCK_LIST"
# Manual Block List for NFTables
# Add IP addresses below the marker to be blocked
######### Place IP Addresses under this line to be compiled #########
EOF

  chmod 644 "$MANUAL_BLOCK_LIST"

  # Create the update script
  cat <<'EOF' > "$UPDATE_SCRIPT"
#!/bin/bash
LOG_TAG="nft-threat-list"
THREAT_LISTS=(
  "https://iplists.firehol.org/files/firehol_level1.netset"
  "https://www.abuseipdb.com/blacklist.csv"
  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
)
THREAT_LIST_FILE="/etc/nft-threat-list/threat_list.txt"
MANUAL_BLOCK_LIST="/etc/nft-threat-list/manual_block_list.txt"
COMBINED_BLOCK_LIST="/etc/nft-threat-list/combined_block_list.txt"
TMP_FILE="/etc/nft-threat-list/threat_list.tmp"
LOG_FILE="/var/log/nft-threat-list.log"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE" | logger -t $LOG_TAG
}

log "Starting NFTables threat list update..."
> "$TMP_FILE"

for URL in "${THREAT_LISTS[@]}"; do
  for i in {1..3}; do
    log "Downloading $URL (Attempt $i)..."
    curl -s --retry 3 "$URL" >> "$TMP_FILE" && break
    sleep 2
  done
done

grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$TMP_FILE" | sort -u > "$THREAT_LIST_FILE"
awk '/#########/{found=1; next} found && /^[0-9]+\./' "$MANUAL_BLOCK_LIST" > "$TMP_FILE"
cat "$THREAT_LIST_FILE" "$TMP_FILE" | sort -u > "$COMBINED_BLOCK_LIST"

if ! nft list set inet filter threat_block &>/dev/null; then
  nft add table inet filter 2>/dev/null
  nft add set inet filter threat_block { type ipv4_addr\; flags timeout\; }
else
  nft flush set inet filter threat_block
fi

while IFS= read -r ip; do
  nft add element inet filter threat_block { $ip }
done < "$COMBINED_BLOCK_LIST"

if ! nft list chain inet filter input | grep -q 'ip saddr @threat_block drop'; then
  nft add rule inet filter input ip saddr @threat_block drop
fi

if ! nft list chain inet filter output &>/dev/null; then
  nft add chain inet filter output { type filter hook output priority 0 \; }
fi

if ! nft list chain inet filter output | grep -q 'ip daddr @threat_block log prefix "Outbound Blocked:" drop'; then
  nft add rule inet filter output ip daddr @threat_block log prefix "Outbound Blocked:" drop
fi

IP_COUNT=$(wc -l < "$COMBINED_BLOCK_LIST")
log "Threat list update completed with $IP_COUNT IPs."
EOF

  chmod +x "$UPDATE_SCRIPT"

  # Create cron job
  cat <<EOF > "$CRON_JOB"
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
0 4 * * * root $UPDATE_SCRIPT
EOF

  chmod 644 "$CRON_JOB"
  systemctl enable --now crond

  # Interface detection
  find_interface() {
    local suffix="$1"
    nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
  }

  find_sub_interfaces() {
    local main="$1"
    nmcli -t -f DEVICE device status | grep -E "^${main}\.[0-9]+" | awk '{print $1}'
  }

  INSIDE_INTERFACE=$(find_interface "-inside")
  OUTSIDE_INTERFACE=$(find_interface "-outside")
  SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")

  if [[ -z "$INSIDE_INTERFACE" || -z "$OUTSIDE_INTERFACE" ]]; then
    dialog --msgbox "Could not determine interfaces. Check your -inside/-outside naming." 8 50
    return 1
  fi

  # Enable IP forwarding
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  sysctl -p

  # nftables base config
  nft add table inet filter 2>/dev/null
  nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null
  nft add rule inet filter input iifname lo accept
  nft add rule inet filter input ct state established,related accept
  nft add rule inet filter input iifname "$INSIDE_INTERFACE" accept

  for sub_iface in $SUB_INTERFACES; do
    nft add rule inet filter input iifname "$sub_iface" accept
  done

  nft add rule inet filter input iifname "$OUTSIDE_INTERFACE" tcp dport 22 accept
  nft add rule inet filter input iifname "$OUTSIDE_INTERFACE" log prefix \"Blocked: \" drop

  nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; } 2>/dev/null
  nft add rule inet filter forward ct state established,related accept
  nft add rule inet filter forward iifname "$INSIDE_INTERFACE" oifname "$OUTSIDE_INTERFACE" accept

  for sub_iface in $SUB_INTERFACES; do
    nft add rule inet filter forward iifname "$INSIDE_INTERFACE" oifname "$sub_iface" accept
    nft add rule inet filter forward iifname "$sub_iface" oifname "$INSIDE_INTERFACE" accept
    nft add rule inet filter forward iifname "$sub_iface" oifname "$sub_iface" accept
    nft add rule inet filter forward iifname "$sub_iface" oifname "$OUTSIDE_INTERFACE" accept
  done

  nft add table inet nat 2>/dev/null
  nft add chain inet nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null
  nft add rule inet nat postrouting oifname "$OUTSIDE_INTERFACE" masquerade

  # Trigger update with dialog gauge
  dialog --title "Threat List Update" --gauge "Downloading and applying threat list..." 10 60 0 < <(
    echo 10; sleep 1
    echo 40; bash "$UPDATE_SCRIPT" >/dev/null 2>&1
    echo 90; sleep 1
    echo 100
  )

  BLOCKED_COUNT=$(wc -l < "$COMBINED_BLOCK_LIST")
  dialog --title "Setup Complete" --infobox "Threat list applied successfully.\nBlocked IPs: $BLOCKED_COUNT" 7 60
  sleep 4
  #if dialog --title "View Log" --yesno "Would you like to view the threat list update log?" 7 50; then
  #  dialog --textbox "$LOG_FILE" 20 80
  #fi

  nft list ruleset > /etc/sysconfig/nftables.conf
  systemctl enable --now nftables
}


#Application menu
# Track installed services configuration
# === Logging ===
LOG_FILE="/var/log/RFWB-installer.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}
declare -A INSTALLED_SERVICES

collect_service_choices() {
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
       12 "Install OpenVPN Server" off
    )
    choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)
    clear

    for choice in $choices; do
        case $choice in
        1) INSTALLED_SERVICES[net_services]=1 ;;
        2) INSTALLED_SERVICES[cockpit]=1 ;;
        3) INSTALLED_SERVICES[ntopng]=1 ;;
        4) INSTALLED_SERVICES[ddclient]=1 ;;
        5) INSTALLED_SERVICES[suricata]=1 ;;
        6) INSTALLED_SERVICES[portscan]=1 ;;
        7) INSTALLED_SERVICES[snmpd]=1 ;;
        8) INSTALLED_SERVICES[netdata]=1 ;;
        9) INSTALLED_SERVICES[qos]=1 ;;
        10) INSTALLED_SERVICES[avahi]=1 ;;
        11) INSTALLED_SERVICES[evebox]=1 ;;
        12) INSTALLED_SERVICES[openvpn]=1 ;;
        esac
    done
}

#Install the Services Selected
install_selected_services() {
    for service in "${!INSTALLED_SERVICES[@]}"; do
        case "$service" in
            net_services) install_net_services ;;
            cockpit) install_cockpit ;;
            ntopng) install_ntopng ;;
            ddclient) install_ddclient ;;
            suricata) install_suricata ;;
            portscan) install_portscan ;;
            snmpd) install_snmpd ;;
            netdata) install_netdata ;;
            qos) install_qos ;;
            avahi) install_avahi ;;
            evebox) install_eve ;;
            openvpn) install_ovpn ;;
        esac
    done
}

#=== Drop to CLI ===

drop_to_cli(){
dialog --title "Service Configuration" --msgbox "Ready to configure services." 8 60
clear
}

#=== CONFIG TIME ===
configure_time() {
    CHRONY_CONF="/etc/chrony.conf"
    TEMP_CONF="/tmp/chrony_temp.conf"

    echo -e "${CYAN}==>Configuring time synchronization...${TEXTRESET}"
    log "Configuring chrony..."

    if [ ! -f "$CHRONY_CONF" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] $CHRONY_CONF not found. Skipping chrony configuration."
        log "chrony.conf not found. Skipping configuration."
        return 1
    fi

    cp "$CHRONY_CONF" "${CHRONY_CONF}.bak"

    # === Helper Functions ===
    find_interface() {
        local suffix="$1"
        nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
    }

    find_sub_interfaces() {
        local main_interface="$1"
        nmcli -t -f DEVICE device status | grep -E "^${main_interface}\\.[0-9]+" | awk '{print $1}'
    }

    find_ip_scheme() {
        local interface="$1"
        nmcli -t -f IP4.ADDRESS dev show "$interface" | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+'
    }

    # === Get all inside interfaces and VLANs ===
    INSIDE_INTERFACES=()
    INSIDE_INTERFACES+=($(find_interface "-inside"))
    for iface in "${INSIDE_INTERFACES[@]}"; do
        SUB_INTERFACES=($(find_sub_interfaces "$iface"))
        INSIDE_INTERFACES+=("${SUB_INTERFACES[@]}")
    done

    # === Determine allow range ===
    declare -A NETWORK_PREFIXES
    for iface in "${INSIDE_INTERFACES[@]}"; do
        IP_SCHEME=$(find_ip_scheme "$iface")
        if [[ $IP_SCHEME =~ ([0-9]+\\.[0-9]+)\\.[0-9]+\\.[0-9]+/\\d+ ]]; then
            NETWORK_PREFIXES["${BASH_REMATCH[1]}"]=1
        fi
    done

    ALLOW_STATEMENT=""
    if [[ ${#NETWORK_PREFIXES[@]} -eq 1 ]]; then
        for prefix in "${!NETWORK_PREFIXES[@]}"; do
            ALLOW_STATEMENT="${prefix}.0.0/16"
        done
    else
        ALLOW_STATEMENT="0.0.0.0/0"
    fi

    # === Check for existing NTP server/pool lines ===
    if grep -qE '^\s*(server|pool)\s+' "$CHRONY_CONF"; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] Found existing 'server' or 'pool' entries in $CHRONY_CONF. Replacing with standard pool directive."
        log "Existing NTP servers found in chrony.conf – replacing with pool 2.rocky.pool.ntp.org iburst"
    fi

    # === Rewrite chrony.conf ===
    awk -v allow_statement="$ALLOW_STATEMENT" '
        BEGIN {
            pool_added = 0
        }
        /^#?allow .*$/ {
            print "allow " allow_statement
            next
        }
        /^server[[:space:]]+/ || /^pool[[:space:]]+/ {
            if (!pool_added) {
                print "pool 2.rocky.pool.ntp.org iburst"
                pool_added = 1
            }
            next
        }
        {
            print
        }
    ' "$CHRONY_CONF" > "$TEMP_CONF"

    mv "$TEMP_CONF" "$CHRONY_CONF"
    chown root:root "$CHRONY_CONF"
    chmod 644 "$CHRONY_CONF"
    restorecon -v "$CHRONY_CONF" >> "$LOG_FILE" 2>&1

    # === Restart or start chrony ===
    if systemctl is-active --quiet chronyd; then
        systemctl restart chronyd >> "$LOG_FILE" 2>&1
    else
        systemctl start chronyd >> "$LOG_FILE" 2>&1
    fi

    # === Wait for chrony to sync ===
    echo -e "[${YELLOW}INFO${TEXTRESET}] Waiting for chrony to synchronize time..."
    while true; do
        CHRONYC_OUTPUT=$(chronyc tracking)
        if echo "$CHRONYC_OUTPUT" | grep -q "Leap status.*Not synchronised"; then
            sleep 10
        else
            break
        fi
    done
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Chrony is synchronized with NTP pool."
    log "Chrony synchronized."

    # === Allow NTP traffic through nftables ===
    systemctl enable nftables >> "$LOG_FILE" 2>&1
    systemctl start nftables >> "$LOG_FILE" 2>&1

    if ! nft list tables | grep -q 'inet filter'; then
        nft add table inet filter
    fi

    if ! nft list chain inet filter input &>/dev/null; then
        nft add chain inet filter input { type filter hook input priority 0 \; }
    fi

    for iface in "${INSIDE_INTERFACES[@]}"; do
        nft_rules=$(nft list chain inet filter input)

        [[ ! "$nft_rules" =~ "iifname \"$iface\" udp dport 123 accept" ]] && \
            nft add rule inet filter input iifname "$iface" udp dport 123 accept

        [[ ! "$nft_rules" =~ "iifname \"$iface\" tcp dport 123 accept" ]] && \
            nft add rule inet filter input iifname "$iface" tcp dport 123 accept

        [[ ! "$nft_rules" =~ "iifname \"$iface\" udp dport 323 accept" ]] && \
            nft add rule inet filter input iifname "$iface" udp dport 323 accept
    done

    # === Restart nftables and re-enable portscan ===
    rfwb_status=$(systemctl is-active rfwb-portscan)
    if [ "$rfwb_status" == "active" ]; then
        systemctl stop rfwb-portscan >> "$LOG_FILE" 2>&1
    fi

    nft list ruleset > /etc/sysconfig/nftables.conf
    systemctl restart nftables >> "$LOG_FILE" 2>&1

    if [ "$rfwb_status" == "active" ]; then
        systemctl start rfwb-portscan >> "$LOG_FILE" 2>&1
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}Time Synchronization Completed Successfully!${TEXTRESET}"
    log "Chrony configuration complete."
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}
#=== CONFIG FAIL2BAN ===
configure_fail2ban() {
    echo -e "${CYAN}==>Configuring Fail2Ban Service...${TEXTRESET}"
    log "Configuring Fail2Ban service..."

    ORIGINAL_FILE="/etc/fail2ban/jail.conf"
    JAIL_LOCAL_FILE="/etc/fail2ban/jail.local"
    SSHD_LOCAL_FILE="/etc/fail2ban/jail.d/sshd.local"

    if cp -v "$ORIGINAL_FILE" "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Copied jail.conf to jail.local"
        log "Copied jail.conf to jail.local"
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to copy $ORIGINAL_FILE to $JAIL_LOCAL_FILE"
        log "Failed to copy jail.conf"
        return 1
    fi

    if sed -i '/^\[sshd\]/,/^$/ s/#mode.*normal/&\nenabled = true/' "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Modified jail.local to enable SSHD"
        log "Modified jail.local to enable SSHD"
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to modify $JAIL_LOCAL_FILE"
        log "Failed to modify jail.local"
        return 1
    fi

    cat <<EOL > "$SSHD_LOCAL_FILE"
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOL
    log "Created $SSHD_LOCAL_FILE"

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl start fail2ban >> "$LOG_FILE" 2>&1
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Fail2Ban is running."
        log "Fail2Ban is running."
    else
        echo -e "[${YELLOW}WARN${TEXTRESET}] Fail2Ban failed to start. Checking for SELinux blocks..."
        log "Fail2Ban failed to start. Checking SELinux..."

        selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')
        if [ "$selinux_status" == "enabled" ]; then
            restorecon -v /etc/fail2ban/jail.local >> "$LOG_FILE" 2>&1
            denials=$(ausearch -m avc -ts recent | grep "fail2ban-server" | wc -l)
            if [ "$denials" -gt 0 ]; then
                echo -e "[${YELLOW}INFO${TEXTRESET}] Generating SELinux policy for Fail2Ban..."
                ausearch -c 'fail2ban-server' --raw | audit2allow -M my-fail2banserver >> "$LOG_FILE" 2>&1
                semodule -X 300 -i my-fail2banserver.pp >> "$LOG_FILE" 2>&1
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Custom SELinux policy applied."
                log "Custom SELinux policy for Fail2Ban applied."
            fi
        fi

        systemctl restart fail2ban >> "$LOG_FILE" 2>&1
        if systemctl is-active --quiet fail2ban; then
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Fail2Ban started after SELinux fix."
            log "Fail2Ban started after SELinux policy."
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Fail2Ban still failed to start. Please investigate."
            log "Fail2Ban still not running after SELinux fix."
        fi
    fi

    sshd_status=$(fail2ban-client status sshd 2>&1)

    if echo "$sshd_status" | grep -q "ERROR   NOK: ('sshd',)"; then
        echo -e "[${RED}ERROR${TEXTRESET}] SSHD jail failed to start. Check configuration."
        log "SSHD jail failed to start."
    elif echo "$sshd_status" | grep -E "Banned IP list:"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] SSHD jail is active and functional."
        log "SSHD jail is active."
    else
        echo -e "[${YELLOW}WARN${TEXTRESET}] SSHD jail may not be functional. Please check."
        log "SSHD jail may not be working correctly."
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}Fail2Ban Configured Successfully!${TEXTRESET}"
    log "Fail2Ban configuration complete."
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}


#=== INSTALL AND CONFIG DDCLIENT ===

install_ddclient() {
    INSTALLED_SERVICES[ddclient]=1
    log "Installing ddclient..."
    {
        echo "30"
        dnf -y install ddclient >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing ddclient..." 10 60 0
    log "ddclient installation complete."
}

configure_ddclient() {
    echo -e "${CYAN}==>Configuring ddclient...${TEXTRESET}"
    echo -e "[${YELLOW}NOTICE${TEXTRESET}] ddclient has been installed but requires manual configuration before the service can be started."
    log "ddclient installed – manual configuration is required."
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}

# === INSTALL AND CONFIG COCKPIT ===

install_cockpit() {
    INSTALLED_SERVICES[cockpit]=1
    log "Installing Cockpit..."
    {
        echo "10"
        sleep 0.5
        echo "70"
        dnf -y install cockpit cockpit-storaged cockpit-files tuned >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing Cockpit..." 10 60 0
    log "Cockpit installation complete."
}
# === CONFIGURE COCKPIT ===

configure_cockpit () {
    echo -e "${CYAN}==>Configuring Cockpit...${TEXTRESET}"
    find_inside_interfaces() {
        # Find all active interfaces with a name ending in '-inside'
        inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

        if [ -z "$inside_interfaces" ]; then
            echo -e "[${RED}ERROR${TEXTRESET}] No interface with ${YELLOW}'-inside'${TEXTRESET} profile found. Exiting..."
            exit 1
        fi

        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Inside interfaces found: ${GREEN}$inside_interfaces${TEXTRESET}"
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
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow Cockpit on port 9090 for interface ${GREEN}$iface${TEXTRESET}"
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow Cockpit on port 9090 for interface $iface"
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
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_cockpit

    # Enable and start cockpit.socket
    systemctl enable --now cockpit.socket
    systemctl start cockpit.socket

    # Continue with the rest of the script
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}Cockpit Configured Successfully!${TEXTRESET}"
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
    
}
# === INSTALL AND CONFIG AVAHI ===

install_avahi() {
    INSTALLED_SERVICES[avahi]=1
    log "Installing Avahi..."
    {
        echo "50"
        dnf -y install avahi avahi-tools >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing Avahi..." 10 60 0
    log "Avahi installation complete."
}

configure_avahi() {
    log "Configuring Avahi for mDNS reflection on inside interfaces..."
    echo -e "${CYAN}==>Configuring Avahi mDNS on 'inside' interfaces...${TEXTRESET}"

    # Get inside interface and sub-interfaces
    INSIDE_INTERFACE=$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: '$2 ~ /-inside/ {print $1; exit}')
    SUB_INTERFACES=$(nmcli -t -f DEVICE device status | grep -E "^${INSIDE_INTERFACE}\.[0-9]+" | awk '{print $1}')
    OUTSIDE_INTERFACE=$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: '$2 ~ /-outside/ {print $1; exit}')

    log "Inside interface: $INSIDE_INTERFACE"
    log "Sub-interfaces: $SUB_INTERFACES"
    log "Outside interface: $OUTSIDE_INTERFACE"

    # Create interface list
    INTERFACES="$INSIDE_INTERFACE"
    for sub in $SUB_INTERFACES; do
        INTERFACES+=",${sub}"
    done

    # Backup and update Avahi configuration
    cp /etc/avahi/avahi-daemon.conf /etc/avahi/avahi-daemon.conf.bak 2>/dev/null
    cat <<EOF > /etc/avahi/avahi-daemon.conf
[server]
use-ipv4=yes
use-ipv6=yes
allow-interfaces=$INTERFACES

[reflector]
enable-reflector=yes
EOF

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Avahi configuration updated for interfaces: ${GREEN}$INTERFACES${TEXTRESET}"
    log "Avahi configuration updated with interfaces: $INTERFACES"

    # Enable and start Avahi
    systemctl enable --now avahi-daemon >> "$LOG_FILE" 2>&1
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Avahi service enabled and started."
    log "Avahi service started and enabled."

    # Ensure nftables table and chain exist
    nft add table inet filter 2>/dev/null || true
    nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null || true

    # Allow mDNS on inside interfaces
    nft add rule inet filter input iifname "$INSIDE_INTERFACE" udp dport 5353 accept 2>/dev/null || true
    for sub in $SUB_INTERFACES; do
        nft add rule inet filter input iifname "$sub" udp dport 5353 accept 2>/dev/null || true
    done

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables rules for Avahi mDNS reflection applied."
    log "nftables rules for Avahi mDNS reflection applied."

    # Save rules and restart nftables
    systemctl is-active rfwb-portscan && rfwb_active=1 || rfwb_active=0
    if [ "$rfwb_active" -eq 1 ]; then
        systemctl stop rfwb-portscan
        log "rfwb-portscan temporarily stopped."
    fi

    nft list ruleset > /etc/sysconfig/nftables.conf
    systemctl restart nftables
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] nftables ruleset saved and service restarted."
    log "nftables ruleset saved and service restarted."

    if [ "$rfwb_active" -eq 1 ]; then
        systemctl start rfwb-portscan
        log "rfwb-portscan restarted after nftables update."
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Avahi has been configured and is now reflecting mDNS on: ${GREEN}$INTERFACES${TEXTRESET}"
     echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}Avahi Configured Successfully!${TEXTRESET}"
    log "Avahi configuration complete."
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}

# === INSTALL AND CONFIG EVE ===
install_eve() {
    INSTALLED_SERVICES[evebox]=1
    log "Installing EVEBOX..."
    {
        echo "30"
        rpm -Uvh https://evebox.org/files/rpm/stable/evebox-release.noarch.rpm >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "80"
        dnf -y install sqlite evebox >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing EVEBOX..." 10 60 0
    log "EVEBOX installation complete."
}



# === INSTALL AND CONFIG OVPN ===
install_ovpn() {
    INSTALLED_SERVICES[openvpn]=1
    log "Installing OpenVPN..."
    {
        echo "50"
        dnf -y install openvpn easy-rsa >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing OpenVPN..." 10 60 0
    log "OpenVPN installation complete."
}

    configure_ovpn() {
    echo -e "${CYAN}==>Configuring OpenVPN Server...${TEXTRESET}"
    LOG_FILE="/var/log/rfwb-openvpn-install.log"
    exec > >(tee -a "$LOG_FILE") 2>&1

    echo -e "[${YELLOW}INFO${TEXTRESET}] Copying OpenVPN client creation tool..."
    sleep 2
    mkdir -p /etc/openvpn/clients
    \cp -r /root/RFWB/ovpn_client_create.sh /etc/openvpn/clients

    if [ -f /etc/openvpn/clients/ovpn_client_create.sh ]; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Client creation tool copied successfully."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to copy client creation tool!"
        exit 1
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Creating Easy-RSA directory..."
    sudo mkdir /etc/openvpn/easy-rsa
    sleep 2
    echo -e "[${YELLOW}INFO${TEXTRESET}] Creating symbolic link for Easy-RSA..."
    sleep 2
    sudo ln -s /usr/share/easy-rsa /etc/openvpn/easy-rsa

    cd /etc/openvpn/easy-rsa

    STATIC_HOSTNAME=$(hostnamectl | grep "Static hostname" | awk '{print $3}' | cut -d '.' -f1)
    echo "Using static hostname as Common Name (CN): $STATIC_HOSTNAME"

    echo -e "[${YELLOW}INFO${TEXTRESET}] Initializing PKI..."
    sleep 2
    sudo ./easy-rsa/3/easyrsa init-pki

    echo -e "[${YELLOW}INFO${TEXTRESET}] Building the Certificate Authority (CA) with hostname as CN..."
    sleep 2
    sudo EASYRSA_BATCH=1 EASYRSA_REQ_CN="$STATIC_HOSTNAME" ./easy-rsa/3/easyrsa build-ca nopass

    echo -e "[${YELLOW}INFO${TEXTRESET}] Generating server certificate request with hostname as CN..."
    sleep 2
    sudo EASYRSA_BATCH=1 EASYRSA_REQ_CN="$STATIC_HOSTNAME" ./easy-rsa/3/easyrsa gen-req server nopass

    echo -e  "[${YELLOW}INFO${TEXTRESET}] Signing the server certificate request..."
    sleep 2
    echo "yes" | sudo ./easy-rsa/3/easyrsa sign-req server server

    echo -e "[${YELLOW}INFO${TEXTRESET}] Generating Diffie-Hellman parameters..."
    sleep 2
    sudo ./easy-rsa/3/easyrsa gen-dh

    echo -e  "[${YELLOW}INFO${TEXTRESET}] Copying OpenVPN sample configuration..."
    sleep 2
    sudo cp /usr/share/doc/openvpn/sample/sample-config-files/server.conf /etc/openvpn/server/

    echo -e  "[${YELLOW}INFO${TEXTRESET}] Updating OpenVPN certificate and key paths..."
    sleep 2
    sudo sed -i '75,81s|^ca .*|ca /etc/openvpn/easy-rsa/pki/ca.crt|' /etc/openvpn/server/server.conf
    sudo sed -i '75,81s|^cert .*|cert /etc/openvpn/easy-rsa/pki/issued/server.crt|' /etc/openvpn/server/server.conf
    sudo sed -i '75,81s|^key .*|key /etc/openvpn/easy-rsa/pki/private/server.key|' /etc/openvpn/server/server.conf

    sudo sed -i '80,85s|^dh .*|dh /etc/openvpn/easy-rsa/pki/dh.pem|' /etc/openvpn/server/server.conf
    sudo sed -i '240,244s|^tls-auth ta.key 0 # This file is secret|#tls-auth ta.key 0 # This file is secret|' /etc/openvpn/server/server.conf
    sudo sed -i '143i push "route 0.0.0.0 0.0.0.0"\n' /etc/openvpn/server/server.conf

    echo -e "[${YELLOW}INFO${TEXTRESET}] Setting process to user and Group nobody"
    sleep 2
    sudo sed -i 's/^;user nobody/user nobody/' /etc/openvpn/server/server.conf
    sudo sed -i 's/^;group nobody/group nobody/' /etc/openvpn/server/server.conf

    echo -e "[${YELLOW}INFO${TEXTRESET}] Checking for named process"
    sleep 2
    if sudo systemctl is-active --quiet named; then
        read -p "Enter the primary DNS IP for OpenVPN clients: " DNS_IP
        sudo sed -i '/push "dhcp-option DNS 208.67.222.222"/i push "dhcp-option DNS '"$DNS_IP"'"' /etc/openvpn/server/server.conf
        echo "$DNS_IP" | sudo tee /etc/openvpn/primary_dns > /dev/null
    fi

    sudo setsebool -P openvpn_enable_homedirs on
    sudo restorecon -Rv /etc/openvpn

    sudo systemctl enable openvpn-server@server
    sudo systemctl start openvpn-server@server

    if sudo systemctl is-active --quiet openvpn-server@server; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] OpenVPN server is running successfully!"
    else
        echo -e "[${RED}ERROR${TEXTRESET}] OpenVPN server failed to start. Check logs with: sudo journalctl -u openvpn-server@server --no-pager -n 50"
    fi

    echo " "
    echo " "
    echo "Select your interface(s) to pass VPN traffic on the firewall"

    set -e

    find_interface() {
        local suffix="$1"
        nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
    }

    find_sub_interfaces() {
        local main_interface="$1"
        nmcli -t -f DEVICE device status | grep -E "^${main_interface}\\.[0-9]+" | awk '{print $1}'
    }

    INSIDE_INTERFACE=$(find_interface "-inside")
    OUTSIDE_INTERFACE=$(find_interface "-outside")

    if [[ -z "$INSIDE_INTERFACE" ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No inside interface found."
        exit 1
    fi

    if [[ -z "$OUTSIDE_INTERFACE" ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No outside interface found."
        exit 1
    fi

    echo -e "Inside interface detected: ${GREEN}$INSIDE_INTERFACE${TEXTRESET}"
    echo -e "Outside interface detected: ${GREEN}$OUTSIDE_INTERFACE${TEXTRESET}"

    SUB_INTERFACES=$(find_sub_interfaces "$INSIDE_INTERFACE")
    ALL_INTERFACES=("$INSIDE_INTERFACE" $SUB_INTERFACES)
    TOTAL_INTERFACES=${#ALL_INTERFACES[@]}

    SELECTED_INTERFACES=()
    echo -e "Select the interfaces that should participate in ${YELLOW}VPN traffic:${TEXTRESET}"
    echo "0. Exit without applying rules"

    for i in "${!ALL_INTERFACES[@]}"; do
        echo "$((i+1)). ${ALL_INTERFACES[i]}"
    done

    while true; do
        if [[ ${#SELECTED_INTERFACES[@]} -eq $TOTAL_INTERFACES ]]; then
            echo -e "[${YELLOW}INFO${TEXTRESET}] All available interfaces have been selected. Proceeding..."
            break
        fi

        read -p "Enter the number of the interface to include (0 to finish): " CHOICE

        if [[ "$CHOICE" == "0" ]]; then
            if [[ ${#SELECTED_INTERFACES[@]} -eq 0 ]]; then
                echo "No interfaces selected. Exiting..."
                exit 0
            else
                break
            fi
        elif [[ "$CHOICE" =~ ^[0-9]+$ ]] && ((CHOICE >= 1 && CHOICE <= TOTAL_INTERFACES)); then
            INTERFACE_SELECTED="${ALL_INTERFACES[CHOICE-1]}"
            if [[ ! " ${SELECTED_INTERFACES[@]} " =~ " ${INTERFACE_SELECTED} " ]]; then
                SELECTED_INTERFACES+=("$INTERFACE_SELECTED")
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Added ${GREEN}$INTERFACE_SELECTED${TEXTRESET} to VPN traffic."
            else
                echo -e "[${RED}ERROR${TEXTRESET}] ${YELLOW}$INTERFACE_SELECTED${TEXTRESET} is already selected."
            fi
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Invalid choice. Please enter a valid number from the list."
        fi
    done

    echo -e "[${YELLOW}INFO${TEXTRESET}] Applying rules to nftables..."
    nft add rule inet filter input iifname "$OUTSIDE_INTERFACE" udp dport 1194 accept
    nft add rule inet filter input iifname "tun0" accept
    nft add rule inet filter forward iifname "tun0" oifname "$OUTSIDE_INTERFACE" ct state new accept

    for IFACE in "${SELECTED_INTERFACES[@]}"; do
        nft add rule inet filter forward iifname "tun0" oifname "$IFACE" accept
        nft add rule inet filter forward iifname "$IFACE" oifname "tun0" ct state new accept
    done

    nft list ruleset > /etc/sysconfig/nftables.conf

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] OpenVPN firewall rules applied successfully!"
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}OpenVPN Server Configured Successfully!${TEXTRESET}"
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}
install_net_services() {
    INSTALLED_SERVICES[net_services]=1
    log "Installing BIND and ISC KEA..."
    {
        echo "10"
        dnf -y install bind bind-utils >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "40"
        curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-2-6/cfg/setup/bash.rpm.sh' | bash >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "70"
        dnf -y update >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "90"
        dnf -y install isc-kea >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing BIND and ISC KEA..." 10 60 0
    log "BIND and ISC KEA installation complete."
}

install_ntopng() {
    INSTALLED_SERVICES[ntopng]=1
    log "Installing ntopng..."
    {
        echo "10"
        curl -s https://packages.ntop.org/centos-stable/ntop.repo -o /etc/yum.repos.d/ntop.repo
        sleep 0.5
        echo "40"
        dnf -y clean all >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "80"
        dnf -y install pfring-dkms n2disk nprobe ntopng cento ntap >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing ntopng..." 10 60 0
    log "ntopng installation complete."
}

configure_ntopng() {
    CONFIG_FILE="/etc/ntopng/ntopng.conf"

    echo -e "${CYAN}==>Configuring ntopng...${TEXTRESET}"
    log "Starting ntopng configuration..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] ntopng configuration file not found: $CONFIG_FILE"
        log "ntopng.conf not found"
        return 1
    fi

    sed -i 's|^-G=/var/run/ntopng.pid|-G=/var/tmp/ntopng.pid --community|' "$CONFIG_FILE"

    if grep -q "^-G=/var/tmp/ntopng.pid --community" "$CONFIG_FILE"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] ntopng configuration updated."
        log "ntopng configuration updated in $CONFIG_FILE"
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to update ntopng configuration. Please check manually."
        log "ntopng config update failed."
        return 1
    fi

    systemctl enable ntopng >> "$LOG_FILE" 2>&1
    systemctl start ntopng >> "$LOG_FILE" 2>&1

    if systemctl is-active --quiet ntopng; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] ntopng service is running."
        log "ntopng service started successfully."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] ntopng failed to start. Check service status."
        log "ntopng service failed to start."
        return 1
    fi

    inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    if [ -z "$inside_interfaces" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No '-inside' interface found. Skipping firewall rule setup."
        log "No inside interface found for ntopng firewall config."
        return 1
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring nftables rules for ntopng..."
    log "Adding nftables rules for ntopng access on port 3000..."

    systemctl enable nftables >> "$LOG_FILE" 2>&1
    systemctl start nftables >> "$LOG_FILE" 2>&1

    nft add table inet filter 2>/dev/null || true
    nft add chain inet filter input { type filter hook input priority 0 \; } 2>/dev/null || true

    for iface in $inside_interfaces; do
        if ! nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 3000 accept"; then
            nft add rule inet filter input iifname "$iface" tcp dport 3000 accept
            log "nftables rule added for $iface on port 3000"
        else
            log "Rule already exists for $iface on port 3000"
        fi
    done

    rfwb_status=$(systemctl is-active rfwb-portscan)
    if [ "$rfwb_status" == "active" ]; then
        systemctl stop rfwb-portscan
        log "Stopped rfwb-portscan to apply new nftables rules"
    fi

    nft list ruleset > /etc/sysconfig/nftables.conf
    systemctl restart nftables
    log "nftables rules saved and restarted"

    if [ "$rfwb_status" == "active" ]; then
        systemctl start rfwb-portscan
        log "Restarted rfwb-portscan after nftables update"
    fi

    echo -e "[${GREEN}DONE${TEXTRESET}] ntopng configuration complete."
    log "ntopng configuration complete."
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}ntopng Configured Successfully!${TEXTRESET}"
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}

install_suricata() {
    total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    total_mem_gb=$(echo "$total_mem_kb / 1024 / 1024" | bc -l | awk '{print ($1 == int($1)) ? $1 : int($1) + 1}')
    cpu_count=$(grep -c ^processor /proc/cpuinfo)

    if (( total_mem_gb < 8 )); then
        dialog --msgbox "RAM Check Failed: ${total_mem_gb} GB detected.\nNeed at least 8 GB." 8 50
        log "Suricata install aborted: insufficient RAM (${total_mem_gb} GB)"
        return 1
    fi
    if (( cpu_count < 2 )); then
        dialog --msgbox "CPU Check Failed: ${cpu_count} CPU(s) detected.\nNeed at least 2." 8 50
        log "Suricata install aborted: insufficient CPUs (${cpu_count})"
        return 1
    fi

    INSTALLED_SERVICES[suricata]=1
    log "Installing Suricata..."
    {
        echo "10"
        dnf install -y 'dnf-command(copr)' >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "40"
        echo 'y' | dnf copr enable @oisf/suricata-7.0 >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "80"
        dnf install -y suricata >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing Suricata..." 10 60 0
    log "Suricata installation complete."
}
configure_suricata() {
    echo -e "${CYAN}==>Configuring Suricata...${TEXTRESET}"
    log "Configuring Suricata..."

    sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
    log "Backed up suricata.yaml"

    echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling Community ID feature..."
    sudo sed -i 's/# \(community-id:\) false/\1 true/' /etc/suricata/suricata.yaml
    log "Enabled community ID"

    INSIDE_INTERFACE=$(nmcli connection show --active | awk '/-inside/ {print $4}')
    if [ -z "$INSIDE_INTERFACE" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No inside interface found. Exiting."
        log "No inside interface found."
        exit 1
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected inside interface: ${INSIDE_INTERFACE}"
    log "Detected inside interface: $INSIDE_INTERFACE"

    echo -e "[${YELLOW}INFO${TEXTRESET}] Updating capture interfaces in config..."
    sudo sed -i "/# Cross platform libpcap capture support/,/interface:/ s/interface: eth0/interface: $INSIDE_INTERFACE/" /etc/suricata/suricata.yaml
    sudo sed -i "/# Linux high speed capture support/,/af-packet:/ {n; s/interface: eth0/interface: $INSIDE_INTERFACE/}" /etc/suricata/suricata.yaml
    sudo sed -i "s/eth0/$INSIDE_INTERFACE/g" /etc/sysconfig/suricata

    echo -e "[${YELLOW}INFO${TEXTRESET}] Setting permissions..."
    sudo chgrp -R suricata /etc/suricata /var/lib/suricata /var/log/suricata
    sudo chmod -R g+r /etc/suricata/
    sudo chmod -R g+rw /var/lib/suricata /var/log/suricata
    sudo usermod -a -G suricata $USER

    if id -nG "$USER" | grep -qw "suricata"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] User $USER added to suricata group."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to add $USER to suricata group."
        exit 1
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Running suricata-update update-sources..."
    if sudo suricata-update update-sources; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] suricata-update update-sources completed successfully."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to run suricata-update update-sources."
        exit 1
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Running suricata-update..."
    trap '' SIGINT
    if sudo suricata-update; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] suricata-update completed successfully."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to run suricata-update."
        exit 1
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Would you like to enable additional rule sources? (y/n)"
    read -r enable_sources

    if [[ "$enable_sources" =~ ^[Yy]$ ]]; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] Fetching available rule sources..."

        TMP_SOURCE_LIST="/tmp/suricata_sources.txt"
        sudo suricata-update list-sources | sed 's/\x1B\[[0-9;]*[mK]//g' | col -b > "$TMP_SOURCE_LIST"

        SOURCE_NAMES=()
        SOURCE_SUMMARIES=()
        SOURCE_LICENSES=()

        while IFS= read -r line; do
            if [[ $line == Name:* ]]; then
                SOURCE_NAMES+=("$(echo "$line" | cut -d' ' -f2)")
            elif [[ $line == "  Summary:"* ]]; then
                SOURCE_SUMMARIES+=("${line#*: }")
            elif [[ $line == "  License:"* ]]; then
                SOURCE_LICENSES+=("${line#*: }")
            fi
        done < "$TMP_SOURCE_LIST"

        count=${#SOURCE_NAMES[@]}

        echo -e "\n[${YELLOW}INFO${TEXTRESET}] Available Rule Sources:"
        for ((i=0; i<$count; i++)); do
            printf "%2d) %s\n    %s\n    License: %s\n\n" \
                "$((i+1))" "${SOURCE_NAMES[$i]}" "${SOURCE_SUMMARIES[$i]:-No summary}" "${SOURCE_LICENSES[$i]:-Unknown}"
        done

        echo -e "[${YELLOW}INFO${TEXTRESET}] Enter the numbers of the sources you want to enable (e.g. 1 3 5):"
        read -r selected_numbers

        for num in $selected_numbers; do
            index=$((num - 1))
            if [[ -n "${SOURCE_NAMES[$index]}" ]]; then
                src="${SOURCE_NAMES[$index]}"
                echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling source: ${GREEN}$src${TEXTRESET}"
                if sudo suricata-update enable-source "$src"; then
                    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Source $src enabled."
                else
                    echo -e "[${RED}ERROR${TEXTRESET}] Failed to enable source: $src"
                fi
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Invalid selection: $num"
            fi
        done

        echo -e "[${YELLOW}INFO${TEXTRESET}] Running suricata-update with new sources..."
        if sudo suricata-update; then
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] suricata-update completed successfully with selected sources."
        else
            echo -e "[${RED}ERROR${TEXTRESET}] suricata-update failed after source additions."
            exit 1
        fi

        rm -f "$TMP_SOURCE_LIST"
    else
        echo -e "[${YELLOW}INFO${TEXTRESET}] Skipping additional rule source configuration."
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Validating Suricata configuration..."
    if suricata -T -c /etc/suricata/suricata.yaml -v | grep -q "Configuration provided was successfully loaded"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Configuration loaded successfully."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Configuration test failed."
        exit 1
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Starting Suricata service..."
    sudo systemctl start suricata
    status_output=$(sudo systemctl status suricata --no-pager)
    echo "$status_output"
    sleep 10

    check_and_fix_permissions() {
        status_output=$(sudo systemctl status suricata --no-pager)
        if echo "$status_output" | grep -q "Permission denied"; then
            echo -e "[${RED}ERROR${TEXTRESET}] Detected permission issues in Suricata log files."
            return 1
        else
            return 0
        fi
    }

    attempts=0
    max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        check_and_fix_permissions && break
        echo -e "[${YELLOW}INFO${TEXTRESET}] Fixing permissions (Attempt $((attempts + 1)))..."
        sudo chown -R suricata:suricata /var/log/suricata
        sudo systemctl restart suricata
        sleep 10
        ((attempts++))
    done

    if [ $attempts -eq $max_attempts ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Could not fix permission issues after $max_attempts attempts."
        exit 1
    fi

    echo -e "[${YELLOW}INFO${TEXTRESET}] Testing rule trigger..."
    for ((i = 0; i <= 30; i++)); do
        printf "\r[%-30s] %d%%" "$(head -c $i < /dev/zero | tr '\0' '#')" $((i * 100 / 30))
        sleep 2
    done
    echo

    response=$(curl -s http://testmynids.org/uid/index.html)
    expected="uid=0(root) gid=0(root) groups=0(root)"

    if [[ "$response" == "$expected" ]]; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Expected test NIDS response received."
        echo -e "[${YELLOW}INFO${TEXTRESET}] Checking fastlog for entry please wait..."
        sleep 4
        last_log_line=$(grep 2100498 /var/log/suricata/fast.log | tail -n 1)
        echo "Log: $last_log_line"
        if echo "$last_log_line" | grep -q "\[Classification: Potentially Bad Traffic\]"; then
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Suricata rule matched expected traffic."
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Rule did not classify expected traffic."
            exit 1
        fi
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Test request failed or unexpected response."
        exit 1
    fi
#Configure_logs
#
# Detects disk space, deployment type, traffic profile and user count,
# then writes a logrotate config for Suricata with an appropriate retention.
#
# Usage: sudo bash suricata-logrotate-setup.sh
#

set -euo pipefail
echo -e "${CYAN}==>Configuring Suricata Logging...${TEXTRESET}"

LOG_DIR="/var/log/suricata"
ROTATE_CONF="/etc/logrotate.d/suricata"
PID_FILE="/var/run/suricata.pid"

# -- 1) Ensure the log directory exists
if [[ ! -d "$LOG_DIR" ]]; then
  echo "[ERROR] Suricata log directory $LOG_DIR not found!"
  exit 1
fi

# -- 2) Get available space (in KB) on that filesystem
avail_kb=$(df -P "$LOG_DIR" | tail -1 | awk '{print $4}')
avail_mb=$(( avail_kb / 1024 ))

# -- 3) Numbered menu for deployment type
while true; do
  cat <<EOF

Select deployment type:
  1) Home    – residential/home usage
  2) SOHO    – small office/home office usage

EOF
  read -rp "Enter choice [1-2]: " dep_choice
  case "$dep_choice" in
    1) deployment="home"; break ;;
    2) deployment="soho"; break ;;
    *) echo "  → Invalid choice; please enter 1 or 2." ;;
  esac
done

# -- 4) Explain profiles and numbered menu for traffic profile
cat <<EOF

Traffic profile definitions:
  1) Light    – Basic web/email and occasional updates
                (~20 MB/user/day in home; ~5 MB/user/day in SOHO).
  2) Moderate – Mixed usage: web, email + some streaming/downloads
                (~50 MB/user/day in home; ~15 MB/user/day in SOHO).
  3) Heavy    – High‑intensity: constant streaming or large transfers
                (~100 MB/user/day in home; ~30 MB/user/day in SOHO).

EOF

while true; do
  cat <<EOF
Select traffic profile:
  1) Light
  2) Moderate
  3) Heavy

EOF
  read -rp "Enter choice [1-3]: " prof_choice
  case "$prof_choice" in
    1) profile="light"; break ;;
    2) profile="moderate"; break ;;
    3) profile="heavy"; break ;;
    *) echo "  → Invalid choice; please enter 1, 2, or 3." ;;
  esac
done

# -- 5) Ask number of clients/users
while true; do
  read -rp "Approximate number of clients/users: " user_count
  [[ "$user_count" =~ ^[0-9]+$ ]] && (( user_count > 0 )) && break
  echo "  → Please enter a positive integer."
done

# -- 6) Map to per‑user daily log volume (MB)
declare mb_per_user
if [[ $deployment == "soho" ]]; then
  case $profile in
    heavy)    mb_per_user=30  ;;
    moderate) mb_per_user=15  ;;
    light)    mb_per_user=5   ;;
  esac
else  # home
  case $profile in
    heavy)    mb_per_user=100 ;;
    moderate) mb_per_user=50  ;;
    light)    mb_per_user=20  ;;
  esac
fi

# -- 7) Compute total daily log volume and retention days
daily_mb=$(( user_count * mb_per_user ))
raw_retention=$(( avail_mb / daily_mb ))
if (( raw_retention > 30 )); then
  retain_days=30
elif (( raw_retention < 7 )); then
  retain_days=7
else
  retain_days=$raw_retention
fi

# -- 8) Write logrotate config with SIGHUP in postrotate
cat <<EOF | sudo tee "$ROTATE_CONF" >/dev/null
$LOG_DIR/*.log $LOG_DIR/*.json {
    daily
    rotate $retain_days
    compress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        # Tell Suricata to close & reopen logs on SIGHUP
        if [[ -f "$PID_FILE" ]]; then
          /bin/kill -HUP \$(cat "$PID_FILE") 2>/dev/null || true
        else
          /bin/kill -HUP \$(pidof suricata) 2>/dev/null || true
        fi
    endscript
}
EOF

# -- 9) Show summary
echo
echo "[INFO] Suricata logrotate configured:"
echo "       Log dir:       $LOG_DIR"
echo "       Free space:    ${avail_mb} MB"
echo "       Deployment:    ${deployment^}"
echo "       Traffic:       ${profile^}"
echo "       Clients:       $user_count"
echo "       Per‑user rate: ${mb_per_user} MB/day"
echo "       Retention:     $retain_days days"
echo

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Suricata installation and configuration complete."
    log "Suricata installation complete."
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}

install_portscan() {
    INSTALLED_SERVICES[portscan]=1
    log "Installing RFWB Portscan detection..."

    dialog --title "RFWB Portscan" --infobox "Installing RFWB-Portscan Detection engine..." 5 60
    sleep 2

    if [[ $EUID -ne 0 ]]; then
        dialog --msgbox "This script must be run as root." 6 40
        return 1
    fi

    CONFIG_FILE="/etc/rfwb-portscan.conf"
    if [ ! -f "$CONFIG_FILE" ]; then
        cat <<EOF >"$CONFIG_FILE"
MAX_RETRIES=10
INITIAL_DELAY=10
RETRY_MULTIPLIER=2
MONITORED_PORTS="20,21,23,25,53,67,68,69,110,111,119,135,137,138,139,143,161,162,179,389,445,465,514,515,587,631,636,993,995"
BLOCK_TIMEOUT="30m"
EOF
    fi
    source "$CONFIG_FILE"

    mkdir -p /etc/nftables
    touch /etc/nftables/hosts.blocked

    IGNORE_NETWORKS_FILE="/etc/nftables/ignore_networks.conf"
    if [ ! -f "$IGNORE_NETWORKS_FILE" ]; then
        cat <<EOF >"$IGNORE_NETWORKS_FILE"
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
EOF
    fi

    IGNORE_PORTS_FILE="/etc/nftables/ignore_ports.conf"
    if [ ! -f "$IGNORE_PORTS_FILE" ]; then
        echo "22,80,443" > "$IGNORE_PORTS_FILE"
    fi

    find_interface() {
        local suffix="$1"
        nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
    }

    OUTSIDE_INTERFACE=$(find_interface "-outside")
    if [[ -z "$OUTSIDE_INTERFACE" ]]; then
        dialog --msgbox "Could not determine the outside interface." 6 50
        return 1
    fi

    attempt=1
    delay=$INITIAL_DELAY
    while :; do
        EXTERNAL_IP=$(ip -4 addr show "$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
        [[ -n "$EXTERNAL_IP" ]] && break
        if [[ $MAX_RETRIES -ne 0 && $attempt -gt $MAX_RETRIES ]]; then
            dialog --msgbox "Failed to determine the external IP address after $MAX_RETRIES attempts." 6 60
            return 1
        fi
        sleep "$delay"
        ((attempt++))
        delay=$((delay * RETRY_MULTIPLIER))
    done

    PRE_START_SCRIPT="/usr/local/bin/rfwb-portscan-prestart.sh"
    cat <<EOF >"$PRE_START_SCRIPT"
#!/bin/bash
MAX_RETRIES=10
INITIAL_DELAY=5
RETRY_MULTIPLIER=2
LOG_FILE="/var/log/rfwb-portscan.log"

attempt=1
delay=\$INITIAL_DELAY
while :; do
    OUTSIDE_INTERFACE=\$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="-outside" '\$2 ~ suffix {print \$1}')
    EXTERNAL_IP=\$(ip -4 addr show "\$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
    if [[ -n "\$EXTERNAL_IP" ]]; then
        echo "\$(date): Interface: \$OUTSIDE_INTERFACE IP: \$EXTERNAL_IP" >> "\$LOG_FILE"
        break
    fi
    [[ \$attempt -ge \$MAX_RETRIES ]] && exit 1
    sleep "\$delay"
    ((attempt++))
    delay=\$((delay * RETRY_MULTIPLIER))
done
EOF
    chmod +x "$PRE_START_SCRIPT"

    STOP_SCRIPT="/usr/local/bin/rfwb-portscan-stop.sh"
    cat <<'EOF' >"$STOP_SCRIPT"
#!/bin/bash
nft flush chain inet portscan input
nft delete set inet portscan dynamic_block
nft delete table inet portscan
truncate -s 0 /etc/nftables/hosts.blocked
EOF
    chmod +x "$STOP_SCRIPT"

    HANDLER_SCRIPT="/usr/local/bin/rfwb-portscan-handler.sh"
    cat <<EOF >"$HANDLER_SCRIPT"
#!/bin/bash
source /etc/rfwb-portscan.conf
OUTSIDE_INTERFACE=\$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="-outside" '\$2 ~ suffix {print \$1}')
EXTERNAL_IP=\$(ip -4 addr show "\$OUTSIDE_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
IGNORED_PORTS=\$(grep -v '^#' "/etc/nftables/ignore_ports.conf" | tr -d '[:space:]' | tr ',' ', ')

cat <<EOL >"/etc/nftables/portscan.conf"
table inet portscan {
  set dynamic_block {
    type ipv4_addr
    flags timeout
    timeout \$BLOCK_TIMEOUT
  }
  chain input {
    type filter hook input priority filter; policy accept;
    ct state established,related accept
    ip saddr @dynamic_block drop
    ip daddr \$EXTERNAL_IP tcp dport == { \$IGNORED_PORTS } accept
    ip daddr \$EXTERNAL_IP tcp flags syn tcp dport { \$MONITORED_PORTS } limit rate 5/second burst 10 packets log prefix "Port Scan Detected: " counter
  }
}
EOL

nft -f /etc/nftables/portscan.conf
EOF
    chmod +x "$HANDLER_SCRIPT"

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

    systemctl daemon-reload
    systemctl enable rfwb-portscan.service
    systemctl start rfwb-portscan.service

    SCRIPT_PATH="/usr/local/bin/rfwb-ps-mon.sh"
    SERVICE_PATH="/etc/systemd/system/rfwb-ps-mon.service"

    cat << 'EOF' > "$SCRIPT_PATH"
#!/bin/bash
IGNORE_NETWORKS=$(cat /etc/nftables/ignore_networks.conf)
BLOCKED_FILE="/etc/nftables/hosts.blocked"

append_blocked_ip() {
    local ip="$1"
    for ignore_network in $IGNORE_NETWORKS; do
        if ipcalc -c "$ip" "$ignore_network" >/dev/null 2>&1; then
            return
        fi
    done
    if ! grep -q "^$ip$" "$BLOCKED_FILE"; then
        echo "$ip" >>"$BLOCKED_FILE"
        if nft list tables | grep -q "inet portscan"; then
            nft add element inet portscan dynamic_block { $ip }
        fi
    fi
}

journalctl -k -f | while read -r line; do
    if [[ "$line" == *"Port Scan Detected:"* ]]; then
        ip=$(echo "$line" | grep -oP 'SRC=\d+\.\d+\.\d+\.\d+' | cut -d '=' -f 2)
        [[ -n "$ip" ]] && append_blocked_ip "$ip"
    fi

done
EOF
    chmod +x "$SCRIPT_PATH"

    cat << EOF > "$SERVICE_PATH"
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
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rfwb-ps-mon

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable rfwb-ps-mon.service
    systemctl start rfwb-ps-mon.service

    dialog --infobox "RFWB Portscan and Monitoring Services Installed and Activated." 5 70
    sleep 3


    log "RFWB Portscan detection installation complete."
}
install_snmpd() {
    INSTALLED_SERVICES[snmpd]=1
    log "Installing SNMP daemon..."
    {
        echo "50"
        dnf -y install net-snmp net-snmp-utils >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing SNMP Daemon..." 10 60 0
    log "SNMP installation complete."
}

install_netdata() {
    INSTALLED_SERVICES[netdata]=1
    log "Installing Netdata..."
    {
        echo "10"
        dnf -y update >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "40"
        wget -q -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh
        sleep 0.5
        echo "70"
        sh /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry --non-interactive >> "$LOG_FILE" 2>&1
        sleep 0.5
        echo "90"
        rm -f /tmp/netdata-kickstart.sh
        sleep 0.5
        echo "100"
        sleep 0.5
    } | dialog --gauge "Installing Netdata..." 10 60 0
    log "Netdata installation complete."
}
configure_netdata() {
    echo -e "${CYAN}==>Configuring NETDATA...${TEXTRESET}"
    
    rm -f /tmp/netdata-kickstart.sh

    inside_interfaces=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    if [ -z "$inside_interfaces" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No interface with ${YELLOW}'-inside'${TEXTRESET} profile found. Exiting..."
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
        if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 19999 accept"; then
            sudo nft add rule inet filter input iifname "$iface" tcp dport 19999 accept
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow Netdata on port 19999 for interface ${GREEN}$iface${TEXTRESET}"
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow Netdata on port 19999 for interface ${GREEN}$iface${TEXTRESET}"
        fi
    done

    rfwb_status=$(systemctl is-active rfwb-portscan)
    if [ "$rfwb_status" == "active" ]; then
        systemctl stop rfwb-portscan
    fi

    sudo nft list ruleset > /etc/sysconfig/nftables.conf
    sudo systemctl restart nftables

    if [ "$rfwb_status" == "active" ]; then
        systemctl start rfwb-portscan
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}NETDATA Configured Successfully!${TEXTRESET}"
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}

install_qos() {
    INSTALLED_SERVICES[qos]=1
    log "Installing RFWB QoS for Voice..."

    dialog --title "RFWB QoS" --infobox "Installing RFWB QoS for Voice with 10% reserved bandwidth..." 6 60
    sleep 2

    CONFIG_FILE="/etc/rfwb-qos.conf"
    SCRIPT_FILE="/usr/local/bin/rfwb-qos.sh"
    SERVICE_FILE="/etc/systemd/system/rfwb-qos.service"
    TIMER_FILE="/etc/systemd/system/rfwb-qos.timer"
    LOG_FILE="/var/log/rfwb-qos.log"
    ERROR_LOG_FILE="/var/log/rfwb-qos-errors.log"

    mkdir -p /etc/nftables

    cat <<EOF > "$CONFIG_FILE"
percentage_bandwidth = 10
adjust_interval_hours = 0.25
wifi_calling_ports = 500,4500
sip_ports = 5060
rtp_ports = 10000-20000
rtsp_ports = 554,8554
h323_port = 1720
webrtc_ports = 16384-32767
mpeg_ts_port = 1234
EOF


    cat << 'EOF' > "$SCRIPT_FILE"
#!/bin/bash
CONFIG_FILE="/etc/rfwb-qos.conf"
LOG_FILE="/var/log/rfwb-qos.log"
ERROR_LOG_FILE="/var/log/rfwb-qos-errors.log"

load_config() {
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
    OUTSIDE_INTERFACE=$(find_interface "-outside")
    [ -z "$OUTSIDE_INTERFACE" ] && echo "No outside interface found." | tee -a "$ERROR_LOG_FILE" && exit 1

    echo "Running speed test..." | tee -a "$LOG_FILE"
    speedtest_output=$(speedtest --format=json 2>>"$ERROR_LOG_FILE") || {
        echo "Speedtest failed." | tee -a "$ERROR_LOG_FILE"
        exit 1
    }

    DOWNLOAD_SPEED=$(echo "$speedtest_output" | jq '.download.bandwidth')
    UPLOAD_SPEED=$(echo "$speedtest_output" | jq '.upload.bandwidth')

    DOWNLOAD_SPEED_KBIT=$((DOWNLOAD_SPEED * 8 / 1000))
    UPLOAD_SPEED_KBIT=$((UPLOAD_SPEED * 8 / 1000))

    [[ $DOWNLOAD_SPEED_KBIT -lt 10000 ]] && R2Q_VALUE=1 || [[ $DOWNLOAD_SPEED_KBIT -lt 100000 ]] && R2Q_VALUE=2 || R2Q_VALUE=10

    CEIL_DOWNLOAD=$((DOWNLOAD_SPEED_KBIT / 1000 - 1))
    CEIL_UPLOAD=$((UPLOAD_SPEED_KBIT / 1000 - 1))

    RESERVED_DOWNLOAD_BANDWIDTH=$((CEIL_DOWNLOAD * 1000 * percentage_bandwidth / 100))
    RESERVED_UPLOAD_BANDWIDTH=$((CEIL_UPLOAD * 1000 * percentage_bandwidth / 100))

    tc qdisc del dev "$OUTSIDE_INTERFACE" root 2>>"$ERROR_LOG_FILE" || true
    tc qdisc add dev "$OUTSIDE_INTERFACE" root handle 1: htb default 20 r2q "$R2Q_VALUE" 2>>"$ERROR_LOG_FILE"
    tc class add dev "$OUTSIDE_INTERFACE" parent 1: classid 1:1 htb rate ${CEIL_DOWNLOAD}Mbit ceil ${CEIL_DOWNLOAD}Mbit
    tc class add dev "$OUTSIDE_INTERFACE" parent 1: classid 1:2 htb rate ${CEIL_UPLOAD}Mbit ceil ${CEIL_UPLOAD}Mbit

    for port in ${wifi_calling_ports//,/ }; do
        tc filter add dev "$OUTSIDE_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dport "$port" 0xffff flowid 1:1
    done
    for port in ${sip_ports//,/ }; do
        tc filter add dev "$OUTSIDE_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dport "$port" 0xffff flowid 1:1
    done

    echo "QoS applied on $OUTSIDE_INTERFACE" | tee -a "$LOG_FILE"
    tc -s class show dev "$OUTSIDE_INTERFACE" | tee -a "$LOG_FILE"
}

configure_qos
EOF
    chmod +x "$SCRIPT_FILE"

    cat <<EOF > "$SERVICE_FILE"
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

    cat <<EOF > "$TIMER_FILE"
[Unit]
Description=Run RFWB QoS Service every 15 minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable rfwb-qos.service
    systemctl start rfwb-qos.service
    systemctl enable rfwb-qos.timer
    systemctl start rfwb-qos.timer

    dialog --title "QoS Installation" --infobox "RFWB QoS for Voice Installed with 10% reserved bandwidth." 5 70
    sleep 3
    log "RFWB QoS for Voice installation complete."
}
#Function to configure snmpd
configure_snmpd() {
    echo -e "${CYAN}==>Configuring SNMP daemon...${TEXTRESET}"
    sleep 4
    # Function to validate IP address or network
    function validate_ip_or_network() {
        local ip_network=$1
        if [[ $ip_network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$ ]]; then
            IFS='/' read -r ip prefix <<<"$ip_network"
            for octet in $(echo $ip | tr '.' ' '); do
                if ((octet < 0 || octet > 255)); then
                    echo -e "[${RED}ERROR${TEXTRESET}] Invalid IP address or network: ${YELLOW}$ip_network${TEXTRESET}"
                    return 1
                fi
            done
            if [ -n "$prefix" ] && ((prefix < 0 || prefix > 32)); then
                echo -e "[${RED}ERROR${TEXTRESET}] Invalid prefix length: ${YELLOW}$prefix${TEXTRESET}"
                return 1
            fi
            return 0
        else
            echo -e "[${RED}ERROR${TEXTRESET}] Invalid IP address or network format: ${YELLOW}$ip_network${TEXTRESET}"
            return 1
        fi
    }

    # Function to locate the server's private IP address using nmcli
    find_private_ip() {
        # Find the interface ending with -inside
        interface=$(nmcli device status | awk '/-inside/ {print $1}')

        if  [ -z "$interface" ]; then
            echo -e "[${RED}ERROR${TEXTRESET}] No interface ending with ${YELLOW}'-inside'${TEXTRESET} found."
            exit 1
        fi

        # Extract the private IP address for the found interface
        ip=$(nmcli -g IP4.ADDRESS device show "$interface" | awk -F/ '{print $1}')

        if [ -z "$ip" ]; then
            echo -e "[${RED}ERROR${TEXTRESET}] No IP address found for the interface ${GREEN}$interface.${TEXTRESET}"
            exit 1
        fi
        echo -e "[${YELLOW}INFO${TEXTRESET}] Getting IP.."
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] $interface"
    }

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
            echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow SNMP (UDP) on interface ${GREEN}$iface${TEXTRESET}"
        else
            echo-e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow SNMP (UDP) on interface ${GREEN}$iface${TEXTRESET}"
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
    systemctl start snmpd
    systemctl enable snmpd

    # Validate that the service is running
    if systemctl status snmpd | grep "active (running)" >/dev/null; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] SNMP service is running successfully.${TEXTRESET}"
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to start SNMP service. Please check the configuration.${TEXTRESET}"
    fi
    # Continue with the rest of the script
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}SNMP Daemon Configured Successfully!${TEXTRESET}"
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}
configure_bind_and_kea () {
# Define file paths and directories
NAMED_CONF="/etc/named.conf"
KEYS_FILE="/etc/named/keys.conf"
ZONE_DIR="/var/named/"

generate_tsig_key() {
    echo -e "[${YELLOW}INFO${TEXTRESET}] Generating TSIG key using rndc-confgen..."

    # Generate an rndc key using rndc-confgen
    sudo rndc-confgen -a

    # The key will be generated and stored in /etc/rndc.key by default
    key_file="/etc/rndc.key"

    # Extract the key secret
    key_secret=$(grep secret $key_file | awk '{print $2}' | tr -d '";')

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Key generated: ${GREEN}$key_secret${TEXTRESET}"

    # Append the key to keys.conf
    sudo bash -c "cat > $KEYS_FILE" <<EOF
key "Kea-DDNS" {
    algorithm hmac-sha256;
    secret "$key_secret";
};
EOF
}

configure_bind() {

    # Extract domain and hostname
    full_hostname=$(hostnamectl status | awk '/Static hostname:/ {print $3}')

    if [[ ! "$full_hostname" == *.* ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Hostname does not contain a domain part.${TEXTRESET}"
        return 1
    fi

    hostname="${full_hostname%%.*}"
    domain="${full_hostname#*.}"

    # Get the server's IP address (IPv4 assumed here)
    ip_address=$(hostname -I | awk '{print $1}')

    if [[ -z "$ip_address" ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Unable to determine IP address."
        return 1
    fi

    reverse_zone=$(echo $ip_address | awk -F. '{print $3"."$2"."$1}')
    reverse_ip=$(echo $ip_address | awk -F. '{print $4}')

    # Check if variables are set correctly
    if [[ -z "$domain" || -z "$reverse_zone" || -z "$reverse_ip" ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Domain or reverse zone information is missing."
        return 1
    fi

    # Create forward and reverse zone files
    forward_zone_file="${ZONE_DIR}db.${domain}"
    reverse_zone_file="${ZONE_DIR}db.${reverse_zone}"

    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring BIND with forward and reverse zones..."

    # Insert forwarders configuration right after the crypto policy include line
    sudo sed -i '/include "\/etc\/crypto-policies\/back-ends\/bind.config";/a \
forwarders {\n\
    208.67.222.222;\n\
    208.67.220.220;\n\
};\n\
forward only;' $NAMED_CONF

    # Append zone configurations at the bottom of named.conf
    sudo bash -c "cat >> $NAMED_CONF" <<EOF

include "$KEYS_FILE";

zone "$domain" {
    type master;
    file "$forward_zone_file";
    allow-update { key "Kea-DDNS"; };
};

zone "${reverse_zone}.in-addr.arpa" {
    type master;
    file "$reverse_zone_file";
    allow-update { key "Kea-DDNS"; };
};
EOF

    # Modify existing configuration in named.conf
    sudo sed -i '/listen-on port 53 {/s/{ 127.0.0.1; }/{ 127.0.0.1; any; }/' $NAMED_CONF
    sudo sed -i 's/allow-query[[:space:]]*{[[:space:]]*localhost;[[:space:]]*};/allow-query { localhost; any; };/' $NAMED_CONF

    # Create forward zone file
    sudo bash -c "cat > $forward_zone_file" <<EOF
\$TTL 86400
@   IN  SOA   $full_hostname. admin.$domain. (
    2023100501 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
@   IN  NS    $full_hostname.
$hostname IN  A     $ip_address
EOF

    # Create reverse zone file
    sudo bash -c "cat > $reverse_zone_file" <<EOF
\$TTL 86400
@   IN  SOA   $full_hostname. admin.$domain. (
    2023100501 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
@   IN  NS    $full_hostname.
$reverse_ip  IN  PTR   $full_hostname.
EOF

    # Set file permissions
    sudo chown root:named $NAMED_CONF $forward_zone_file $reverse_zone_file $KEYS_FILE
    sudo chmod 640 $NAMED_CONF $forward_zone_file $reverse_zone_file $KEYS_FILE
    semanage boolean -m --on named_write_master_zones
    chown named:named $forward_zone_file $reverse_zone_file
    chmod g+w /var/named
    # Define the file path
    RNDC_KEY_FILE="/etc/rndc.key"

    # Check if the file exists
    if [[ -f "$RNDC_KEY_FILE" ]]; then
        # Change the ownership to 'named' user and group
        chown named:named "$RNDC_KEY_FILE"

        # Set the permissions to 600
        chmod 600 "$RNDC_KEY_FILE"

        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Permissions and ownership for ${GREEN}$RNDC_KEY_FILE${TEXTRESET} have been set."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] $RNDC_KEY_FILE does not exist."
        exit 1
    fi

    # Check SELinux status and provide guidance
    SELINUX_STATUS=$(getenforce)
    if [[ "$SELINUX_STATUS" != "Enforcing" ]]; then
        echo "SELinux is currently set to $SELINUX_STATUS."
    else
        echo " "
    fi

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] BIND configuration complete."
    sleep 3
}

start_and_enable_service() {
    local service_name="$1"

    echo -e "[${YELLOW}INFO${TEXTRESET}]Enabling and starting the ${GREEN}$service_name${TEXTRESET} service..."

    sudo systemctl enable "$service_name"
    sudo systemctl start "$service_name"

    # Check if the service is running
    if sudo systemctl status "$service_name" | grep -q "running"; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}$service_name${TEXTRESET} service is running."
    else
        echo -e "[${RED}ERROR${TEXTRESET}] Failed to start ${GREEN}$service_name${TEXTRESET} service."
        exit 1
    fi
    sleep 2
}

# Main execution block
     echo -e "${CYAN}==>Configuring BIND...${TEXTRESET}"
if [ -f "$NAMED_CONF" ]; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] $NAMED_CONF found. Proceeding with configuration..."
    generate_tsig_key
    configure_bind
    start_and_enable_service "named"
else
    echo -e "[${YELLOW}INFO${TEXTRESET}] $NAMED_CONF not found. Skipping BIND configuration.${TEXTRESET}"
fi

 # Function to locate the inside interface and its sub-interfaces
    find_inside_interfaces() {
        main_interface=$(nmcli device status | awk '/-inside/ {print $1}')

        if [ -z "$main_interface" ]; then
            echo -e "[${RED}ERROR${TEXTRESET}] No interface with ${YELLOW}'-inside'${TEXTRESET} profile found. Exiting..."
            exit 1
        fi

        sub_interfaces=$(nmcli device status | awk -v main_intf="$main_interface" '$1 ~ main_intf "\\." {print $1}')
        inside_interfaces="$main_interface $sub_interfaces"

        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Inside interfaces found: ${GREEN}$inside_interfaces${TEXTRESET}"
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
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow DNS (UDP) on interface ${GREEN}$iface${TEXTRESET}"
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow DNS (UDP) on interface ${GREEN}$iface${TEXTRESET}"
            fi
            if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 53 accept"; then
                sudo nft add rule inet filter input iifname "$iface" tcp dport 53 accept
                echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow DNS (TCP) on interface ${GREEN}$iface${TEXTRESET}"
            else
                echo -e "[${RED}ERROR${TEXTRESET}] Rule already exists: Allow DNS (TCP) on interface ${GREEN}$iface${TEXTRESET}"
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
    }

    # Execute functions
    find_inside_interfaces
    setup_nftables_for_dns

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}BIND Configured Successfully!${TEXTRESET}"
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
#Configure DHCP
# ─────────────────────────────────────────────────────────────────
# KEA DHCP4 + DDNS + Reverse DNS Zone Installer with PTR Record
# ─────────────────────────────────────────────────────────────────
# Phase 1: Configure first subnet + base configs
# Phase 2: Loop additional subnets + DDNS zones
# Phase 3: Map interfaces + final validation
# ─────────────────────────────────────────────────────────────────

# ─── Configuration ────────────────────────────────────────────────
KEA_DHCP4_CONF="/etc/kea/kea-dhcp4.conf"
KEA_DHCP_DDNS_CONF="/etc/kea/kea-dhcp-ddns.conf"
NAMED_CONF="/etc/named.conf"
ZONE_DIR="/var/named"

# ─── Helper Functions ─────────────────────────────────────────────
validate_ip() {
  local ip=$1
  local n="(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
  [[ $ip =~ ^$n(\.$n){3}$ ]]
}

validate_cidr() {
  local cidr=$1
  local ip="${cidr%/*}"
  local prefix="${cidr#*/}"
  validate_ip "$ip" && [[ $prefix -ge 0 && $prefix -le 32 ]]
}

reverse_ip() {
  echo "$1" | awk -F. '{print $4"."$3"."$2"."$1}' | cut -d. -f2-
}

get_hostname_parts() {
  full_hostname=$(hostnamectl | awk '/Static hostname:/ {print $3}')
  domain="${full_hostname#*.}"
  hostname="${full_hostname%%.*}"
}
is_valid_standard_option() {
  local opt="$1"
  case "$opt" in
    routers|domain-name-servers|domain-search|ntp-servers|boot-file-name|tftp-server-name|host-name|vendor-class-identifier|domain-name|nis-domain|netbios-name-servers|netbios-node-type)
      return 0 ;;  # valid
    *)
      return 1 ;;  # invalid
  esac
}

# ─── Gather Subnet Info ───────────────────────────────────────────
gather_subnet_inputs() {
  local id="$1"
  echo -e "\n==> Gathering DHCP Scope Information"
  echo -n "Provide a Friendly name (description) for the subnet: "; read -r description

  while true; do
    echo -n "Enter CIDR (e.g., 192.168.10.0/24): "; read -r CIDR
    validate_cidr "$CIDR" && break || echo "[ERROR] Invalid CIDR format."
  done

  IFS='/' read -r subnet _ <<< "$CIDR"
  IFS='.' read -r o1 o2 o3 _ <<< "$subnet"
  default_start="$o1.$o2.$o3.10"
  default_end="$o1.$o2.$o3.100"
  default_router="$o1.$o2.$o3.1"

  echo -n "Start IP [$default_start]: "; read -r pool_start
  pool_start=${pool_start:-$default_start}

  echo -n "End IP [$default_end]: "; read -r pool_end
  pool_end=${pool_end:-$default_end}

  echo -n "Router IP [$default_router]: "; read -r router
  router=${router:-$default_router}

  interface=$(nmcli device status | awk '/-inside/ {print $1; exit}')
  dns="$router"

  get_hostname_parts
  domain_suffix="$domain"

  EXTRA_OPTIONS=()
  echo -n "Add custom DHCP options? [y/N]: "; read -r add_opts
  if [[ "$add_opts" =~ ^[Yy]$ ]]; then
    while true; do
      echo "0) Exit"
echo "1) Standard option"
echo "2) Advanced option"
echo "? for help"
echo -n "#? "; read -r opt_type

if [[ "$opt_type" == "0" ]]; then
  break
elif [[ "$opt_type" == "?" ]]; then
  echo ""
  echo "Supported DHCP Options:"
  echo ""
  echo "Standard (Common) Options (by name):"
  echo "  - routers"
  echo "  - domain-name-servers"
  echo "  - domain-search"
  echo "  - ntp-servers"
  echo "  - boot-file-name"
  echo "  - tftp-server-name"
  echo "  - host-name"
  echo "  - vendor-class-identifier"
  echo "  - domain-name"
  echo "  - nis-domain"
  echo "  - netbios-name-servers"
  echo "  - netbios-node-type"
  echo ""
  echo "Advanced (Common) Options (by code):"
  echo "  - code 66 → tftp-server-name"
  echo "  - code 67 → boot-file-name"
  echo "  - code 150 → tftp-server address for VoIP phones"
  echo "  - code 43 → vendor-specific information"
  echo ""
  echo "[INFO] Use Standard (Common) for simple options (by name)."
  echo "[INFO] Use Advanced (Common) for custom numeric codes (VoIP, PXE boot, etc)."
  echo ""
  continue
fi

      case "$opt_type" in
           1)
  echo -n "Option name: "; read -r n
  if ! is_valid_standard_option "$n"; then
    echo "[ERROR] Invalid standard option name: $n"
    echo -e "\nSupported Standard (Common) Options:"
    echo " - routers"
    echo " - domain-name-servers"
    echo " - domain-search"
    echo " - ntp-servers"
    echo " - boot-file-name"
    echo " - tftp-server-name"
    echo " - host-name"
    echo " - vendor-class-identifier"
    echo " - domain-name"
    echo " - nis-domain"
    echo " - netbios-name-servers"
    echo " - netbios-node-type"
    continue
  fi
  echo -n "Value: "; read -r v
  EXTRA_OPTIONS+=("{\"name\": \"$n\", \"data\": \"$v\"}")
  ;;


        2)
    echo -e "\n[INFO] You selected Advanced (Common) Option."
    echo "Reminder: Use advanced options (e.g., codes 66, 67, 150) only if you know the required format."
    echo "Incorrect advanced entries may cause KEA service validation to fail."
    echo
    echo -n "Code: "; read -r c
  if ! [[ "$c" =~ ^[0-9]+$ ]]; then
    echo -e "[\e[31mERROR\e[0m] Invalid code: $c. Code must be a number."
    continue
  fi
  echo -n "Name: "; read -r n
  echo -n "Data: "; read -r v
  echo -n "Space (default: dhcp4): "; read -r s
  s=${s:-dhcp4}
  EXTRA_OPTIONS+=("{\"code\": $c, \"name\": \"$n\", \"space\": \"$s\", \"data\": \"$v\"}")
  ;;

      esac
      echo -n "Do you want to add another DHCP option? [y/N]: "; read -r again
      [[ ! "$again" =~ ^[Yy]$ ]] && break
    done
  fi
}

# ─── Build Subnet JSON ────────────────────────────────────────────
build_subnet_json() {
  local id="$1"
  EXTRA_JSON=$(IFS=,; echo "${EXTRA_OPTIONS[*]}")
  POOL_RANGE="$pool_start - $pool_end"

  jq -n \
    --arg cidr "$CIDR" \
    --arg iface "$interface" \
    --arg pool "$POOL_RANGE" \
    --arg desc "$description" \
    --arg router "$router" \
    --arg dns "$dns" \
    --arg dom "$domain_suffix" \
    --argjson id "$id" \
    --argjson extras "[${EXTRA_JSON:-}]" '
{
  comment: $desc,
  id: $id,
  subnet: $cidr,
  interface: $iface,
  pools: [ { pool: $pool } ],
  "option-data": (
    [
      { name: "routers", data: $router },
      { name: "domain-name-servers", data: $dns },
      { name: "ntp-servers", data: $dns },
      { name: "domain-search", data: $dom },
      { name: "domain-name", data: $dom }
    ] + $extras
  )
}'
}

# ─── Phase 1: Initial Setup ────────────────────────────────────────
id=1
echo -e "\n==> Configuring ISC-KEA Phase 1"
gather_subnet_inputs $id

# After gathering EXTRA_OPTIONS, fix for hex value issue
for i in "${!EXTRA_OPTIONS[@]}"; do
  if [[ ${EXTRA_OPTIONS[$i]} == *\"code\":* ]]; then
    hex_data=$(printf '%02x' $(echo "$router" | tr '.' ' '))
    EXTRA_OPTIONS[$i]=$(echo "${EXTRA_OPTIONS[$i]}" | sed "s/\"data\": \"[^\"]*\"/\"data\": \"$hex_data\"/")
  fi
done

build_subnet_json $id > /tmp/subnet${id}.json
subnet_json=$(< /tmp/subnet${id}.json)

# Create DDNS Config
ts_key=$(grep secret /etc/rndc.key | awk '{print $2}' | tr -d '";')

jq -n \
  --arg domain "$domain_suffix." \
  --arg reverse "$(reverse_ip "${CIDR%/*}").in-addr.arpa." \
  --arg secret "$ts_key" '
{
  DhcpDdns: {
    "ip-address": "127.0.0.1",
    port: 53001,
    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/tmp/kea-ddns-ctrl-socket"
    },
    "dns-server-timeout": 500,
    "ncr-format": "JSON",
    "ncr-protocol": "UDP",
    "forward-ddns": {
      "ddns-domains": [
        { name: $domain, "key-name": "Kea-DDNS", "dns-servers": [ { "ip-address": "127.0.0.1", port: 53 } ] }
      ]
    },
    "reverse-ddns": {
      "ddns-domains": [
        { name: $reverse, "key-name": "Kea-DDNS", "dns-servers": [ { "ip-address": "127.0.0.1", port: 53 } ] }
      ]
    },
    "tsig-keys": [
      { name: "Kea-DDNS", algorithm: "HMAC-SHA256", secret: $secret }
    ]
  }
}' > "$KEA_DHCP_DDNS_CONF"

chmod 640 "$KEA_DHCP_DDNS_CONF"
chown root:kea "$KEA_DHCP_DDNS_CONF"
restorecon "$KEA_DHCP_DDNS_CONF"

# Create DHCP4 Config
jq -n \
  --argjson subnet "$subnet_json" \
  --arg iface "$interface" \
  --arg suffix "$domain_suffix" '
{
  Dhcp4: {
    "interfaces-config": {
      interfaces: [ $iface ]
    },
    "lease-database": {
      type: "memfile",
      persist: true,
      name: "/var/lib/kea/kea-leases4.csv"
    },
    "dhcp-ddns": {
      "enable-updates": true,
      "server-ip": "127.0.0.1",
      "server-port": 53001,
      "sender-ip": "127.0.0.1",
      "sender-port": 53000,
      "max-queue-size": 1024,
      "ncr-protocol": "UDP",
      "ncr-format": "JSON"
    },
    "ddns-qualifying-suffix": $suffix,
    "ddns-override-client-update": true,
    "ddns-override-no-update": true,
    "ddns-update-on-renew": true,
    "ddns-generated-prefix": "dynamic",
    "ddns-replace-client-name": "always",
    authoritative: true,
    subnet4: [ $subnet ]
  }
}' > "$KEA_DHCP4_CONF"

chmod 640 "$KEA_DHCP4_CONF"
chown root:kea "$KEA_DHCP4_CONF"
restorecon "$KEA_DHCP4_CONF"

# Create Reverse DNS Zone
rev_zone=$(reverse_ip "${CIDR%/*}")
zone_file="$ZONE_DIR/db.$rev_zone"

if ! grep -q "zone \"$rev_zone.in-addr.arpa\"" "$NAMED_CONF"; then
  echo -e "\nzone \"$rev_zone.in-addr.arpa\" {\n  type master;\n  file \"$zone_file\";\n  allow-update { key \"Kea-DDNS\"; };\n};\n" >> "$NAMED_CONF"
  cat > "$zone_file" <<EOF
\$TTL 86400
@   IN  SOA   ${hostname}.${domain}. admin.${domain}. (
    2024042501 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
@   IN  NS    ${hostname}.${domain}.
EOF
  chown named:named "$zone_file"
  chmod 640 "$zone_file"
  restorecon "$zone_file"
fi

# ─── Continues to Phase 2 and Phase 3 exactly as discussed ───


# ─── Phase 2: Add Additional Subnets ─────────────────────────────
while true; do
  echo -n "Add another subnet? [y/N]: "; read -r more
  [[ "$more" =~ ^[Yy]$ ]] || break
  ((id++))
  gather_subnet_inputs $id

  # After gathering, fix hex for advanced options
  for i in "${!EXTRA_OPTIONS[@]}"; do
    if [[ ${EXTRA_OPTIONS[$i]} == *\"code\":* ]]; then
      hex_data=$(printf '%02x' $(echo "$router" | tr '.' ' '))
      EXTRA_OPTIONS[$i]=$(echo "${EXTRA_OPTIONS[$i]}" | sed "s/\"data\": \"[^\"]*\"/\"data\": \"$hex_data\"/")
    fi
  done

  build_subnet_json $id > /tmp/subnet${id}.json
  subnet_json=$(< /tmp/subnet${id}.json)

  # Append new subnet to kea-dhcp4.conf
  jq --argjson newsubnet "$subnet_json" '.Dhcp4.subnet4 += [$newsubnet]' "$KEA_DHCP4_CONF" > /tmp/kea.tmp && mv /tmp/kea.tmp "$KEA_DHCP4_CONF"
  chmod 640 "$KEA_DHCP4_CONF"
  chown root:kea "$KEA_DHCP4_CONF"
  restorecon "$KEA_DHCP4_CONF"

  # Validate config
  if kea-dhcp4 -t "$KEA_DHCP4_CONF"; then
    echo -e "[SUCCESS] New subnet validated and added."
  else
    echo -e "[ERROR] Validation failed after adding new subnet. Exiting."
    exit 1
  fi

  # Update DDNS reverse zone if needed
  rev_zone="$(reverse_ip "${CIDR%/*}")"
  existing=$(jq --arg zone "$rev_zone.in-addr.arpa." '.DhcpDdns["reverse-ddns"]["ddns-domains"][]? | select(.name == $zone)' "$KEA_DHCP_DDNS_CONF")
  if [[ -z "$existing" ]]; then
    jq --arg zone "$rev_zone.in-addr.arpa." '.DhcpDdns["reverse-ddns"]["ddns-domains"] += [
      { "name": $zone, "key-name": "Kea-DDNS", "dns-servers": [ { "ip-address": "127.0.0.1", "port": 53 } ] }
    ]' "$KEA_DHCP_DDNS_CONF" > /tmp/ddns.tmp && mv /tmp/ddns.tmp "$KEA_DHCP_DDNS_CONF"
    chmod 640 "$KEA_DHCP_DDNS_CONF"
    chown root:kea "$KEA_DHCP_DDNS_CONF"
    restorecon "$KEA_DHCP_DDNS_CONF"
    echo -e "[INFO] Added $rev_zone.in-addr.arpa. to kea-dhcp-ddns.conf."
  else
    echo -e "[INFO] Reverse zone $rev_zone.in-addr.arpa. already exists in DDNS config."
  fi

  # ─── Phase 2: Additional Subnet Handling ─────────────────────────

# Create Reverse DNS Zone and zone file if needed
zone_file="$ZONE_DIR/db.$rev_zone"

# Add named.conf entry if missing
if ! grep -q "zone \"$rev_zone.in-addr.arpa\"" "$NAMED_CONF"; then
  echo -e "\nzone \"$rev_zone.in-addr.arpa\" {\n  type master;\n  file \"$zone_file\";\n  allow-update { key \"Kea-DDNS\"; };\n};\n" >> "$NAMED_CONF"
  restorecon "$NAMED_CONF"
fi

# Ensure zone file exists (create headers if missing)
if [ ! -f "$zone_file" ]; then
  cat > "$zone_file" <<EOF
\$TTL 86400
@   IN  SOA   ${hostname}.${domain}. admin.${domain}. (
    2024042501 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
@   IN  NS    ${hostname}.${domain}.
EOF
  chown named:named "$zone_file"
  chmod 640 "$zone_file"
  restorecon "$zone_file"
fi

# Always append the router PTR record
octet=$(echo "$router" | awk -F. '{print $4}')
echo "${octet}   IN PTR   ${hostname}.${domain}." >> "$zone_file"

chown named:named "$zone_file"
chmod 640 "$zone_file"
restorecon "$zone_file"
restorecon "$NAMED_CONF"

echo -e "[INFO] Created reverse zone file $zone_file and updated named.conf."


# ─── Phase 3: Interface Assignment ───────────────────────────────

echo -e "\n==> Phase 3: Assign Interfaces to Subnets"

# Gather available interfaces (-inside and VLAN subinterfaces)
find_interfaces() {
  local suffix="$1"
  nmcli -t -f DEVICE,CONNECTION device status | awk -F: -v suffix="$suffix" '$2 ~ suffix {print $1}'
}

INSIDE_INTERFACE=$(find_interfaces "-inside")
SUB_INTERFACES=$(nmcli -t -f DEVICE device status | grep -E "${INSIDE_INTERFACE}\\.[0-9]+")
INTERFACES=($INSIDE_INTERFACE $SUB_INTERFACES)

CONFIG_FILE="${KEA_DHCP4_CONF:-/etc/kea/kea-dhcp4.conf}"
if [ ! -f "$CONFIG_FILE" ]; then
  echo -e "[ERROR] Configuration file not found: $CONFIG_FILE"
  exit 1
fi

# Extract subnet list from config
mapfile -t SUBNETS < <(jq -r '.Dhcp4.subnet4[].subnet' "$CONFIG_FILE")

if [ "${#SUBNETS[@]}" -eq 0 ]; then
  echo -e "[WARN] No subnets found in configuration."
  exit 0
fi

# ─── Interface Mapping with Confirmation, Validation, and Redisplay ──────────────
while true; do
  echo -e "\n[INFO] Available Interfaces:"
  for i in "${!INTERFACES[@]}"; do
    ip=$(nmcli -g IP4.ADDRESS device show "${INTERFACES[$i]}" | head -n1)
    echo "  [$i] ${INTERFACES[$i]} (${ip%%/*})"
  done

  ASSIGNED=()
  for j in "${!SUBNETS[@]}"; do
    echo -e "\n[INFO] Subnet ${SUBNETS[$j]}"
    while true; do
  read -p "Select interface index to bind to this subnet: " sel
  if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -lt "${#INTERFACES[@]}" ]; then
    chosen_iface="${INTERFACES[$sel]}"
    ASSIGNED+=("$chosen_iface")
    break
  else
    echo -e "[\e[31mERROR\e[0m] Invalid selection. Please choose a valid index."
  fi
done
done

  echo -e "\n[REVIEW] Subnet to Interface Selections:"
  for j in "${!SUBNETS[@]}"; do
    echo "  ${SUBNETS[$j]} → ${ASSIGNED[$j]}"
  done

  echo
  read -p "Confirm these mappings? [y/N]: " confirm_mappings
  if [[ "$confirm_mappings" =~ ^[Yy]$ ]]; then
    break
  else
    echo -e "\n[INFO] Restarting interface selection..."
    sleep 2
  fi
done



# ─── Apply Confirmed Interface Mapping ───────────────────────────
for j in "${!SUBNETS[@]}"; do
  jq --arg subnet "${SUBNETS[$j]}" --arg iface "${ASSIGNED[$j]}" '(.Dhcp4.subnet4[] | select(.subnet == $subnet) | .interface) = $iface' "$CONFIG_FILE" > /tmp/kea_iface.tmp && mv /tmp/kea_iface.tmp "$CONFIG_FILE"
done

# Check if any subnets left unassigned (fallback)
if [ ${#SUBNETS[@]} -gt ${#ASSIGNED[@]} ]; then
  ip_fallback=$(nmcli -g IP4.ADDRESS device show "$INSIDE_INTERFACE" | head -n1 | cut -d/ -f1)
  echo -e "\n[WARN] Some subnets not assigned. Assigning to $INSIDE_INTERFACE ($ip_fallback)."
  sleep 3
  for j in "${!SUBNETS[@]}"; do
    if ! grep -q "${SUBNETS[$j]}" <<< "${ASSIGNED[*]}"; then
      jq --arg subnet "${SUBNETS[$j]}" --arg iface "$INSIDE_INTERFACE" '(.Dhcp4.subnet4[] | select(.subnet == $subnet) | .interface) = $iface' "$CONFIG_FILE" > /tmp/kea_iface_fallback.tmp && mv /tmp/kea_iface_fallback.tmp "$CONFIG_FILE"
    fi
  done
fi

# ─── Print Mapping Summary ──────────────────────────────────────
echo -e "\n[SUMMARY] Final Subnet to Interface Mapping:"
for subnet in "${SUBNETS[@]}"; do
  iface=$(jq -r --arg subnet "$subnet" '.Dhcp4.subnet4[] | select(.subnet == $subnet) | .interface' "$CONFIG_FILE")
  echo -e "  $subnet  →  $iface"
done
read -p $'\nPress [Enter] to continue...' _

# ─── Update interfaces array at top level ────────────────────────
current_list=$(jq -r '.Dhcp4."interfaces-config".interfaces[]' "$CONFIG_FILE")
for chosen in "${INTERFACES[@]}"; do
  if ! grep -q "$chosen" <<< "$current_list"; then
    current_list+=$'\n'"$chosen"
  fi
done

updated_list=$(echo "$current_list" | sort -u | jq -R . | jq -s .)
jq --argjson updated "$updated_list" '.Dhcp4."interfaces-config".interfaces = $updated' "$CONFIG_FILE" > /tmp/kea_final_iface.tmp && mv /tmp/kea_final_iface.tmp "$CONFIG_FILE"

# ─── Final validation ────────────────────────────────────────────
echo -e "\n==> Final Validation of Configs"
if kea-dhcp4 -t "$CONFIG_FILE"; then
  echo -e "[SUCCESS] Final config validated successfully."
else
  echo -e "[ERROR] Final validation failed!"
  exit 1
fi


# Restart services
for svc in kea-dhcp-ddns kea-dhcp4; do
  echo -e "[INFO] Restarting service: $svc"
  if systemctl restart "$svc" && systemctl is-active --quiet "$svc"; then
    echo -e "[SUCCESS] $svc is running."
  else
    echo -e "[ERROR] Failed to restart or activate $svc."
  fi
done

# Reload named (only if running and config valid)
echo -e "[INFO] Checking named configuration before reload..."

if named-checkconf; then
  echo -e "[SUCCESS] named.conf validated."
  if systemctl is-active --quiet named; then
    echo -e "[INFO] Reloading named.service to pick up new zones..."
    if systemctl reload named; then
      echo -e "[SUCCESS] named.service reloaded."
    else
      echo -e "[ERROR] Failed to reload named.service. Manual check recommended."
    fi
  else
    echo -e "[WARN] named.service not active. Skipping reload."
  fi
else
  echo -e "[ERROR] named.conf validation failed. Please fix issues before starting/reloading named."
fi

# === Allow DHCP traffic on assigned interfaces ===
echo -e "\n[${CYAN}INFO${TEXTRESET}] Ensuring DHCP traffic is allowed on assigned interfaces..."

sudo systemctl enable nftables >/dev/null 2>&1
sudo systemctl start nftables >/dev/null 2>&1

if ! sudo nft list tables | grep -q 'inet filter'; then
  sudo nft add table inet filter
fi

if ! sudo nft list chain inet filter input &>/dev/null; then
  sudo nft add chain inet filter input { type filter hook input priority 0 \; }
fi

rfwb_status=$(systemctl is-active rfwb-portscan)
if [ "$rfwb_status" == "active" ]; then
  echo -e "[${YELLOW}INFO${TEXTRESET}] Temporarily stopping rfwb-portscan..."
  systemctl stop rfwb-portscan
fi

for iface in "${INTERFACES[@]}"; do
  for proto in udp tcp; do
    if ! sudo nft list chain inet filter input | grep -q "iifname \"$iface\" $proto dport 67 accept"; then
      sudo nft add rule inet filter input iifname "$iface" $proto dport 67 accept
      echo -e "[${GREEN}SUCCESS${TEXTRESET}] Rule added: Allow DHCP (${proto^^}) on ${GREEN}$iface${TEXTRESET}"
    else
      echo -e "[${YELLOW}INFO${TEXTRESET}] Rule already exists: DHCP (${proto^^}) on ${GREEN}$iface${TEXTRESET}"
    fi
  done
done

sudo nft list ruleset > /etc/sysconfig/nftables.conf
sudo systemctl restart nftables

if [ "$rfwb_status" == "active" ]; then
  echo -e "[${YELLOW}INFO${TEXTRESET}] Restarting rfwb-portscan..."
  systemctl start rfwb-portscan
fi
echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}




configure_evebox () {
echo -e "${CYAN}==>Configuring EVEBOX...${TEXTRESET}"
mkdir -p /etc/evebox/
    # Define configuration file path
    CONFIG_FILE="/etc/evebox/evebox.yaml"

    # Backup existing configuration file if it exists
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "[${YELLOW}INFO${TEXTRESET}] Backing up existing configuration file..."
        cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
    fi

    # Write new configuration to evebox.yaml including all remarks
    echo -e "[${YELLOW}INFO${TEXTRESET}] Writing new configuration to ${GREEN}$CONFIG_FILE...${TEXTRESET}"
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

    # Create evebox-agent systemd service
    echo "Creating evebox-agent systemd service..."
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
    echo -e "[${YELLOW}INFO${TEXTRESET}] Setting Group permissions with Suricata"
    sudo usermod -aG suricata evebox
    sudo usermod -aG evebox suricata
    #Make sure logrotate is happy
    echo -e "[${YELLOW}INFO${TEXTRESET}] Setting Log permissions for Logs files"
    sudo chown -R suricata:suricata /var/log/suricata
    sudo chmod 750 /var/log/suricata
    sudo find /var/log/suricata -type f -exec chmod 640 {} \;
    #restart suricata
    systemctl restart suricata
    sleep 2
    # Enable and start the EveBox and evebox-agent services
    echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling and starting the EveBox and evebox-agent services..."
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
    }

    # Configure nftables to allow TCP traffic on port 5636
    configure_nftables

   # Capture administrator credentials from /var/log/messages

echo -e "[${YELLOW}INFO${TEXTRESET}] Capturing administrator credentials from /var/log/messages..."
sleep 5
# Remove ANSI color codes and extract the latest matching log entry
credentials=$(tail -n 500 /var/log/messages | sed 's/\x1B\[[0-9;]*m//g' | grep "Created administrator username and password" | tail -n 1)
if [[ $credentials =~ username=([a-zA-Z0-9]+),\ password=([a-zA-Z0-9]+) ]]; then
    admin_user="${BASH_REMATCH[1]}"
    admin_pass="${BASH_REMATCH[2]}"
    echo "username=$admin_user, password=$admin_pass" > /root/evebox_credentials
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Credentials captured and saved to ${GREEN}/root/evebox_credentials.${TEXTRESET}"
    echo -e "Your username is: ${GREEN}$admin_user${TEXTRESET} and your password is: ${GREEN}$admin_pass${TEXTRESET}"
else
    echo -e "[${RED}ERROR${TEXTRESET}] Failed to capture administrator credentials from logs.${TEXTRESET}"
fi



    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}evebox and evebox-agent Configured Successfully${TEXTRESET}"
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
    
}



configure_services() {
configure_time  # Always configure chrony, even if not selected
configure_fail2ban # Always configure not user optional
    for service in "${!INSTALLED_SERVICES[@]}"; do
        case "$service" in
            net_services) configure_bind_and_kea ;;
            cockpit) configure_cockpit ;;
            ntopng) configure_ntopng ;;
            ddclient) configure_ddclient ;;
            suricata) configure_suricata ;;
            snmpd) configure_snmpd ;;
            netdata) configure_netdata ;;
            avahi) configure_avahi ;;
            evebox) configure_evebox ;;
            openvpn) configure_ovpn ;;
        esac
    done
}

#========POST INSTALLATION AND CLEANUP
echo -e "${CYAN}==>STARTING POST INSTALL CLEANUP${TEXTRESET}"
configure_dnf_automatic () {
# Install and configure dnf-automatic for security updates only
echo -e "${CYAN}==>Configuring system for security updates only...${TEXTRESET}"

EPEL_CONFIG="/etc/dnf/automatic.conf"
BACKUP_CONFIG="/etc/dnf/automatic.conf.bak"
TIMER_CONFIG="/etc/systemd/system/dnf-automatic.timer.d/override.conf"

echo -e "[${YELLOW}INFO${TEXTRESET}] Backing up the current dnf-automatic configuration..."
sudo cp "$EPEL_CONFIG" "$BACKUP_CONFIG"

echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring dnf-automatic for security updates..."
sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' "$EPEL_CONFIG"
sudo sed -i 's/^apply_updates.*/apply_updates = yes/' "$EPEL_CONFIG"

# Ensure the override directory exists
sudo mkdir -p /etc/systemd/system/dnf-automatic.timer.d

# Set the update time to 3 AM
echo -e "[${YELLOW}INFO${TEXTRESET}] Setting dnf-automatic to run at 3:00 AM..."
echo -e "[Timer]\nOnCalendar=*-*-* 03:00:00" | sudo tee "$TIMER_CONFIG" > /dev/null

# Reload systemd and restart the timer
echo -e "[${YELLOW}INFO${TEXTRESET}] Reloading systemd and restarting dnf-automatic.timer..."
sudo systemctl daemon-reload
sudo systemctl enable --now dnf-automatic.timer

# Validate the configuration
echo -e "[${YELLOW}INFO${TEXTRESET}] Validating configuration..."
CONFIG_CHECK=$(grep -E 'upgrade_type|apply_updates' "$EPEL_CONFIG")

if echo "$CONFIG_CHECK" | grep -q "apply_updates = yes"; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] dnf-automatic is correctly configured to apply security updates."
else
    echo -e "[${RED}ERROR${TEXTRESET}] Configuration failed! Check $EPEL_CONFIG manually."
    exit 1
fi

# Validate the timer status
echo -e "[${YELLOW}INFO${TEXTRESET}] Checking dnf-automatic.timer status..."
if systemctl is-active --quiet dnf-automatic.timer; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] dnf-automatic.timer is running."
else
    echo -e "[${RED}ERROR${TEXTRESET}] dnf-automatic.timer is NOT running! Check logs: journalctl -u dnf-automatic.timer"
    exit 1
fi

# Validate the new update time
echo -e "[${YELLOW}INFO${TEXTRESET}] Checking the scheduled update time..."
if systemctl show dnf-automatic.timer | grep -q "OnCalendar=.*03:00:00"; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] dnf-automatic is scheduled to run at 3:00 AM."
else
    echo -e "[${RED}ERROR${TEXTRESET}] Failed to set the update time! Check $TIMER_CONFIG."
    exit 1
fi

echo -e "[${YELLOW}INFO${TEXTRESET}] dnf-automatic setup is complete."
echo -e "[${GREEN}DONE${TEXTRESET}]"
sleep 3
}

update_login_console () {
# Update /etc/issue for login information
echo -e "${CYAN}==>Updating Login Console with Hostname and IP address...${TEXTRESET}"
sudo bash -c 'cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF'
echo -e "[${GREEN}DONE${TEXTRESET}]"
sleep 3
}



# Function to manage inside interfaces and update DNS settings
manage_inside_dns() {
    echo -e "${CYAN}==>Configuring Inside interfaces with updated DNS entries...${TEXTRESET}"
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')
    if [ -z "$main_interface" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No interface ending with '-inside' found."
        exit 1
    fi
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Main inside interface found: $main_interface"

    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No connections found for interface: $main_interface and its sub-interfaces."
        exit 1
    fi

    if systemctl is-active --quiet named; then
        dns_servers="127.0.0.1 208.67.222.222 208.67.220.220"
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Using DNS servers: $dns_servers [${YELLOW}named is active${TEXTRESET}]"
    else
        dns_servers="208.67.222.222 208.67.220.220"
        echo -e "[${YELLOW}INFO${TEXTRESET}] Using DNS servers: $dns_servers [${YELLOW}named is not active${TEXTRESET}]"
    fi
    sleep 2

    for connection_name in $connection_names; do
        echo -e "[${YELLOW}INFO${TEXTRESET}] Processing connection: ${GREEN}$connection_name${TEXTRESET}"
        nmcli connection modify "$connection_name" ipv4.dns ""
        echo -e "[${YELLOW}INFO${TEXTRESET}] Cleared existing DNS settings for connection: $connection_name"
        nmcli connection modify "$connection_name" ipv4.dns "$dns_servers"
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Set new DNS servers for connection: $connection_name"
    done
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}


# ========= INSTALL KEA STARTUP SCRIPT =========
setup_kea_startup_script () {
echo -e "${CYAN}==>Installing KEA delay script for on boot...${TEXTRESET}"
sleep 4

SRC_SCRIPT="/root/RFWB/kea_delay_start.sh"
DEST_SCRIPT="/usr/local/bin/kea_delay_start.sh"
RC_LOCAL="/etc/rc.d/rc.local"

# Check source script
if [ ! -f "$SRC_SCRIPT" ]; then
    echo -e "[${RED}ERROR${TEXTRESET}] KEA startup script not found: $SRC_SCRIPT"
    exit 1
fi

# Copy to /usr/local/bin
echo -e "[${YELLOW}INFO${TEXTRESET}] Copying KEA startup script to /usr/local/bin..."
sudo cp "$SRC_SCRIPT" "$DEST_SCRIPT"
sudo chmod +x "$DEST_SCRIPT"
echo -e "[${GREEN}SUCCESS${TEXTRESET}] Script copied and made executable: $DEST_SCRIPT"

# Setup rc.local
if [ ! -f "$RC_LOCAL" ]; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Creating rc.local file..."
    sudo touch "$RC_LOCAL"
fi
sudo chmod +x "$RC_LOCAL"
echo -e "[${GREEN}SUCCESS${TEXTRESET}] rc.local is set up and executable."

# Add the script to rc.local if not already added
if ! grep -q "$DEST_SCRIPT" "$RC_LOCAL"; then
    echo "$DEST_SCRIPT" | sudo tee -a "$RC_LOCAL" >/dev/null
    echo -e "[${YELLOW}INFO${TEXTRESET}] Added $DEST_SCRIPT to rc.local."
fi

# Enable and start rc-local service
if ! systemctl is-enabled rc-local.service &>/dev/null; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling rc-local service..."
    sudo ln -sf "$RC_LOCAL" /etc/rc.local
    sudo systemctl enable rc-local
fi

if ! systemctl is-active rc-local.service &>/dev/null; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Starting rc-local service..."
    sudo systemctl start rc-local
fi

echo -e "[${GREEN}SUCCESS${TEXTRESET}] Setup complete. The script $DEST_SCRIPT will run at startup."
echo -e "[${GREEN}DONE${TEXTRESET}]"
sleep 3
}


# ========= REMOVE INSIDE GATEWAYS =========


manage_inside_gw() {
    echo -e "${CYAN}==>Removing Default Gateway Entries on 'inside' interfaces...${TEXTRESET}"
    sleep 4
    main_interface=$(nmcli device status | awk '/-inside/ {print $1}')
    if [ -z "$main_interface" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No interface ending with '-inside' found."
        exit 1
    fi
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Main inside interface found: $main_interface"

    connection_names=$(nmcli -g NAME,DEVICE connection show | awk -F: -v main_intf="$main_interface" '$2 ~ main_intf {print $1}')
    if [ -z "$connection_names" ]; then
        echo -e "[${RED}ERROR${TEXTRESET}] No connections found for interface: $main_interface and its sub-interfaces."
        exit 1
    fi

    for connection_name in $connection_names; do
        echo -e "[${YELLOW}INFO${TEXTRESET}] Processing connection: ${GREEN}$connection_name${TEXTRESET}"
        nmcli connection modify "$connection_name" ipv4.gateway ""
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Removed gateway for connection: $connection_name"
    done
    echo -e "[${GREEN}DONE${TEXTRESET}]"
    sleep 3
}


organize_nft () {

# ─── Paths & Tempfiles ───────────────────────────────────────────────────────
NFT_FILE="/etc/sysconfig/nftables.conf"
BACKUP="${NFT_FILE}.bak.$(date +%Y%m%d%H%M%S)"
TMP="$(mktemp)"
DEBUG="/tmp/nftables_debug.conf"

# ─── Helpers ─────────────────────────────────────────────────────────────────
die(){ echo -e "${RED}ERROR${RESET} $*" >&2; exit 1; }
service_is_installed(){ systemctl list-unit-files | grep -q "^$1.service"; }
service_is_running(){ systemctl is-active --quiet "$1"; }

# ─── Track & pause rfwb-portscan & rfwb-ps-mon ────────────────────────────────
PORTSCAN_WAS_RUNNING=false
PS_MON_WAS_RUNNING=false

if service_is_installed rfwb-portscan && service_is_running rfwb-portscan; then
  echo -e "[${YELLOW}INFO${RESET}] Stopping rfwb-portscan…"
  systemctl stop rfwb-portscan
  PORTSCAN_WAS_RUNNING=true
  sleep 2
fi

if service_is_installed rfwb-ps-mon && service_is_running rfwb-ps-mon; then
  echo -e "[${YELLOW}INFO${RESET}] Stopping rfwb-ps-mon…"
  systemctl stop rfwb-ps-mon
  PS_MON_WAS_RUNNING=true
  sleep 2
fi

# ─── Main re‑ordering function ───────────────────────────────────────────────
organize_nft () {
  echo -e "${CYAN}==> Backing up nftables config...${RESET}"
  cp "$NFT_FILE" "$BACKUP"
  echo -e "[${YELLOW}INFO${RESET}] Backup saved to ${GREEN}$BACKUP${RESET}"

  echo -e "[${YELLOW}INFO${RESET}] Removing old outbound‑block from OUTPUT"
  sed -i '/chain output {/,/}/ { /ip daddr @threat_block log prefix "Outbound Blocked:/d }' \
    "$NFT_FILE"

  echo -e "[${YELLOW}INFO${RESET}] Reordering INPUT, FORWARD & OUTPUT chains…"
  awk '
    BEGIN {
      in_input = in_forward = in_output = in_portscan = 0
      cnt_in = cnt_fw = cnt_out = 0
    }
    # Portscan table: passthrough
    /^[ \t]*table inet portscan/ { in_portscan=1 }
    in_portscan && /^[ \t]*}/    { print; in_portscan=0; next }
    in_portscan                   { print; next }

    # INPUT chain
    /^[ \t]*chain input/ {
      in_input=1
      indent=substr($0,1,match($0,/chain input/)-1)
      print $0
      print indent "    type filter hook input priority filter; policy drop;"
      print indent "    ip saddr @threat_block drop"
      print indent "    iifname \"lo\" accept"
      print indent "    ct state established,related accept"
      next
    }
    in_input && /^[ \t]*}/ {
      for(i=1;i<=cnt_in;i++) print extra_in[i]
      print indent "    log prefix \"Blocked:\" drop"
      print $0
      in_input=0; cnt_in=0
      next
    }
    in_input {
      if ($0 ~ /^[ \t]*iifname/ && $0 !~ /iifname "lo"/) {
        extra_in[++cnt_in] = $0
      }
      next
    }

    # FORWARD chain
    /^[ \t]*chain forward/ {
      in_forward=1
      indent_f=substr($0,1,match($0,/chain forward/)-1)
      print $0
      print indent_f "    type filter hook forward priority filter; policy drop;"
      print indent_f "    ct state established,related accept"
      next
    }
    in_forward && /^[ \t]*}/ {
      for(j=1;j<=cnt_fw;j++) print extra_fw[j]
      print $0
      in_forward=0; cnt_fw=0
      next
    }
    in_forward {
      if ($0 ~ /^[ \t]*type filter hook forward/ ||
          $0 ~ /^[ \t]*ct state established,related accept/) next
      extra_fw[++cnt_fw] = $0
      next
    }

    # OUTPUT chain
    /^[ \t]*chain output/ {
      in_output=1
      indent_o=substr($0,1,match($0,/chain output/)-1)
      print $0
      print indent_o "    type filter hook output priority filter; policy accept;"
      print indent_o "    ip daddr @threat_block log prefix \"Outbound Blocked:\" drop"
      next
    }
    in_output && /^[ \t]*}/ {
      for(k=1;k<=cnt_out;k++) print extra_out[k]
      print $0
      in_output=0; cnt_out=0
      next
    }
    in_output {
      if ($0 ~ /^[ \t]*type filter hook output/ ||
          $0 ~ /^[ \t]*ip daddr @threat_block/) next
      extra_out[++cnt_out] = $0
      next
    }

    # Everything else
    { print }
  ' "$NFT_FILE" > "$TMP"

  cp "$TMP" "$DEBUG"
  echo -e "[${YELLOW}DEBUG${RESET}] Modified config saved to ${GREEN}$DEBUG${RESET}"

  mv "$TMP" "$NFT_FILE"
  restorecon -v "$NFT_FILE"

  echo -e "[${YELLOW}INFO${RESET}] Validating new configuration…"
  if nft -c -f "$NFT_FILE"; then
    echo -e "[${GREEN}SUCCESS${RESET}] Valid configuration. Reloading…"
    nft flush ruleset
    nft -f "$NFT_FILE"
    echo -e "[${GREEN}SUCCESS${RESET}] nftables reloaded successfully."
  else
    echo -e "[${RED}ERROR${RESET}] Validation failed; restoring backup."
    cp "$BACKUP" "$NFT_FILE"
    nft -f "$NFT_FILE"
    exit 1
  fi
echo -e "[${GREEN}DONE${TEXTRESET}]"
sleep 3
}

# ─── Invoke the reordering ───────────────────────────────────────────────────
organize_nft

# ─── Resume rfwb‑portscan & rfwb‑ps‑mon if they were running ────────────────
if [[ "$PORTSCAN_WAS_RUNNING" == true ]]; then
  echo -e "[${YELLOW}INFO${RESET}] Restarting rfwb-portscan…"
  systemctl restart rfwb-portscan
  sleep 2
fi

if [[ "$PS_MON_WAS_RUNNING" == true ]]; then
  echo -e "[${YELLOW}INFO${RESET}] Restarting rfwb-ps-mon…"
  systemctl restart rfwb-ps-mon
  sleep 2
fi

echo -e "[${GREEN}DONE${RESET}] nftables reorganized."
sleep 3
}

remove_rtp () {
#Make sure rtp-linux is not in the dnf makecache
echo -e "${CYAN}==>Cleaning DNF...${TEXTRESET}"
EPEL_REPO="/etc/yum.repos.d/epel.repo"

echo -e "[${YELLOW}INFO${TEXTRESET}] Checking for 'rtp-linux.cisco.com' in the EPEL repository configuration..."

# Check if rtp-linux.cisco.com is still referenced
if dnf repoinfo epel | grep -q "rtp-linux.cisco.com"; then
    echo -e "[${RED}WARNING${TEXTRESET}] Custom Cisco EPEL mirror detected! Updating repository settings..."

    # Force override to the official Fedora EPEL mirror
    sudo dnf config-manager --setopt=epel.baseurl=https://download.fedoraproject.org/pub/epel/9/Everything/x86_64/ --save
    echo -e "[${YELLOW}INFO${TEXTRESET}] Updated EPEL repository to use Fedora mirrors."

    # Clean and rebuild DNF cache
    echo -e "[${YELLOW}INFO${TEXTRESET}] Cleaning DNF cache..."
    sudo dnf clean all
    echo -e "[${YELLOW}INFO${TEXTRESET}] Rebuilding DNF cache..."
    sudo dnf makecache

    # Validate the change
    echo -e "[${YELLOW}INFO${TEXTRESET}] Validating EPEL repository update..."
    if dnf repoinfo epel | grep -q "rtp-linux.cisco.com"; then
        echo -e "[${RED}ERROR${TEXTRESET}] EPEL repository update failed. Please check $EPEL_REPO manually."
        exit 1
    else
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}EPEL repository updated successfully!${TEXTRESET}"
    fi
else
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] No reference to 'rtp-linux.cisco.com' found in EPEL. No changes needed."
fi
echo -e "[${GREEN}DONE${TEXTRESET}]"
sleep 3
}
install_rfwb_admin () {
echo -e "${CYAN}==> Retrieving and Installing RFWB-Admin...${TEXTRESET}"

spinner() {
  # $1 = PID of background process
  local pid=$1
  local delay=0.1
  local spinstr='|/-\'
  printf " "
  while ps -p "$pid" &>/dev/null; do
    for (( i=0; i<${#spinstr}; i++ )); do
      printf "\b${spinstr:i:1}"
      sleep $delay
    done
  done
  printf "\b"  # clear spinner
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Done."
}

  # 1) must be root
  if [[ $EUID -ne 0 ]]; then
    echo -e "[${RED}ERROR${TEXTRESET}] This installer must be run as root."
    return 1
  fi


  if [[ ! -f /etc/redhat-release ]]; then
    echo -e "[${RED}ERROR${TEXTRESET}] /etc/redhat-release not found. Cannot detect OS."
    return 1
  fi
  local major
  major=$(grep -oP '\d+' /etc/redhat-release | head -1)
  if (( major < 9 )); then
    echo -e "[${RED}ERROR${TEXTRESET}] Rocky 9.x or later is required (found $major)."
    return 1
  fi


  if [[ -d /root/.rfwb-admin ]]; then
    echo -e "[${RED}WARN${TEXTRESET}] /root/.rfwb-admin already exists. Removing old directory."
    rm -rf /root/.rfwb-admin
  fi
  echo -e "[${YELLOW}INFO${TEXTRESET}] Creating /root/.rfwb-admin…"
  mkdir -p /root/.rfwb-admin


  echo -e "[${YELLOW}INFO${TEXTRESET}] Installing git & wget…"
  dnf install -y git wget &>/dev/null &
  spinner $!


  echo -e "[${YELLOW}INFO${TEXTRESET}] Cloning RFWB-SM.git into /root/.rfwb-admin…"
  if ! git clone https://github.com/fumatchu/RFWB-SM.git /root/.rfwb-admin &>/dev/null; then
    echo -e "[${RED}ERROR${TEXTRESET}] Git clone failed."
    return 1
  fi

  chmod 700 /root/.rfwb-admin/*

  # Directory to check
DIR="/root/.rfwb-admin"

# Colored prefixes (optional)
INFO="INFO"
SUCCESS="SUCCESS"
FAIL="FAIL"

# Ensure the directory exists
if [[ ! -d "$DIR" ]]; then
  echo "$FAIL Directory not found: $DIR" >&2
  return 1
fi

echo -e "[${YELLOW}$INFO${TEXTRESET}] Checking permissions under $DIR (should be 700)..."

good=true
shopt -s nullglob
for item in "$DIR"/*; do
  mode=$(stat -c '%a' "$item")
  if [[ "$mode" != "700" ]]; then
    echo "$FAIL $item has permissions $mode"
    good=false
  else
    echo -e "[${GREEN}$SUCCESS${TEXTRESET}] $item has correct permissions (${GREEN}$mode${TEXTRESET})"
  fi
done

if $good; then
  echo -e "[${GREEN}$SUCCESS${TEXTRESET}] All items have correct permissions (${GREEN}700${TEXTRESET})."
  return 0
else
  echo -e "[${YELLOW}$INFO${TEXTRESET}] You can correct permissions with: ${CYAN}chmod 700 $DIR/*${TEXTRESET}"
  return 1
fi



  if [[ ! -d /root/.rfwb-admin/.git ]]; then
    echo -e "[${RED}ERROR${TEXTRESET}] /root/.rfwb-admin doesn’t look like a Git repo."
    return 1
  fi

  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Repository bootstrapped in /root/.rfwb-admin."
  return 0

echo -e "[${GREEN}DONE${TEXTRESET}]"
sleep 3
}

clear_bash_profile () {
sed -i '/## Run RFWB installer on every interactive login ##/,/^fi$/d' /root/.bash_profile
}

prompt_firewall_restart () {
# Notify and handle firewall restart
echo "Firewall setup complete."
read -p "Do you want to restart the firewall now? (yes/no): " user_choice
if [[ "$user_choice" == "yes" ]]; then
    echo "Restarting the firewall..."
    sudo reboot
elif [[ "$user_choice" == "no" ]]; then
    echo "The firewall will not be restarted now."
else
    echo "Invalid choice. Please run the script again and select either 'yes' or 'no'."
fi
}


# ========= MAIN =========
show_welcome_screen
network_interface_count
detect_active_interface
prompt_static_ip_if_dhcp
check_root_and_os
check_and_enable_selinux
check_internet_connectivity
validate_and_set_hostname
set_inside_interface
vlan_main
setup_outside_interface
config_fw_service
setup_nftables_inside
configure_nftables_threatlists
collect_service_choices
update_and_install_packages
vm_detection
install_yq_cli
install_speedtest_cli
install_selected_services
drop_to_cli
configure_services
# ========= POST INSTALLATION/CLEANUP =========
configure_dnf_automatic
manage_inside_dns
update_login_console
setup_kea_startup_script
manage_inside_gw
organize_nft
remove_rtp
install_rfwb_admin
clear_bash_profile
prompt_firewall_restart

#!/bin/bash
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

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
        echo "/root/RFWB/rfwb_install.sh" >> /root/.bash_profile

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
      "Hostname is already set to: $current_hostname\nNo changes needed." 6 60
    sleep 4
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
    echo "[INFO] firewalld is running, disabling it..." >> "$DEBUG_LOG"
    systemctl stop firewalld >> "$DEBUG_LOG" 2>&1
    systemctl disable firewalld >> "$DEBUG_LOG" 2>&1
    FIREWALLD_STATUS="firewalld was running and has been disabled."
  else
    echo "[INFO] firewalld is not running." >> "$DEBUG_LOG"
    FIREWALLD_STATUS="firewalld was already stopped."
  fi

  # Enable nftables if not running
  if ! systemctl is-active --quiet nftables; then
    echo "[INFO] nftables is not running, enabling it..." >> "$DEBUG_LOG"
    systemctl start nftables >> "$DEBUG_LOG" 2>&1
    systemctl enable nftables >> "$DEBUG_LOG" 2>&1
    NFTABLES_STATUS="nftables was not running and has been started."
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

        dialog --infobox "VLAN $vlan_id configured on $selected_interface as $friendly_name.\nContinuing..." 6 50
        sleep 4
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
dialog --title "Service Configuration" --msgbox "Dropping to CLI to configure services.\n\nUser interaction may be required." 8 60
clear
}

#=== CONFIG TIME ===
configure_time() {
    CHRONY_CONF="/etc/chrony.conf"
    TEMP_CONF="/tmp/chrony_temp.conf"

    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring chrony for local time synchronization..."
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

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Chrony configuration completed."
    log "Chrony configuration complete."
    sleep 2
}
#=== CONFIG FAIL2BAN ===
configure_fail2ban() {
    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring Fail2Ban service..."
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

    echo -e "[${GREEN}DONE${TEXTRESET}] Fail2Ban configuration complete."
    log "Fail2Ban configuration complete."
    sleep 2
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
    echo -e "[${YELLOW}NOTICE${TEXTRESET}] ddclient has been installed but requires manual configuration before the service can be started."
    log "ddclient installed – manual configuration is required."
}

# === INSTALL AND CONFIG COCKPIT ===
# === SUPPORTING FUNCTIONS FOR COCKPIT CONFIG ===

# Detect interfaces with "-inside" in their connection name
find_inside_interfaces() {
    inside_interfaces=$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: '$2 ~ /-inside/ {print $1}')
    log "Detected inside interfaces: $inside_interfaces"
}

# Set up nftables rule to allow Cockpit (port 9090) on inside interfaces
setup_nftables_for_cockpit() {
    log "Setting up nftables rules for Cockpit..."

    systemctl enable --now nftables >> "$LOG_FILE" 2>&1

    # Ensure table and chain exist
    if ! nft list tables | grep -q 'inet filter'; then
        nft add table inet filter
    fi
    if ! nft list chain inet filter input &>/dev/null; then
        nft add chain inet filter input { type filter hook input priority 0 \; }
    fi

    # Add rule per interface
    for iface in $inside_interfaces; do
        if ! nft list chain inet filter input | grep -q "iifname \"$iface\" tcp dport 9090 accept"; then
            nft add rule inet filter input iifname "$iface" tcp dport 9090 accept
            log "Rule added: Allow Cockpit on port 9090 for $iface"
        else
            log "Rule already exists: Cockpit 9090 for $iface"
        fi
    done

    # If rfwb-portscan is running, stop it temporarily
    if systemctl is-active --quiet rfwb-portscan; then
        systemctl stop rfwb-portscan
        restart_rfwb_portscan=true
        log "Temporarily stopped rfwb-portscan for nftables reload"
    fi

    # Save and reload nftables
    nft list ruleset > /etc/sysconfig/nftables.conf
    systemctl restart nftables

    # Restart portscan service if it was stopped
    if [[ "$restart_rfwb_portscan" == true ]]; then
        systemctl start rfwb-portscan
        log "Restarted rfwb-portscan after nftables update"
    fi
}


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

configure_cockpit() {
    log "Configuring Cockpit..."
    echo -e "[${YELLOW}INFO${TEXTRESET}] Enabling and starting Cockpit service..."

    systemctl enable --now cockpit.socket >> "$LOG_FILE" 2>&1
    systemctl start cockpit >> "$LOG_FILE" 2>&1

    if systemctl is-active --quiet cockpit; then
        log "Cockpit is running."
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Cockpit is running."

        # Find the inside interface and IP
        inside_iface=$(nmcli -t -f DEVICE,CONNECTION device status | awk -F: '$2 ~ /-inside/ {print $1; exit}')
        inside_ip=$(ip -4 addr show "$inside_iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

        echo -e "[${YELLOW}INFO${TEXTRESET}] You can access Cockpit at: https://${inside_ip}:9090"
    else
        log "Cockpit failed to start."
        echo -e "[${RED}ERROR${TEXTRESET}] Cockpit failed to start. Please check the service status."
    fi

    sleep 1
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
    echo -e "[${YELLOW}INFO${TEXTRESET}] Setting up Avahi on inside interfaces..."

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

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Avahi configuration updated for interfaces: $INTERFACES"
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

    echo -e "[${GREEN}DONE${TEXTRESET}] Avahi has been configured and is now reflecting mDNS on: $INTERFACES"
    log "Avahi configuration complete."
    sleep 1
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

configure_openvpn() {
    configure_ovpn() {
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
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] ${GREEN}OpenVPN Server Install successfull${TEXTRESET}"
    sleep 4
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

    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring ntopng..."
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
    sleep 2
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
    echo -e "[${YELLOW}INFO${TEXTRESET}] Configuring Suricata..."
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

    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Suricata installation and configuration complete."
    log "Suricata installation complete."
    sleep 4
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

    dialog --msgbox "RFWB Portscan and Monitoring Services Installed and Running." 7 60

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

    dialog --title "QoS Installation" --infobox "RFWB QoS for Voice Installed with 10% reserved bandwidth." 5 60
    sleep 3
    log "RFWB QoS for Voice installation complete."
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
            portscan) configure_portscan ;;
            snmpd) configure_snmpd ;;
            netdata) configure_netdata ;;
            qos) configure_qos ;;
            avahi) configure_avahi ;;
            evebox) configure_evebox ;;
            openvpn) configure_openvpn ;;
        esac
    done
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
install_speedtest_cli
install_selected_services
drop_to_cli
configure_services

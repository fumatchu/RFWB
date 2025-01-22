#!/bin/bash
# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
# Function to install REQUIRED
install_required() {
    echo -e "${GREEN}Installing Required packages...${TEXTRESET}"
    dnf -y config-manager --set-enabled crb
    dnf -y install epel-release
    dnf -y clean all
    dnf -y update 
    dnf -y install ntsysv iptraf
    echo -e "${GREEN}Required Package installation complete.${TEXTRESET}"
}
# Function to install ddns
install_ddclient() {
    echo -e "${GREEN}Installing ddns client (ddclient)...${TEXTRESET}"
    dnf -y install ddclient
    echo -e "${GREEN}ddns client (ddclient) installation complete.${TEXTRESET}"
}
# Function to install BIND
install_bind() {
    echo -e "${GREEN}Installing BIND...${TEXTRESET}"
    dnf -y install bind
    echo -e "${GREEN}BIND installation complete.${TEXTRESET}"

    # Firewall configuration for BIND
    # Get the network interface associated with a connection name ending in '-inside'
    inside_interface=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    # Check if we found the inside interface
    if [ -z "$inside_interface" ]; then
      echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Inside interface found: $inside_interface${TEXTRESET}"

    # Determine the zone associated with this interface by parsing the output of `firewall-cmd --list-all-zones`
    inside_zone=""
    while IFS= read -r line; do
      if [[ $line =~ ^([a-zA-Z0-9_-]+) ]]; then
        current_zone="${BASH_REMATCH[1]}"
      fi

      if [[ $line == *"interfaces: "* && $line == *"$inside_interface"* ]]; then
        inside_zone="$current_zone"
        break
      fi
    done < <(firewall-cmd --list-all-zones)

    # Check if we found the zone
    if [ -z "$inside_zone" ]; then
      echo -e "${RED}No zone associated with interface $inside_interface. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Zone associated with interface $inside_interface: $inside_zone${TEXTRESET}"

    # Add the DNS service to this zone
    echo -e "${YELLOW}Adding DNS service to zone $inside_zone...${TEXTRESET}"
    if firewall-cmd --zone="$inside_zone" --add-service=dns --permanent; then
      echo -e "${GREEN}DNS service added to zone $inside_zone.${TEXTRESET}"
    else
      echo -e "${RED}Failed to add DNS service to zone $inside_zone.${TEXTRESET}"
      exit 1
    fi

    # Reload the firewall to apply changes
    echo -e "${YELLOW}Reloading firewall...${TEXTRESET}"
    firewall-cmd --reload

    # Display the services in the zone
    echo -e "${YELLOW}Services in zone $inside_zone:${TEXTRESET}"
    firewall-cmd --list-services --zone="$inside_zone"

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

}

# Function to install ISC KEA
install_isc_kea() {
    echo -e "${GREEN}Installing ISC KEA...${TEXTRESET}"
    dnf -y install epel-release
    curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-2-6/cfg/setup/bash.rpm.sh' | sudo bash
    sudo dnf -y update
    dnf -y install isc-kea
    echo -e "${GREEN}ISC KEA installation complete.${TEXTRESET}"

    # Firewall configuration for ISC KEA
    # Get the network interface associated with a connection name ending in '-inside'
    inside_interface=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    # Check if we found the inside interface
    if [ -z "$inside_interface" ]; then
      echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Inside interface found: $inside_interface${TEXTRESET}"

    # Determine the zone associated with this interface by parsing the output of `firewall-cmd --list-all-zones`
    inside_zone=""
    while IFS= read -r line; do
      if [[ $line =~ ^([a-zA-Z0-9_-]+) ]]; then
        current_zone="${BASH_REMATCH[1]}"
      fi

      if [[ $line == *"interfaces: "* && $line == *"$inside_interface"* ]]; then
        inside_zone="$current_zone"
        break
      fi
    done < <(firewall-cmd --list-all-zones)

    # Check if we found the zone
    if [ -z "$inside_zone" ]; then
      echo -e "${RED}No zone associated with interface $inside_interface. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Zone associated with interface $inside_interface: $inside_zone${TEXTRESET}"

    # Add the DHCP service to this zone
    echo -e "${YELLOW}Adding DHCP service to zone $inside_zone...${TEXTRESET}"
    if firewall-cmd --zone="$inside_zone" --add-service=dhcp --permanent; then
      echo -e "${GREEN}DHCP service added to zone $inside_zone.${TEXTRESET}"
    else
      echo -e "${RED}Failed to add DHCP service to zone $inside_zone.${TEXTRESET}"
      exit 1
    fi

    # Reload the firewall to apply changes
    echo -e "${YELLOW}Reloading firewall...${TEXTRESET}"
    firewall-cmd --reload

    # Display the services in the zone
    echo -e "${YELLOW}Services in zone $inside_zone:${TEXTRESET}"
    firewall-cmd --list-services --zone="$inside_zone"
}

    # Function to install COCKPIT
install_cockpit() {
    echo -e "${GREEN}Installing Cockpit...${TEXTRESET}"
    dnf -y install cockpit cockpit-storaged tuned
    echo -e "${GREEN}Cockpit installation complete.${TEXTRESET}"
    # Get the network interface associated with a connection name ending in '-inside'
    inside_interface=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    # Check if we found the inside interface
    if [ -z "$inside_interface" ]; then
      echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Inside interface found: $inside_interface${TEXTRESET}"

    # Determine the zone associated with this interface by parsing the output of `firewall-cmd --list-all-zones`
    inside_zone=""
    while IFS= read -r line; do
      if [[ $line =~ ^([a-zA-Z0-9_-]+) ]]; then
        current_zone="${BASH_REMATCH[1]}"
      fi

      if [[ $line == *"interfaces: "* && $line == *"$inside_interface"* ]]; then
        inside_zone="$current_zone"
        break
      fi
    done < <(firewall-cmd --list-all-zones)

    # Check if we found the zone
    if [ -z "$inside_zone" ]; then
      echo -e "${RED}No zone associated with interface $inside_interface. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Zone associated with interface $inside_interface: $inside_zone${TEXTRESET}"

    # Add the Cockpit service to this zone
    echo -e "${YELLOW}Adding Cockpit service to zone $inside_zone...${TEXTRESET}"
    if firewall-cmd --zone="$inside_zone" --add-service=cockpit --permanent; then
      echo -e "${GREEN}Cockpit service added to zone $inside_zone.${TEXTRESET}"
    else
      echo -e "${RED}Failed to add Cockpit service to zone $inside_zone.${TEXTRESET}"
      exit 1
    fi

    # Reload the firewall to apply changes
    echo -e "${YELLOW}Reloading firewall...${TEXTRESET}"
    firewall-cmd --reload

    # Display the services in the zone
    echo -e "${YELLOW}Services in zone $inside_zone:${TEXTRESET}"
    firewall-cmd --list-services --zone="$inside_zone"
}

# Function to install WEBMIN
install_webmin() {
    echo -e "${GREEN}Installing Webmin...${TEXTRESET}"
    curl -o webmin-setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/webmin-setup-repos.sh
    yes y | sh webmin-setup-repos.sh
    dnf -y install webmin
    echo -e "${GREEN}Enabling Webmin at boot up${TEXTRESET}"
    systemctl enable webmin
    echo -e "${GREEN}Adding port 10000 to firewalld services${TEXTRESET}"
    firewall-cmd --permanent --new-service=webmin
    firewall-cmd --permanent --service=webmin --set-description=webmin
    firewall-cmd --permanent --service=webmin --add-port=10000/tcp
    # Reload firewalld to recognize the new service
    echo -e "${YELLOW}Reloading firewalld to recognize the new service...${TEXTRESET}"
    sudo firewall-cmd --reload

  # Get the network interface associated with a connection name ending in '-inside'
    inside_interface=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    # Check if we found the inside interface
    if [ -z "$inside_interface" ]; then
      echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Inside interface found: $inside_interface${TEXTRESET}"

    # Determine the zone associated with this interface by parsing the output of `firewall-cmd --list-all-zones`
    inside_zone=""
    while IFS= read -r line; do
      if [[ $line =~ ^([a-zA-Z0-9_-]+) ]]; then
        current_zone="${BASH_REMATCH[1]}"
      fi

      if [[ $line == *"interfaces: "* && $line == *"$inside_interface"* ]]; then
        inside_zone="$current_zone"
        break
      fi
    done < <(firewall-cmd --list-all-zones)

    # Check if we found the zone
    if [ -z "$inside_zone" ]; then
      echo -e "${RED}No zone associated with interface $inside_interface. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Zone associated with interface $inside_interface: $inside_zone${TEXTRESET}"

    # Add the Webmin service to this zone
    echo -e "${YELLOW}Adding Webmin service to zone $inside_zone...${TEXTRESET}"
    if firewall-cmd --zone="$inside_zone" --add-service=webmin --permanent; then
      echo -e "${GREEN}Webmin service added to zone $inside_zone.${TEXTRESET}"
    else
      echo -e "${RED}Failed to add Webmin service to zone $inside_zone.${TEXTRESET}"
      exit 1
    fi

    # Reload the firewall to apply changes
    echo -e "${YELLOW}Reloading firewall...${TEXTRESET}"
    firewall-cmd --reload

    # Display the services in the zone
    echo -e "${YELLOW}Services in zone $inside_zone:${TEXTRESET}"
    firewall-cmd --list-services --zone="$inside_zone"
}
# Function to install NTOPNG
install_ntopng() {
    echo -e "${GREEN}Installing ntopng...${TEXTRESET}"
    curl https://packages.ntop.org/centos-stable/ntop.repo > /etc/yum.repos.d/ntop.repo
    dnf -y config-manager --set-enabled crb
    dnf -y install epel-release
    dnf -y clean all
    dnf -y update
    dnf -y install pfring-dkms n2disk nprobe ntopng cento ntap
    echo -e "${GREEN}Enabling ntopng at boot up${TEXTRESET}"
    systemctl enable ntopng

    # Path to the configuration file
    CONFIG_FILE="/etc/ntopng/ntopng.conf"

    # Check if the configuration file exists
    if [ ! -f "$CONFIG_FILE" ]; then
      echo -e "${RED}Configuration file $CONFIG_FILE does not exist. Exiting...${TEXTRESET}"
      exit 1
    fi

    # Modify the line in the configuration file
    echo -e "${GREEN}Modifying $CONFIG_FILE...${TEXTRESET}"
    sed -i 's|^-G=/var/run/ntopng.pid|-G=/var/tmp/ntopng.pid --community|' "$CONFIG_FILE"

    # Verify the change
    if grep -q "^-G=/var/tmp/ntopng.pid --community" "$CONFIG_FILE"; then
      echo -e "${GREEN}Modification successful: -G=/var/tmp/ntopng.pid --community${TEXTRESET}"
    else
      echo -e "${RED}Modification failed. Please check the file manually.${TEXTRESET}"
      exit 1
    fi

    # Enable ntopng service
    echo -e "${GREEN}Enabling ntopng service...${TEXTRESET}"
    systemctl enable ntopng

    # Start ntopng service
    echo -e "${GREEN}Starting ntopng service...${TEXTRESET}"
    systemctl start ntopng

    # Validate ntopng service is running
    if systemctl is-active --quiet ntopng; then
      echo -e "${GREEN}ntopng service is running.${TEXTRESET}"
    else
      echo -e "${RED}Failed to start ntopng service. Please check the service status manually.${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Adding port 3000 to firewalld services${TEXTRESET}"
    # Add to Firewalld
    firewall-cmd --permanent --new-service=ntopng
    firewall-cmd --permanent --service=ntopng --set-description=ntopng
    firewall-cmd --permanent --service=ntopng --add-port=3000/tcp
    # Reload firewalld to recognize the new service
    echo -e "${YELLOW}Reloading firewalld to recognize the new service...${TEXTRESET}"
    sudo firewall-cmd --reload
# Get the network interface associated with a connection name ending in '-inside'
    inside_interface=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: '$1 ~ /-inside$/ {print $2}')

    # Check if we found the inside interface
    if [ -z "$inside_interface" ]; then
      echo -e "${RED}No interface with '-inside' profile found. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Inside interface found: $inside_interface${TEXTRESET}"

    # Determine the zone associated with this interface by parsing the output of `firewall-cmd --list-all-zones`
    inside_zone=""
    while IFS= read -r line; do
      if [[ $line =~ ^([a-zA-Z0-9_-]+) ]]; then
        current_zone="${BASH_REMATCH[1]}"
      fi

      if [[ $line == *"interfaces: "* && $line == *"$inside_interface"* ]]; then
        inside_zone="$current_zone"
        break
      fi
    done < <(firewall-cmd --list-all-zones)

    # Check if we found the zone
    if [ -z "$inside_zone" ]; then
      echo -e "${RED}No zone associated with interface $inside_interface. Exiting...${TEXTRESET}"
      exit 1
    fi

    echo -e "${GREEN}Zone associated with interface $inside_interface: $inside_zone${TEXTRESET}"

    # Add the ntopng service to this zone
    echo -e "${YELLOW}Adding ntopng service to zone $inside_zone...${TEXTRESET}"
    if firewall-cmd --zone="$inside_zone" --add-service=ntopng --permanent; then
      echo -e "${GREEN}ntopng service added to zone $inside_zone.${TEXTRESET}"
    else
      echo -e "${RED}Failed to add ntopng service to zone $inside_zone.${TEXTRESET}"
      exit 1
    fi

    # Reload the firewall to apply changes
    echo -e "${YELLOW}Reloading firewall...${TEXTRESET}"
    firewall-cmd --reload

    # Display the services in the zone
    echo -e "${YELLOW}Services in zone $inside_zone:${TEXTRESET}"
    firewall-cmd --list-services --zone="$inside_zone"

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"
}


# Use dialog to prompt the user
cmd=(dialog --separate-output --checklist "Select services to install:" 22 76 16)
options=(
    1 "Install BIND" off
    2 "Install ISC KEA" off
    3 "Install Cockpit" off
    4 "Install Webmin" off
    5 "Install ntopng" off
    6 "Install DDNS Client" off
    7 "Install required Packages" on
)
choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)

clear

for choice in $choices; do
    case $choice in
    1)
        install_bind
        ;;
    2)
        install_isc_kea
        ;;
    3)
        install_cockpit
        ;;
    4)
        install_webmin
        ;;
    5)
        install_ntopng
        ;;
    6) 
        install_ddclient
        ;;
    7)
        install_required
        ;;


    esac
done

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

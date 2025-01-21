#!/bin/bash


# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to install BIND
install_bind() {
    echo -e "${GREEN}Installing BIND...${TEXTRESET}"
    dnf -y install bind
    echo -e "${GREEN}BIND installation complete.${TEXTRESET}"
}

# Prompt user to install BIND
echo -e "${YELLOW}Do you want to install BIND? (yes/no)${TEXTRESET}"
read -p "Your choice: " user_choice

if [[ "$user_choice" =~ ^[Yy][Ee][Ss]$ || "$user_choice" =~ ^[Yy]$ ]]; then
    install_bind
else
    echo -e "${YELLOW}Skipping BIND installation.${TEXTRESET}"
fi

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

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




# Function to install ISC KEA
install_isc_kea() {
    echo -e "${GREEN}Installing ISC KEA...${TEXTRESET}"
    dnf -y install epel-release
    curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-2-6/cfg/setup/bash.rpm.sh' | sudo bash
    sudo dnf -y update
    dnf -y install isc-kea
    echo -e "${GREEN}ISC KEA installation complete.${TEXTRESET}"
}

# Prompt user to install ISC KEA
echo -e "${YELLOW}Do you want to install ISC KEA? (yes/no)${TEXTRESET}"
read -p "Your choice: " user_choice

if [[ "$user_choice" =~ ^[Yy][Ee][Ss]$ || "$user_choice" =~ ^[Yy]$ ]]; then
    install_isc_kea
else
    echo -e "${YELLOW}Skipping ISC KEA installation.${TEXTRESET}"
fi

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

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



# Function to install COCKPIT
install_cockpit() {
    echo -e "${GREEN}Installing Cockpit...${TEXTRESET}"
    dnf -y install cockpit cockpit-storaged tuned
    echo -e "${GREEN}Cockpit installation complete.${TEXTRESET}"
}

# Prompt user to install COCKPIT
echo -e "${YELLOW}Do you want to install Cockpit? (yes/no)${TEXTRESET}"
read -p "Your choice: " user_choice

if [[ "$user_choice" =~ ^[Yy][Ee][Ss]$ || "$user_choice" =~ ^[Yy]$ ]]; then
    install_cockpit
else
    echo -e "${YELLOW}Skipping Cockpit installation.${TEXTRESET}"
fi

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

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
echo -e "${YELLOW}Adding Cockpit service to zone $inside_zone...${TEXTRESET}"
if firewall-cmd --zone="$inside_zone" --add-service=cockpit --permanent; then
  echo -e "${GREEN}Cockpit service added to zone $inside_zone.${TEXTRESET}"
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


# Function to install WEBMIN
install_webmin() {
    echo -e "${GREEN}Installing Webmin...${TEXTRESET}"
    curl -o webmin-setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/webmin-setup-repos.sh
    yes y | sh webmin-setup-repos.sh
    dnf -y install webmin
    echo -e "${GREEN}Enabling Webmin at boot up${TEXTRESET}"
    systemctl enable webmin 
    echo -e "${GREEN}Adding port 10000 to firewalld services${TEXTRESET}"
    # Define the service XML content
    WEBMIN_SERVICE_XML="<?xml version=\"1.0\" encoding=\"utf-8\"?>
    <service>
    <short>Webmin</short>
    <description>Webmin is a powerful and flexible web-based server management control panel.</description>
    <port protocol=\"tcp\" port=\"10000\"/>
    </service>"

    # Create the Webmin service XML file
    echo -e "${YELLOW}Creating Webmin service file...${TEXTRESET}"
    echo "$WEBMIN_SERVICE_XML" | sudo tee /etc/firewalld/services/webmin.xml > /dev/null

    # Reload firewalld to recognize the new service
    echo -e "${YELLOW}Reloading firewalld to recognize the new service...${TEXTRESET}"
    sudo firewall-cmd --reload
}

# Prompt user to install WEBMIN
echo -e "${YELLOW}Do you want to install Webmin? (yes/no)${TEXTRESET}"
read -p "Your choice: " user_choice

if [[ "$user_choice" =~ ^[Yy][Ee][Ss]$ || "$user_choice" =~ ^[Yy]$ ]]; then
    install_webmin
else
    echo -e "${YELLOW}Skipping Webmin installation.${TEXTRESET}"
fi

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

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
    sed -i 's|^-G=/var/tmp/ntopng.pid|-G=/var/tmp/ntopng.pid --community|' "$CONFIG_FILE"

    # Verify the change
    if grep -q "^-G=/var/tmp/ntopng.pid --community" "$CONFIG_FILE"; then
    echo -e "${GREEN}Modification successful: -G=/var/tmp/ntopng.pid --community${TEXTRESET}"
    else
    echo -e "${RED}Modification failed. Please check the file manually.${TEXTRESET}"
    fi
    echo -e "${GREEN}starting ntopng...${TEXTRESET}"
    systemctl start ntopng
    echo -e "${GREEN}Adding port 3000 to firewalld services${TEXTRESET}"
    #Add to Firewalld
    firewall-cmd --permanent --new-service=ntopng
    firewall-cmd --permanent --service=ntopng --set-description=ntopng
    firewall-cmd --permanent --service=ntopng --add-port=3000/tcp
    # Reload firewalld to recognize the new service
    echo -e "${YELLOW}Reloading firewalld to recognize the new service...${TEXTRESET}"
    sudo firewall-cmd --reload
}
# Prompt user to install ntopng
echo -e "${YELLOW}Do you want to install ntopng? (yes/no)${TEXTRESET}"
read -p "Your choice: " user_choice

if [[ "$user_choice" =~ ^[Yy][Ee][Ss]$ || "$user_choice" =~ ^[Yy]$ ]]; then
    install_webmin
else
    echo -e "${YELLOW}Skipping ntopng installation.${TEXTRESET}"
fi

# Continue with the rest of the script
echo -e "${GREEN}Continuing with the rest of the script...${TEXTRESET}"

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



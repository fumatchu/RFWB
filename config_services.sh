#!/bin/bash

# Define color codes
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to check if a domain name is in the correct format
is_valid_domain() {
    local domain=$1
    local regex="^([a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*\.)?[a-zA-Z0-9]+\.[a-zA-Z]{2,}$"
    [[ $domain =~ $regex ]]
}

# Function to validate an email address format
is_valid_email() {
    local email=$1
    local regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    [[ $email =~ $regex ]]
}

# Function to update the serial number in a zone file
update_serial_number() {
    local zone_file=$1
    local current_serial=$(awk '/SOA/ {getline; print $1}' "$zone_file")

    if [[ "$current_serial" =~ ^[0-9]+$ ]]; then
        local new_serial=$((current_serial + 1))
        sudo sed -i "s/$current_serial/$new_serial/" "$zone_file"
        echo -e "${GREEN}Serial number updated from $current_serial to $new_serial in $zone_file.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update serial number: could not find a valid serial number.${TEXTRESET}"
    fi
}

# Function to configure BIND with rndc
configure_rndc() {
    echo -e "${YELLOW}Generating rndc key...${TEXTRESET}"
    sudo rndc-confgen -a

    if grep -q 'include "/etc/rndc.key";' "$NAMED_CONF" && grep -q 'controls {' "$NAMED_CONF"; then
        echo -e "${YELLOW}rndc configuration already exists in $NAMED_CONF. Skipping addition.${TEXTRESET}"
    else
        echo -e "${YELLOW}Adding rndc configuration to $NAMED_CONF...${TEXTRESET}"
        sudo bash -c "cat >> $NAMED_CONF" <<EOF

include "/etc/rndc.key";

controls {
    inet 127.0.0.1 allow { localhost; } keys { "rndc-key"; };
};
EOF
    fi

    echo -e "${GREEN}Configuration updated for rndc in $NAMED_CONF.${TEXTRESET}"
    sudo chown root:named /etc/rndc.key
    sudo chmod 640 /etc/rndc.key
    if selinuxenabled; then
        sudo restorecon /etc/rndc.key
    fi

    echo -e "${YELLOW}Updating firewall rules to allow rndc...${TEXTRESET}"
    sudo firewall-cmd --add-port=953/tcp --permanent
    sudo firewall-cmd --reload

    echo -e "${YELLOW}Restarting BIND service...${TEXTRESET}"
    sudo systemctl restart named

    echo -e "${YELLOW}Testing rndc status...${TEXTRESET}"
    sudo rndc status || echo -e "${RED}rndc status command failed. Please check the configuration.${TEXTRESET}"
}

# Function to create a new forwarding zone
create_forwarding_zone() {
    while true; do
        read -p "Enter the domain name for the new zone (e.g., example.int): " domain_name

        if is_valid_domain "$domain_name"; then
            while true; do
                read -p "Enter the email address for the zone (e.g., admin@example.com): " email_address

                if is_valid_email "$email_address"; then
                    soa_email="${email_address//@/.}"
                    break
                else
                    echo -e "${RED}Invalid email address format. Please try again.${TEXTRESET}"
                fi
            done

            zone_file="/var/named/${domain_name}.hosts"
            fqdn=$(hostname -f)

            sudo bash -c "cat > $zone_file" <<EOF
\$TTL 3600
$domain_name.  IN  SOA  $fqdn. $soa_email. (
            2025013000
            3600
            600
            1209600
            3600 )
$domain_name.  IN  NS  $fqdn.
EOF

            sudo chown root:named $zone_file
            sudo chmod 640 $zone_file
            sudo restorecon $zone_file

            echo -e "${GREEN}Zone file $zone_file created and configured.${TEXTRESET}"
            echo -e "${YELLOW}Contents of the newly created zone file:${TEXTRESET}"
            cat $zone_file

            echo -e "${YELLOW}Adding the new zone configuration to the end of $NAMED_CONF...${TEXTRESET}"
            sudo bash -c "cat >> $NAMED_CONF" <<EOF

zone "$domain_name" {
    type master;
    file "$zone_file";
};
EOF

            update_serial_number "$zone_file"

            break
        else
            echo -e "${RED}Invalid domain name format. Please use the format subdomain.domain.int or domain.int.${TEXTRESET}"
        fi
    done
}

# Function to update named.conf for crypto policy and logging
update_named_conf() {
    echo -e "${YELLOW}Updating $NAMED_CONF for crypto policy and logging...${TEXTRESET}"

    # Backup the original named.conf
    sudo cp "$NAMED_CONF" "${NAMED_CONF}.bak"

    # Use sed to replace specific blocks
    sudo sed -i '/\/\* https:\/\/fedoraproject.org\/wiki\/Changes\/CryptoPolicy \*\//,/}/c\/* https://fedoraproject.org/wiki/Changes/CryptoPolicy */\n\tinclude "/etc/crypto-policies/ba
ck-ends/bind.config";\n\tforwarders {\n\t\t208.67.222.222;\n\t\t208.67.220.220;\n\t};\n\tforward only;' "$NAMED_CONF"

    sudo sed -i '/logging {/,/};/c\logging {\n\tchannel default_debug {\n\t\tfile "data/named.run";\n\t\tseverity dynamic;\n\t};\n\n\tcategory lame-servers { null; };\n};' "$NAMED_CONF
"

    echo -e "${GREEN}Updated $NAMED_CONF for crypto policy and logging.${TEXTRESET}"
}

NAMED_CONF="/etc/named.conf"

if [ -f "$NAMED_CONF" ]; then
    echo -e "${GREEN}$NAMED_CONF found.${TEXTRESET}"

    read -p "Do you want to configure BIND? (yes/no): " user_input
    user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

    if [ "$user_input" == "yes" ]; then
        echo -e "${YELLOW}Configuring BIND...${TEXTRESET}"

        sudo sed -i 's/listen-on port 53 { 127.0.0.1; };/listen-on port 53 { 127.0.0.1; any; };/' "$NAMED_CONF"
        sudo sed -i 's/allow-query[[:space:]]*{[[:space:]]*localhost;[[:space:]]*};/allow-query { localhost; any; };/' "$NAMED_CONF"

        echo -e "${GREEN}Configuration updated in $NAMED_CONF.${TEXTRESET}"
        configure_rndc

        read -p "Do you want to create a new forwarding zone? (yes/no): " create_zone

        if [ "$create_zone" == "yes" ]; then
            create_forwarding_zone
        else
            echo -e "${YELLOW}Zone creation skipped.${TEXTRESET}"
        fi

        update_named_conf

    elif [ "$user_input" == "no" ]; then
        echo -e "${YELLOW}BIND configuration skipped.${TEXTRESET}"
    else
        echo -e "${RED}Invalid input. Please answer 'yes' or 'no'.${TEXTRESET}"
    fi
else
    echo -e "${RED}$NAMED_CONF not found. BIND might not be installed.${TEXTRESET}"
fi

#!/bin/bash

# Define color codes
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to find the network interface
find_interface() {
    # Find the interface with a connection ending in -inside
    interface=$(nmcli device status | awk '/-inside/ {print $1}')

    if [ -z "$interface" ]; then
        echo -e "${RED}Error: No interface with a connection ending in '-inside' found.${TEXTRESET}"
        exit 1
    fi

    echo "$interface"
}

# Function to update the serial number in a zone file
update_serial_number() {
    local zone_file=$1
    local current_serial=$(awk '/SOA/ {getline; print $1}' "$zone_file")

    if [[ "$current_serial" =~ ^[0-9]+$ ]]; then
        local new_serial=$((current_serial + 1))
        sudo sed -i "s/$current_serial/$new_serial/" "$zone_file"
        echo -e "${GREEN}Serial number updated from $current_serial to $new_serial in $zone_file.${TEXTRESET}"
    else
        echo -e "${RED}Failed to update serial number: could not find a valid serial number.${TEXTRESET}"
    fi
}

# Main script logic
read -p "Do you want to add an A record for the firewall? (yes/no): " add_a_record
add_a_record=$(echo "$add_a_record" | tr '[:upper:]' '[:lower:]')

if [ "$add_a_record" == "yes" ]; then
    # Get the static hostname
    hostname=$(hostnamectl status | awk '/Static hostname:/ {print $3}')

    if [ -z "$hostname" ]; then
        echo -e "${RED}Failed to determine the hostname.${TEXTRESET}"
        exit 1
    fi

    # Find the interface and get the IP address
    interface=$(find_interface)
    ip_address=$(ip -o -4 addr show dev "$interface" | awk '{print $4}' | cut -d/ -f1)

    if [ -z "$ip_address" ]; then
        echo -e "${RED}Failed to retrieve IP address for the interface $interface.${TEXTRESET}"
        exit 1
    fi

    # Locate the .hosts file
    zone_file=$(find /var/named -type f -name "*.hosts" -print -quit)

    if [ -z "$zone_file" ]; then
        echo -e "${RED}No .hosts file found in /var/named.${TEXTRESET}"
        exit 1
    fi

    # Add the A record to the zone file
    sudo bash -c "echo '$hostname. IN A $ip_address' >> $zone_file"
    echo -e "${GREEN}A record added: $hostname. IN A $ip_address${TEXTRESET}"

    # Update the serial number
    update_serial_number "$zone_file"
else
    echo -e "${YELLOW}A record addition skipped.${TEXTRESET}"
fi

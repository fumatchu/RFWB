#!/bin/bash

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

    # Extract the current serial number by searching the line after the SOA opening
    local current_serial=$(awk '/SOA/ {getline; print $1}' "$zone_file")

    # Check if the current serial number is valid
    if [[ "$current_serial" =~ ^[0-9]+$ ]]; then
        local new_serial=$((current_serial + 1))
        # Update the zone file with the new serial number
        sudo sed -i "s/$current_serial/$new_serial/" "$zone_file"
        echo "Serial number updated from $current_serial to $new_serial in $zone_file."
    else
        echo "Failed to update serial number: could not find a valid serial number."
    fi
}

# Function to configure BIND with rndc
configure_rndc() {
    echo "Generating rndc key..."
    sudo rndc-confgen -a

    if grep -q 'include "/etc/rndc.key";' "$NAMED_CONF" && grep -q 'controls {' "$NAMED_CONF"; then
        echo "rndc configuration already exists in $NAMED_CONF. Skipping addition."
    else
        echo "Adding rndc configuration to $NAMED_CONF..."
        sudo bash -c "cat >> $NAMED_CONF" <<EOF

include "/etc/rndc.key";

controls {
    inet 127.0.0.1 allow { localhost; } keys { "rndc-key"; };
};
EOF
    fi

    echo "Configuration updated for rndc in $NAMED_CONF."
    sudo chown root:named /etc/rndc.key
    sudo chmod 640 /etc/rndc.key
    if selinuxenabled; then
        sudo restorecon /etc/rndc.key
    fi

    echo "Updating firewall rules to allow rndc..."
    sudo firewall-cmd --add-port=953/tcp --permanent
    sudo firewall-cmd --reload

    echo "Restarting BIND service..."
    sudo systemctl restart named

    echo "Testing rndc status..."
    sudo rndc status || echo "rndc status command failed. Please check the configuration."
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
                    echo "Invalid email address format. Please try again."
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

            echo "Zone file $zone_file created and configured."
            echo "Contents of the newly created zone file:"
            cat $zone_file

            echo "Adding the new zone configuration to the end of $NAMED_CONF..."
            sudo bash -c "cat >> $NAMED_CONF" <<EOF

zone "$domain_name" {
    type master;
    file "$zone_file";
};
EOF

            update_serial_number "$zone_file"

            break
        else
            echo "Invalid domain name format. Please use the format subdomain.domain.int or domain.int."
        fi
    done
}

NAMED_CONF="/etc/named.conf"

if [ -f "$NAMED_CONF" ]; then
    echo "$NAMED_CONF found."

    read -p "Do you want to configure BIND? (yes/no): " user_input
    user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

    if [ "$user_input" == "yes" ]; then
        echo "Configuring BIND..."

        sudo sed -i 's/listen-on port 53 { 127.0.0.1; };/listen-on port 53 { 127.0.0.1; any; };/' "$NAMED_CONF"
        sudo sed -i 's/allow-query[[:space:]]*{[[:space:]]*localhost;[[:space:]]*};/allow-query { localhost; any; };/' "$NAMED_CONF"

        echo "Configuration updated in $NAMED_CONF."
        configure_rndc

        read -p "Do you want to create a new forwarding zone? (yes/no): " create_zone

        if [ "$create_zone" == "yes" ]; then
            create_forwarding_zone
        else
            echo "Zone creation skipped."
        fi

    elif [ "$user_input" == "no" ]; then
        echo "BIND configuration skipped."
    else
        echo "Invalid input. Please answer 'yes' or 'no'."
    fi
else
    echo "$NAMED_CONF not found. BIND might not be installed."
fi

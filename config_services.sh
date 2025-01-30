#!/bin/bash





#Create BIND forward domain
# Function to check if a domain name is in the correct format
is_valid_domain() {
    local domain=$1
    # Regex to match subdomain.domain.int or domain.int
    local regex="^([a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*\.)?[a-zA-Z0-9]+\.[a-zA-Z]{2,}$"
    [[ $domain =~ $regex ]]
}

# Function to configure BIND with rndc
configure_rndc() {
    echo "Generating rndc key..."
    sudo rndc-confgen -a

    # Check for existing rndc configuration in named.conf
    if grep -q 'include "/etc/rndc.key";' "$NAMED_CONF" && grep -q 'controls {' "$NAMED_CONF"; then
        echo "rndc configuration already exists in $NAMED_CONF. Skipping addition."
    else
        # Update named.conf to include rndc key and control settings
        echo "Adding rndc configuration to $NAMED_CONF..."
        sudo bash -c "cat >> $NAMED_CONF" <<EOF

include "/etc/rndc.key";

controls {
    inet 127.0.0.1 allow { localhost; } keys { "rndc-key"; };
};
EOF
    fi

    echo "Configuration updated for rndc in $NAMED_CONF."

    # Ensure /etc/rndc.key has the correct permissions and ownership
    echo "Setting correct permissions and ownership for /etc/rndc.key..."
    sudo chown root:named /etc/rndc.key
    sudo chmod 640 /etc/rndc.key

    # Adjust SELinux context if SELinux is enabled
    if selinuxenabled; then
        echo "Adjusting SELinux context for /etc/rndc.key..."
        sudo restorecon /etc/rndc.key
    fi

    # Open port 953 in the firewall
    echo "Updating firewall rules to allow rndc..."
    sudo firewall-cmd --add-port=953/tcp --permanent
    sudo firewall-cmd --reload

    # Restart BIND service
    echo "Restarting BIND service..."
    sudo systemctl restart named

    # Test rndc
    echo "Testing rndc status..."
    sudo rndc status || echo "rndc status command failed. Please check the configuration."
}

# Function to create a new forwarding zone
create_forwarding_zone() {
    while true; do
        read -p "Enter the domain name for the new zone (e.g., example.int): " domain_name

        # Validate the domain name format
        if is_valid_domain "$domain_name"; then
            zone_file="/var/named/${domain_name}.hosts"

            # Get the server's fully qualified domain name (FQDN)
            fqdn=$(hostname -f)

            # Create the zone file
            sudo bash -c "cat > $zone_file" <<EOF
\$TTL 3600
$domain_name.  IN  SOA  $fqdn. matgear.cisco.com. (
            2025013000
            3600
            600
            1209600
            3600 )
$domain_name.  IN  NS  $fqdn.
EOF

            # Set the correct permissions and ownership for the zone file
            echo "Setting permissions and ownership for the zone file..."
            sudo chown root:named $zone_file
            sudo chmod 640 $zone_file
            sudo restorecon $zone_file

            echo "Zone file $zone_file created and configured."

            # Display the contents of the new zone file
            echo "Contents of the newly created zone file:"
            cat $zone_file

            # Add the new zone configuration to the end of named.conf
            echo "Adding the new zone configuration to the end of $NAMED_CONF..."
            sudo bash -c "cat >> $NAMED_CONF" <<EOF

zone "$domain_name" {
    type master;
    file "$zone_file";
};
EOF

            break
        else
            echo "Invalid domain name format. Please use the format subdomain.domain.int or domain.int."
        fi
    done
}

# Path to the named.conf file
NAMED_CONF="/etc/named.conf"

# Check if the named.conf file exists
if [ -f "$NAMED_CONF" ]; then
    echo "$NAMED_CONF found."

    # Prompt the user for action
    read -p "Do you want to configure BIND? (yes/no): " user_input

    # Convert input to lowercase to handle different cases
    user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

    if [ "$user_input" == "yes" ]; then
        echo "Configuring BIND..."

        # Use sed to modify the listen-on and allow-query directives
        sudo sed -i 's/listen-on port 53 { 127.0.0.1; };/listen-on port 53 { 127.0.0.1; any; };/' "$NAMED_CONF"
        sudo sed -i 's/allow-query[[:space:]]*{[[:space:]]*localhost;[[:space:]]*};/allow-query { localhost; any; };/' "$NAMED_CONF"

        echo "Configuration updated in $NAMED_CONF."

        # Call the configure_rndc function
        configure_rndc

        # Ask the user if they want to create a new forwarding zone
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

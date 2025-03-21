#!/bin/bash

NFTABLES_FILE="/etc/sysconfig/nftables.conf"
TMP_FILE=$(mktemp)
DEBUG_FILE="/tmp/nftables_debug.conf"

# Backup original nftables configuration
cp "$NFTABLES_FILE" "$NFTABLES_FILE.bak"
echo "Backed up original file to: $NFTABLES_FILE.bak"

# Function to check if a service is installed
service_is_installed() {
    systemctl list-unit-files | grep -q "^$1.service"
}

# Function to check if a service is running
service_is_running() {
    systemctl is-active --quiet "$1"
}

# Track if rfwb-portscan was running before stopping it
PORTSCAN_WAS_RUNNING=false

# Step 1: Check if rfwb-portscan is installed
if service_is_installed "rfwb-portscan"; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] rfwb-portscan is installed."

    # Step 2: Check if rfwb-portscan is running
    if service_is_running "rfwb-portscan"; then
        echo "Stopping rfwb-portscan..."
        systemctl stop rfwb-portscan
        PORTSCAN_WAS_RUNNING=true
        sleep 2  # Allow time for rfwb-ps-mon to stop automatically
    else
        echo "rfwb-portscan is installed but not running."
    fi
else
    echo "rfwb-portscan is NOT installed. Continuing..."
fi

# === ADD YOUR NFTABLES RULES ADJUSTMENTS HERE ===
echo "Adjusting nftables rules..."
# Step 1: Remove all instances of the outbound block rule from the chain output
sed -i '/chain output {/,/}/ {/ip daddr @threat_block log prefix "Outbound Blocked:" drop/d;}' "$NFTABLES_FILE"
sed -i '/chain output {/,/}/ {/ip daddr @threat_block log prefix "Outbound Blocked: " drop/d;}' "$NFTABLES_FILE"

# Step 2: Process the nftables configuration with awk
awk '
  BEGIN {
    in_input = 0;
    in_output = 0;
    in_portscan = 0;
    input_header = "";
    output_header = "";
    input_rules = "";
    output_rules = "";
    input_policy = "    type filter hook input priority filter; policy drop;";
    output_policy = "    type filter hook output priority filter; policy accept;";
    threat_rule = "    ip saddr @threat_block drop";  # Always at the top of input chain
    log_rule = "    log prefix \"Blocked:\" drop";  # Always at the bottom of input chain
    threat_out_rule = "    ip daddr @threat_block log prefix \"Outbound Blocked:\" drop";  # Ensure correct format
    threat_out_seen = 0;
  }

  /table inet portscan/ {
    in_portscan = 1;
  }

  /chain input/ && !in_portscan {
    in_input = 1;
    input_header = $0;
    input_rules = "";
    next;
  }
  
  /chain output/ {
    in_output = 1;
    output_header = $0;
    output_rules = "";
    next;
  }

  in_input && /}/ {
    in_input = 0;
    print input_header;
    print input_policy;
    print threat_rule;
    print input_rules;
    print log_rule;
    print "}";
    next;
  }

  in_input {
    if ($0 ~ /ip saddr @threat_block drop/ || $0 ~ /log prefix "Blocked:/ || $0 ~ /type filter hook input priority filter; policy/) {
      next;
    } else {
      input_rules = input_rules "\n" $0;
    }
    next;
  }

  in_output && /}/ {
    in_output = 0;
    print output_header;
    print output_policy;
    if (!threat_out_seen) {
      print threat_out_rule;
      threat_out_seen = 1;
    }
    print output_rules;
    print "}";
    next;
  }

  in_output {
    if ($0 ~ /ip daddr @threat_block log prefix "Outbound Blocked: "/ || $0 ~ /type filter hook output priority filter; policy/) {
      next;
    } else {
      output_rules = output_rules "\n" $0;
    }
    next;
  }

  { print }
' "$NFTABLES_FILE" > "$TMP_FILE"

# Save debug file before applying changes
cp "$TMP_FILE" "$DEBUG_FILE"
echo "Modified nftables configuration saved to: $DEBUG_FILE"

# Replace original file with updated rules
mv "$TMP_FILE" "$NFTABLES_FILE"

# Restore original ownership and permissions
chown --reference="$NFTABLES_FILE.bak" "$NFTABLES_FILE"
chmod --reference="$NFTABLES_FILE.bak" "$NFTABLES_FILE"

# Fix SELinux context
restorecon -v "$NFTABLES_FILE"

# Validate configuration
if nft -c -f "$NFTABLES_FILE"; then
    echo "nftables configuration is valid. Reloading..."
    systemctl restart nftables
else
    echo "nftables configuration test failed! Restoring previous config."
    cp "$NFTABLES_FILE.bak" "$NFTABLES_FILE"
    systemctl restart nftables
    echo "🔍 Check debug output in: $DEBUG_FILE"
fi


# Step 3: Restart services if rfwb-portscan was stopped
if [[ "$PORTSCAN_WAS_RUNNING" == true ]]; then
    echo "Restarting rfwb-portscan..."
    systemctl start rfwb-portscan
    sleep 2
fi

# Ensure both services are running at the end

# Start rfwb-portscan if installed and not running
if service_is_installed "rfwb-portscan" && ! service_is_running "rfwb-portscan"; then
    echo "rfwb-portscan was not running. Attempting to start..."
    systemctl start rfwb-portscan
fi

# Start rfwb-ps-mon if installed and not running
if service_is_installed "rfwb-ps-mon" && ! service_is_running "rfwb-ps-mon"; then
    echo "rfwb-ps-mon was not running. Attempting to start..."
    systemctl start rfwb-ps-mon
fi

# Final verification
echo "🔍 Verifying service status..."

if service_is_installed "rfwb-portscan"; then
    if service_is_running "rfwb-portscan"; then
        echo "rfwb-portscan is running."
    else
        echo "rfwb-portscan is NOT running!"
    fi
fi

if service_is_installed "rfwb-ps-mon"; then
    if service_is_running "rfwb-ps-mon"; then
        echo "rfwb-ps-mon is running."
    else
        echo "rfwb-ps-mon is NOT running!"
    fi
fi

echo "Script execution complete."

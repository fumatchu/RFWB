#!/bin/bash
#this script places block at the bottom and ip src threat at the top. Run this when needed to reorg your chains

# File paths
NFTABLES_FILE="/etc/sysconfig/nftables.conf"
BACKUP_FILE="/etc/sysconfig/nftables.conf.bak"
TMP_FILE="/tmp/nftables_input_reordered.tmp"

# Backup original file
cp "$NFTABLES_FILE" "$BACKUP_FILE"
echo "Backup created at $BACKUP_FILE."

# Get current ownership and permissions
CURRENT_OWNER=$(stat -c "%u:%g" "$NFTABLES_FILE")
CURRENT_PERMISSIONS=$(stat -c "%a" "$NFTABLES_FILE")

# Reorganize the input chain
awk '
  BEGIN {
    in_block = 0;
    log_rule = "";
    threat_rule = "";
  }
  /chain input/ { in_block = 1; block=""; print; next }
  in_block && /}/ {
    in_block = 0;
    if (threat_rule != "") {
      print threat_rule;  # Ensure threat_block drop is at the top
    }
    print block;  # Print all other rules
    if (log_rule != "") {
      print log_rule;  # Append the log rule at the bottom
    }
    print;
    next;
  }
  in_block {
    if ($0 ~ /ip saddr @threat_block drop/) {
      threat_rule = $0;  # Save threat_block drop rule for later insertion
    } else if ($0 ~ /log prefix "Blocked: " drop/) {
      log_rule = $0;  # Save log rule for later insertion
    } else {
      block = block "\n" $0;  # Store all other rules normally
    }
    next;
  }
  { print }
' "$NFTABLES_FILE" > "$TMP_FILE"

# Replace original file with updated rules
mv "$TMP_FILE" "$NFTABLES_FILE"
echo "Reorganized rules have been saved to $NFTABLES_FILE."

# Restore original ownership and permissions
sudo chown "$CURRENT_OWNER" "$NFTABLES_FILE"
sudo chmod "$CURRENT_PERMISSIONS" "$NFTABLES_FILE"

# Fix SELinux context
sudo restorecon -v "$NFTABLES_FILE"

# Restart nftables to apply changes
sudo systemctl restart nftables

# Verify nftables status
if systemctl is-active --quiet nftables; then
    echo "✅ nftables service restarted successfully!"
else
    echo "❌ nftables failed to restart! Check logs with: sudo journalctl -xeu nftables.service"
fi

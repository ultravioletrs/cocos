#!/bin/sh

WORK_DIR="/cocos"

# IFACES are all network interfaces excluding lo (LOOPBACK) and sit interfaces 
IFACES=$(ip link show | grep -vE 'LOOPBACK|sit*' | awk -F': ' '{print $2}')

# This for loop brings up all network interfaces in IFACES and dhclient obtains an IP address for the every interface
for IFACE in $IFACES; do
    STATE=$(ip link show $IFACE | grep DOWN)
    if [ -n "$STATE" ]; then
        ip link set $IFACE up
    fi

    IP_ADDR=$(ip addr show $IFACE | grep 'inet ')
    if [ -z "$IP_ADDR" ]; then
        dhclient $IFACE
    fi
done

if [ ! -d "$WORK_DIR" ]; then
    mkdir -p $WORK_DIR
fi

# Resize the root file system to 100%
mount -o remount,size=100% /

SYSTEMD_SERVICE="/usr/lib/systemd/system/cocos-agent.service"
ENV_FILE="/mnt/env/environment"

# Function to setup environment variables
setup_environment() {

    # Check if systemd service file exists
    if [ ! -f "$SYSTEMD_SERVICE" ]; then
        exit 1
    fi

    if [ ! -f "$ENV_FILE" ]; then
        exit 1
    fi

    # Backup the original file if not already backed up
    if [ ! -f "$SYSTEMD_SERVICE.bak" ]; then
        cp "$SYSTEMD_SERVICE" "$SYSTEMD_SERVICE.bak" || exit 1
    fi

    # Create a temporary file
    TEMP_FILE=$(mktemp) || exit 1

    # Process the service file
    if ! sed -n '1,/^\[Service\]/p' "$SYSTEMD_SERVICE" > "$TEMP_FILE" && \
       while IFS= read -r line; do
           escaped_line=$(echo "$line" | sed 's/=/\\=/g')
           echo "Environment=$escaped_line" >> "$TEMP_FILE"
       done < "$ENV_FILE" && \
       sed -n '/^\[Service\]/,$p' "$SYSTEMD_SERVICE" | sed '/^Environment=/d' | tail -n +2 >> "$TEMP_FILE"; then
        rm -f "$TEMP_FILE"
        exit 1
    fi

    # Replace original file with new content
    if ! mv "$TEMP_FILE" "$SYSTEMD_SERVICE"; then
        rm -f "$TEMP_FILE"
        exit 1
    fi
}

setup_environment

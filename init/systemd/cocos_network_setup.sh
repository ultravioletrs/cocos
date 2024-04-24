#!/bin/sh

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

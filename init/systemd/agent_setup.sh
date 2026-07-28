#!/bin/sh

WORK_DIR="/cocos"
DOCKER_OVERRIDE_DIR="/etc/systemd/system/docker.service.d"
DOCKER_OVERRIDE_FILE="$DOCKER_OVERRIDE_DIR/override.conf"

# Docker runs on a writable bind mount while the rootfs itself stays ephemeral,
# so force RAM-disk mode to avoid pivot_root failures inside containers.
mkdir -p "$DOCKER_OVERRIDE_DIR"
if ! grep -qs '^Environment=DOCKER_RAMDISK=true$' "$DOCKER_OVERRIDE_FILE"; then
    tee "$DOCKER_OVERRIDE_FILE" > /dev/null <<EOF
[Service]
Environment=DOCKER_RAMDISK=true
EOF
    systemctl daemon-reload
fi

# Docker is required by the computation runner. Start the runtime stack here so
# later units don't depend on passive boot enablement or service ordering races.
systemctl start containerd.service
systemctl start docker.service

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

# RAM-only agent images use tmpfs as the root filesystem
ROOT_FSTYPE=$(awk '$2 == "/" { print $3; exit }' /proc/mounts)
if [ "$ROOT_FSTYPE" = "tmpfs" ]; then
    mount -o remount,size=100% /
fi

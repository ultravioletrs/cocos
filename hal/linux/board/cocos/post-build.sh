#!/bin/sh

set -u
set -e

# Add a console on tty1
if [ -e ${TARGET_DIR}/etc/inittab ]; then
    grep -qE '^tty1::' ${TARGET_DIR}/etc/inittab || \
    sed -i '/GENERIC_SERIAL/a\
tty1::respawn:/sbin/getty -L  tty1 0 vt100 # QEMU graphical window' ${TARGET_DIR}/etc/inittab
fi

# Create the mount points
# Create the mount points
mkdir -p ${TARGET_DIR}/etc/certs
mkdir -p ${TARGET_DIR}/mnt/env

# Ensure /etc/fstab exists
if [ ! -f "${TARGET_DIR}/etc/fstab" ]; then
    touch "${TARGET_DIR}/etc/fstab"
fi

# Add the 9p entries to /etc/fstab
grep -q "certs_share /etc/certs" ${TARGET_DIR}/etc/fstab || \
echo "certs_share /etc/certs 9p trans=virtio,version=9p2000.L,cache=mmap 0 0" >> "${TARGET_DIR}/etc/fstab"

grep -q "env_share /etc/cocos" ${TARGET_DIR}/etc/fstab || \
echo "env_share /etc/cocos 9p trans=virtio,version=9p2000.L,cache=mmap 0 0" >> "${TARGET_DIR}/etc/fstab"

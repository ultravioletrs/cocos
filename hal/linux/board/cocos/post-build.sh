#!/bin/sh

set -u
set -e

# Add a console on tty1
if [ -e ${TARGET_DIR}/etc/inittab ]; then
    grep -qE '^tty1::' ${TARGET_DIR}/etc/inittab || \
    sed -i '/GENERIC_SERIAL/a\
tty1::respawn:/sbin/getty -L  tty1 0 vt100 # QEMU graphical window' ${TARGET_DIR}/etc/inittab
fi

# Ensure /etc/fstab does not exists
if [ -f "${TARGET_DIR}/etc/fstab" ]; then
    rm "${TARGET_DIR}/etc/fstab"
fi

# Copy the init file into the target filesystem
cp ../cocos/init/init.sh ${TARGET_DIR}/init
chmod +x ${TARGET_DIR}/init

#!/bin/sh

set -e

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

/bin/mount -t devtmpfs devtmpfs /dev
if (exec 0</dev/console) 2>/dev/null; then
    exec 0</dev/console
    exec 1>/dev/console
    exec 2>/dev/console
fi

[ -d /dev ] || mkdir -m 0755 /dev
[ -d /root ] || mkdir -m 0700 /root
[ -d /sys ] || mkdir /sys
[ -d /proc ] || mkdir /proc
[ -d /tmp ] || mkdir /tmp

mount -t sysfs -o nodev,noexec,nosuid sysfs /sys
mount -t proc -o nodev,noexec,nosuid proc /proc

mount -t devtmpfs -o nosuid,mode=0755 udev /dev
mkdir /dev/pts
mount -t devpts -o noexec,nosuid,gid=5,mode=0620 devpts /dev/pts || true

MNT_DIR=/root
BASE=$(pwd)

SRC=/dev/nbd2
SRC_IP=147.91.12.238
SRC_PORT=10809

DST=/dev/sda
MAP="$(basename $DST)_crypt"
MAPPER="/dev/mapper/$MAP"

ROOT_PART=""
ROOT_PART_CANDIDATE1="/dev/mapper/${MAP}p1"
ROOT_PART_CANDIDATE2="/dev/mapper/${MAP}1"
ROOTFS_TYPE="ext4"
LUKS_PARAMS="--cipher aes-xts-plain64 --integrity hmac-sha256"


echo "[init] Starting encrypting disk..."

echo "[init] Assign IP address..."
dhclient

echo "[init] Connecting NBD service..."
nbd-client -N src "$SRC_IP" "$SRC_PORT" "$SRC"

echo "[init] Generating keyslot key..."
dd if=/dev/urandom of=kk.bin bs=64 count=1
KK_BIN=$BASE/kk.bin

echo "[init] Creating LUKS container and opening it..."
cryptsetup luksFormat "$DST" --type luks2 $LUKS_PARAMS --key-file="$KK_BIN" -q
cryptsetup open "$DST" "$MAP" --key-file="$KK_BIN"

echo "[clone] Copying raw blocks from $SRC → $MAPPER ..."
dd if="$SRC" of="$MAPPER" bs=16M oflag=direct conv=fsync

echo "[init] Disconnecting NBD..."
nbd-client -d "$SRC" || true

echo "[init] Triggering partition scan on $MAPPER..."
# partprobe "$MAPPER" 2>/dev/null || true
kpartx -av $MAPPER
sleep 1

# Detect root partition node created by kernel
if [ -b "$ROOT_PART_CANDIDATE1" ]; then
  ROOT_PART="$ROOT_PART_CANDIDATE1"
elif [ -b "$ROOT_PART_CANDIDATE2" ]; then
  ROOT_PART="$ROOT_PART_CANDIDATE2"
else
  echo "[init] Could not find root partition as ${ROOT_PART_CANDIDATE1} or ${ROOT_PART_CANDIDATE2}"
  echo "[init] Available block devices:"
  lsblk || true
  echo "[init] Dropping to shell."
  exec /bin/sh
fi

echo "[init] Using root partition: $ROOT_PART"

echo "[init] Mounting $ROOT_PART to $MNT_DIR..."
mount -t "$ROOTFS_TYPE" "$ROOT_PART" $MNT_DIR

mount --move /proc $MNT_DIR/proc
mount --move /sys $MNT_DIR/sys

mv $MNT_DIR/etc/fstab $MNT_DIR/etc/fstab.bak

exec switch_root $MNT_DIR/ /sbin/init

# If switch_root somehow returns:
echo "[init] switch_root failed, dropping to shell"
exec /sbin/init "$@"

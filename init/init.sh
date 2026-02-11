#!/bin/sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

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
DST=/dev/sda
MAP="$(basename $DST)_crypt"
MAPPER="/dev/mapper/$MAP"

ROOT_PART=""
ROOT_PART_CANDIDATE1="/dev/mapper/${MAP}p1"
ROOT_PART_CANDIDATE2="/dev/mapper/${MAP}1"
ROOTFS_TYPE="ext4"
LUKS_PARAMS="--cipher aes-xts-plain64"
HASH256=/hash_rootimg.sha256
HASH384=/hash_rootimg.sha384

# Parse kernel command line for src_ip, src_port
# Example usage: append 'src_ip=10.172.192.30 src_port=10809'
SRC_IP=""
SRC_PORT="10809"

for param in $(cat /proc/cmdline); do
    case "$param" in
        src_ip=*)
            SRC_IP="${param#src_ip=}"
            ;;
        src_port=*)
            SRC_PORT="${param#src_port=}"
            ;;
    esac
done

# Validate required parameters
if [ -z "$SRC_IP" ]; then
    echo "[init] FATAL: src_ip not provided in kernel command line"
    echo "[init] Usage: append 'src_ip=10.172.192.30' to kernel cmdline"
    echo "[init] Dropping to shell."
    exec /bin/sh
fi

echo "[init] Starting disk encryption..."
echo "[init] Source IP: $SRC_IP"
echo "[init] Source Port: $SRC_PORT"

echo "[init] Assign IP address..."
udhcpc || {
    echo "[init] FATAL: Failed to obtain IP address"
    exec /bin/sh
}

echo "[init] Connecting NBD service..."
timeout 30 nbd-client -N src "$SRC_IP" "$SRC_PORT" "$SRC" || {
    echo "[init] FATAL: NBD connection failed or timed out"
    exec /bin/sh
}

echo "[init] Generating keyslot key..."
dd if=/dev/urandom of=kk.bin bs=64 count=1 || {
    echo "[init] FATAL: Failed to generate encryption key"
    nbd-client -d "$SRC" 2>/dev/null
    exec /bin/sh
}
KK_BIN=$BASE/kk.bin

echo "[init] Creating LUKS container and opening it..."
cryptsetup luksFormat "$DST" --type luks2 $LUKS_PARAMS --key-file="$KK_BIN" -q || {
    echo "[init] FATAL: LUKS format failed"
    shred -vfz -n 3 "$KK_BIN" 2>/dev/null || dd if=/dev/zero of="$KK_BIN" bs=64 count=1
    nbd-client -d "$SRC" 2>/dev/null
    exec /bin/sh
}

cryptsetup open "$DST" "$MAP" --key-file="$KK_BIN" || {
    echo "[init] FATAL: Failed to open LUKS container"
    shred -vfz -n 3 "$KK_BIN" 2>/dev/null || dd if=/dev/zero of="$KK_BIN" bs=64 count=1
    nbd-client -d "$SRC" 2>/dev/null
    exec /bin/sh
}

echo "[clone] Copying raw blocks from $SRC → $MAPPER ..."

# Copy the data
dd if="$SRC" bs=16M iflag=fullblock of="$MAPPER" oflag=direct conv=fsync || {
    echo "[init] FATAL: Disk copy failed"
    cryptsetup close "$MAP" 2>/dev/null
    shred -vfz -n 3 "$KK_BIN" 2>/dev/null || dd if=/dev/zero of="$KK_BIN" bs=64 count=1
    nbd-client -d "$SRC" 2>/dev/null
    exec /bin/sh
}

sync

# Hash the destination after copy
echo "[init] Computing SHA-256..."
DISK_HASH256=$(dd if="$MAPPER" bs=16M iflag=fullblock 2>/dev/null | sha256sum | cut -d' ' -f1)

echo "[init] Computing SHA-384..."
DISK_HASH384=$(dd if="$MAPPER" bs=16M iflag=fullblock 2>/dev/null | sha384sum | cut -d' ' -f1)

echo "$DISK_HASH256" > "$HASH256"
echo "$DISK_HASH384" > "$HASH384"

echo "[init] Disconnecting NBD..."
nbd-client -d "$SRC" 2>&1 || echo "[init] Warning: NBD disconnect failed"

# Extract and verify hashes
DISK_HASH256=$(cut -d' ' -f1 "$HASH256")
DISK_HASH384=$(cut -d' ' -f1 "$HASH384")

echo "[init] Computed SHA-256: $DISK_HASH256"
echo "[init] Computed SHA-384: $DISK_HASH384"

# Extend TPM PCR with disk hash
if [ -e /dev/tpm0 ] && [ -e /dev/sev-guest ]; then
    echo "[init] vTPM and SEV-SNP devices present, extending PCR16..."
    
    # Build the command with optional SHA-384
    PCR_EXTEND_CMD="tpm2_pcrextend 16:sha256=$DISK_HASH256"
    [ -n "$DISK_HASH384" ] && PCR_EXTEND_CMD="$PCR_EXTEND_CMD 16:sha384=$DISK_HASH384"
    
    eval "$PCR_EXTEND_CMD" || {
        echo "[init] Warning: PCR extension failed"
    }
else
    echo "[init] vTPM or SEV-SNP device missing, skipping PCR extension"
fi

echo "[init] Triggering partition scan on $MAPPER..."
kpartx -av $MAPPER || {
    echo "[init] FATAL: kpartx failed"
    cryptsetup close "$MAP" 2>/dev/null
    shred -vfz -n 3 "$KK_BIN" 2>/dev/null || dd if=/dev/zero of="$KK_BIN" bs=64 count=1
    exec /bin/sh
}

# Wait for device to settle instead of arbitrary sleep
echo "[init] Waiting for devices to settle..."
if command -v udevadm >/dev/null 2>&1; then
    udevadm settle --timeout=10 || sleep 2
else
    sleep 2
fi

# Detect root partition node created by kernel
if [ -b "$ROOT_PART_CANDIDATE1" ]; then
  ROOT_PART="$ROOT_PART_CANDIDATE1"
elif [ -b "$ROOT_PART_CANDIDATE2" ]; then
  ROOT_PART="$ROOT_PART_CANDIDATE2"
else
  echo "[init] Could not find root partition as ${ROOT_PART_CANDIDATE1} or ${ROOT_PART_CANDIDATE2}"
  echo "[init] Available block devices:"
  lsblk || ls -la /dev/mapper/ || true
  echo "[init] Dropping to shell."
  cryptsetup close "$MAP" 2>/dev/null
  shred -vfz -n 3 "$KK_BIN" 2>/dev/null || dd if=/dev/zero of="$KK_BIN" bs=64 count=1
  exec /bin/sh
fi

echo "[init] Using root partition: $ROOT_PART"

echo "[init] Mounting $ROOT_PART to $MNT_DIR..."
mount -t "$ROOTFS_TYPE" "$ROOT_PART" $MNT_DIR || {
    echo "[init] FATAL: Failed to mount root partition"
    cryptsetup close "$MAP" 2>/dev/null
    shred -vfz -n 3 "$KK_BIN" 2>/dev/null || dd if=/dev/zero of="$KK_BIN" bs=64 count=1
    exec /bin/sh
}

mount --move /proc $MNT_DIR/proc
mount --move /sys $MNT_DIR/sys

# Backup old fstab and create new one for encrypted root
if [ -f $MNT_DIR/etc/fstab ]; then
    mv $MNT_DIR/etc/fstab $MNT_DIR/etc/fstab.bak
fi

# Generate basic fstab for encrypted root
cat > $MNT_DIR/etc/fstab << EOF
# Generated by init script for encrypted root
$ROOT_PART / $ROOTFS_TYPE defaults 0 1
EOF

# Securely wipe the encryption key before switching root
echo "[init] Securely wiping encryption key..."
shred -vfz -n 3 "$KK_BIN" 2>/dev/null || dd if=/dev/zero of="$KK_BIN" bs=64 count=1
rm -f "$KK_BIN"

echo "[init] Switching to real root..."
exec switch_root $MNT_DIR/ /sbin/init

# If switch_root somehow returns:
echo "[init] switch_root failed, dropping to shell"
exec /bin/sh

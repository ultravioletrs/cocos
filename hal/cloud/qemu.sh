#!/bin/bash

# Base image URL and names
BASE_IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
BASE_IMAGE="ubuntu-base.qcow2"
CUSTOM_IMAGE="ubuntu-custom.qcow2"

# Paths for OVMF firmware
OVMF_CODE="/usr/share/ovmf/x64/OVMF_CODE.4m.fd"
OVMF_VARS="/usr/share/ovmf/x64/OVMF_VARS.4m.fd"

# VM parameters
VM_NAME="cocos-vm"
RAM="16G"
CPU="8"
DISK_SIZE="10G" # Size for root filesystem
QEMU_BINARY="qemu-system-x86_64"


# Required commands
REQUIRED_CMDS=("wget" "cloud-localds" "$QEMU_BINARY" "qemu-img")

# Check for required commands
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed. Please install it and try again."
        exit 1
    fi
done

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi


# Create the root filesystem image if it doesn't exist
if [ ! -f $BASE_IMAGE ]; then
  echo "Downloading base Ubuntu image..."
  wget -q $BASE_IMAGE_URL -O $BASE_IMAGE --show-progress
fi

# Create custom image
echo "Creating custom QEMU image..."
qemu-img create -f qcow2 -b $BASE_IMAGE -F qcow2 $CUSTOM_IMAGE $DISK_SIZE

# Cloud-init configuration files
USER_DATA="user-data"
META_DATA="meta-data"
SEED_IMAGE="seed.img"

# Create seed image for cloud-init
echo "Creating seed image..."
cloud-localds $SEED_IMAGE $USER_DATA $META_DATA

# Start QEMU
echo "Starting QEMU VM..."
$QEMU_BINARY \
  -name $VM_NAME \
  -m $RAM \
  -smp $CPU \
  -machine q35 \
  -enable-kvm \
  -boot d \
  -netdev user,id=vmnic,hostfwd=tcp::6190-:22,hostfwd=tcp::6191-:80,hostfwd=tcp::6192-:443,hostfwd=tcp::6193-:3001 \
  -device e1000,netdev=vmnic,romfile= \
  -vnc :9 \
  -nographic \
  -no-reboot \
  -drive file=$SEED_IMAGE,media=cdrom \
  -drive file=$CUSTOM_IMAGE,if=none,id=disk0,format=qcow2 \
  -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true \
  -device scsi-hd,drive=disk0 \
  -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=198 \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
  -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=$OVMF_VARS
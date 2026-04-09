#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_DIR="$(cd "$SCRIPT_DIR/../cloud" && pwd)"

source "$CLOUD_DIR/.env"

SEED_ISO="${SEED_ISO:-$SCRIPT_DIR/seed.iso}"
META_DATA="${META_DATA:-$CLOUD_DIR/meta-data}"
BASE_IMAGE_PATH="${BASE_IMAGE_PATH:-$SCRIPT_DIR/$BASE_IMAGE}"
CUSTOM_IMAGE_PATH="${CUSTOM_IMAGE_PATH:-$SCRIPT_DIR/$CUSTOM_IMAGE}"
OVMF_FILE="${OVMF_FILE:-${OVMF_FD:-${OVMF_CODE_FILE:-${OVMF_CODE:-}}}}"

REQUIRED_CMDS=("wget" "$QEMU_BINARY" "qemu-img")

for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: $cmd is not installed. Please install it and try again." >&2
        exit 1
    fi
done

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

if [ ! -x "$SCRIPT_DIR/create-seed-iso.sh" ]; then
    echo "Error: create-seed-iso.sh is missing or not executable." >&2
    exit 1
fi

if [ ! -f "$META_DATA" ]; then
    echo "Error: meta-data file not found at $META_DATA" >&2
    exit 1
fi

if [ -z "$OVMF_FILE" ] || [ ! -f "$OVMF_FILE" ]; then
    echo "Error: OVMF firmware file not found at $OVMF_FILE" >&2
    exit 1
fi

mkdir -p "$SCRIPT_DIR"

if [ ! -f "$BASE_IMAGE_PATH" ]; then
    echo "Downloading base Ubuntu image..."
    wget -q "$BASE_IMAGE_URL" -O "$BASE_IMAGE_PATH" --show-progress
fi

echo "Creating seed ISO..."
"$SCRIPT_DIR/create-seed-iso.sh" "$SEED_ISO"

rm -f "$CUSTOM_IMAGE_PATH"
echo "Creating custom QEMU image..."
qemu-img create -f qcow2 -b "$BASE_IMAGE_PATH" -F qcow2 "$CUSTOM_IMAGE_PATH" "$DISK_SIZE"

construct_qemu_args() {
    QEMU_ARGS=()

    QEMU_ARGS+=("-name" "$VM_NAME")

    if [ "$ENABLE_KVM" = "true" ]; then
        QEMU_ARGS+=("-enable-kvm")
    fi

    if [ -n "$MACHINE" ]; then
        QEMU_ARGS+=("-machine" "$MACHINE")
    fi

    if [ -n "$CPU" ]; then
        QEMU_ARGS+=("-cpu" "$CPU")
    fi

    QEMU_ARGS+=("-boot" "d")
    QEMU_ARGS+=("-smp" "$SMP_COUNT,maxcpus=$SMP_MAXCPUS")
    QEMU_ARGS+=("-m" "$MEMORY_SIZE,slots=$MEMORY_SLOTS,maxmem=$MAX_MEMORY")
    QEMU_ARGS+=("-bios" "$OVMF_FILE")

    QEMU_ARGS+=("-netdev" "user,id=$NET_DEV_ID,hostfwd=tcp::$NET_DEV_HOST_FWD_AGENT-:$NET_DEV_GUEST_FWD_AGENT")
    QEMU_ARGS+=("-device" "virtio-net-pci,disable-legacy=$VIRTIO_NET_PCI_DISABLE_LEGACY,iommu_platform=$VIRTIO_NET_PCI_IOMMU_PLATFORM,netdev=$NET_DEV_ID,addr=$VIRTIO_NET_PCI_ADDR,romfile=$VIRTIO_NET_PCI_ROMFILE")

    QEMU_ARGS+=("-drive" "file=$SEED_ISO,media=cdrom")
    QEMU_ARGS+=("-drive" "file=$CUSTOM_IMAGE_PATH,if=none,id=disk0,format=qcow2")
    QEMU_ARGS+=("-device" "virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true")
    QEMU_ARGS+=("-device" "scsi-hd,drive=disk0")

    if [ "$NO_GRAPHIC" = "true" ]; then
        QEMU_ARGS+=("-nographic")
    fi

    QEMU_ARGS+=("-monitor" "$MONITOR")
    QEMU_ARGS+=("-vnc" ":9")
}

QEMU_ARGS=()
construct_qemu_args

echo "Running QEMU with the following arguments: ${QEMU_ARGS[*]}"
echo "Starting QEMU VM..."
"$QEMU_BINARY" "${QEMU_ARGS[@]}"

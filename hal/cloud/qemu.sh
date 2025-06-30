#!/bin/bash

# Source environment variables
source ./.env

# Required commands
REQUIRED_CMDS=("wget" "cloud-localds" "$QEMU_BINARY" "qemu-img")

# Check for required commands
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
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
if [ ! -f "$BASE_IMAGE" ]; then
  echo "Downloading base Ubuntu image..."
  wget -q "$BASE_IMAGE_URL" -O "$BASE_IMAGE" --show-progress
fi

# Create custom image
echo "Creating custom QEMU image..."
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$CUSTOM_IMAGE" "$DISK_SIZE"

# Cloud-init configuration files
CLOUD_CONFIG="config.yaml"
META_DATA="meta-data"
SEED_IMAGE="seed.img"

# Create seed image for cloud-init
echo "Creating seed image..."
cloud-localds "$SEED_IMAGE" "$CLOUD_CONFIG" "$META_DATA"

# Construct QEMU arguments from environment variables
construct_qemu_args() {
    args=()

    args+=("-name" "$VM_NAME")

    # Virtualization (Enable KVM)
    if [ "$ENABLE_KVM" == "true" ]; then
        args+=("-enable-kvm")
    fi

    # Machine, CPU, RAM
    if [ -n "$MACHINE" ]; then
        args+=("-machine" "$MACHINE")
    fi

    if [ -n "$CPU" ]; then
        args+=("-cpu" "$CPU")
    fi

    args+=("-boot" "d")
    args+=("-smp" "$SMP_COUNT,maxcpus=$SMP_MAXCPUS")
    args+=("-m" "$MEMORY_SIZE,slots=$MEMORY_SLOTS,maxmem=$MAX_MEMORY")

    # OVMF (if applicable)
    if [ "$ENABLE_SEV_SNP" != "true" ]; then
        args+=("-drive" "if=$OVMF_CODE_IF,format=$OVMF_CODE_FORMAT,unit=$OVMF_CODE_UNIT,file=$OVMF_CODE,readonly=$OVMF_CODE_READONLY")
        args+=("-drive" "if=$OVMF_VARS_IF,format=$OVMF_VARS_FORMAT,unit=$OVMF_VARS_UNIT,file=$OVMF_VARS")
    fi

    # Network configuration
    args+=("-netdev" "user,id=$NET_DEV_ID,hostfwd=tcp::$NET_DEV_HOST_FWD_AGENT-:$NET_DEV_GUEST_FWD_AGENT")
    args+=("-device" "virtio-net-pci,disable-legacy=$VIRTIO_NET_PCI_DISABLE_LEGACY,iommu_platform=$VIRTIO_NET_PCI_IOMMU_PLATFORM,netdev=$NET_DEV_ID,addr=$VIRTIO_NET_PCI_ADDR,romfile=$VIRTIO_NET_PCI_ROMFILE")
    args+=("-device" "vhost-vsock-pci,id=$VSOCK_ID,guest-cid=$VSOCK_GUEST_CID")

    # SEV_SNP (if enabled)
    if [ "$ENABLE_SEV_SNP" == "true" ]; then
        kernel_hash=""
        host_data=""

        args+=("-machine" "confidential-guest-support=$SEV_ID,memory-backend=$MEM_ID")

        args+=("-bios" "$OVMF_CODE_FILE")
        sev_snp_type="sev-snp-guest"

        if [ -n "$SEV_HOST_DATA" ]; then
            host_data=",host-data=$SEV_HOST_DATA"
        fi

        if [ "$ENABLE_KERNEL_HASH" == "true" ]; then
            kernel_hash=",kernel-hashes=on"
        fi

        args+=("-object" "memory-backend-memfd,id=$MEM_ID,size=$MEMORY_SIZE,share=true,prealloc=false")
        args+=("-object" "$sev_snp_type,id=$SEV_ID,cbitpos=$SEV_CBIT_POS,reduced-phys-bits=$SEV_REDUCED_PHYS_BITS$kernel_hash$host_data")
    fi

    # Disk image configuration
    args+=("-drive" "file=$SEED_IMAGE,media=cdrom")
    args+=("-drive" "file=$CUSTOM_IMAGE,if=none,id=disk0,format=qcow2")
    args+=("-device" "virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true")
    args+=("-device" "scsi-hd,drive=disk0")

    # Display options
    if [ "$NO_GRAPHIC" == "true" ]; then
        args+=("-nographic")
    fi

    args+=("-monitor" "$MONITOR")
    args+=("-vnc" ":9")

    echo "${args[@]}"
}

qemu_args=$(construct_qemu_args)

echo "Running QEMU with the following arguments: $qemu_args"
echo "Starting QEMU VM..."
$QEMU_BINARY $qemu_args

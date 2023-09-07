#!/bin/bash

# Set your default values for sudo and sev
sudo_option=false
sev_option=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        --sudo)
            sudo_option=true
            shift
            ;;
        --sev)
            sev_option=true
            shift
            ;;
        *)
            echo "Unknown option: $key"
            exit 1
            ;;
    esac
done

build_qemu_command() {
    local qemu_command="/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 2048M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=$MANAGER_QEMU_OVMF_CODE_FILE,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty"

    if [ "$sev_option" = true ]; then
        qemu_command="$qemu_command -object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0"
    fi

    echo "$qemu_command"
}

if [ ! -f "img/OVMF_VARS.fd" ]; then
    cp "$MANAGER_QEMU_OVMF_VARS_FILE" "img/OVMF_VARS.fd"
    echo "Copied $MANAGER_QEMU_OVMF_VARS_FILE to img/OVMF_VARS.fd"
else
    echo "img/OVMF_VARS.fd already exists. No need to copy."
fi

echo "Launching VM ..."

qemu_command=$(build_qemu_command)
echo "$qemu_command"

echo "Mapping CTRL-C to CTRL-]"
stty intr ^]

if [ "$sudo_option" = true ]; then
    # Split the command and arguments into an array; << operator is known as a "here string"
    IFS=" " read -r -a qemu_command_array <<< "$qemu_command"
    # Treat each element in the array as a separate word, preserving spaces within each element
    sudo "${qemu_command_array[@]}"
else
    $qemu_command
fi

# Restore the mapping
stty intr ^c

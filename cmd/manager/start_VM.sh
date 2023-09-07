#!/bin/bash

echo "Mapping CTRL-C to CTRL-]"
stty intr ^]

#!/bin/bash

# Check if the destination file exists
if [ ! -f "img/OVMF_VARS.fd" ]; then
  # Copy $MANAGER_QEMU_OVMF_VARS_FILE to the destination
  cp "$MANAGER_QEMU_OVMF_VARS_FILE" "img/OVMF_VARS.fd"
  echo "Copied $MANAGER_QEMU_OVMF_VARS_FILE to img/OVMF_VARS.fd"
else
  echo "img/OVMF_VARS.fd already exists. No need to copy."
fi

echo "Launching VM ..."
/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 2048M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=$MANAGER_QEMU_OVMF_CODE_FILE,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty

# restore the mapping
stty intr ^c
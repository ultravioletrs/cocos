#!/bin/bash

/usr/bin/qemu-system-x86_64 \
  -enable-kvm \
  -cpu EPYC \
  -machine q35 \
  -smp 4,maxcpus=64 \
  -m 4096M,slots=5,maxmem=30G \
  -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly \
  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd \
  -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 \
  -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
  -drive file=./focal-server-cloudimg-amd64.qcow2,if=none,id=disk0,format=qcow2 \
  -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true \
  -device scsi-hd,drive=disk0 \
  -vga qxl \
  -monitor pty

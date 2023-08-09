#!/bin/bash

#
# user changeable parameters
#

HDA_FILE="cmd/manager/img/focal-server-cloudimg-amd64.qcow2"
GUEST_SIZE_IN_MB="4096"
SEV_GUEST="1"
SMP_NCPUS="4"
CONSOLE="serial"
VNC_PORT=""
USE_VIRTIO="1"

UEFI_BIOS_CODE="/usr/share/OVMF/OVMF_CODE.fd"
UEFI_BIOS_VARS_ORIG="/usr/share/OVMF/OVMF_VARS.fd"
UEFI_BIOS_VARS_COPY="cmd/manager/img/OVMF_VARS.fd"

CBITPOS=51
HOST_HTTP_PORT=9301
GUEST_HTTP_PORT=9031
HOST_GRPC_PORT=7020
GUEST_GRPC_PORT=7002

ENABLE_FILE_LOG="0"
EXEC_QEMU_CMDLINE="0"

usage() {
    echo "$0 [options]"
    echo "Available <commands>:"
    echo " -hda           hard disk ($HDA_FILE)"
    echo " -nosev         disable sev support"
    echo " -mem           guest memory"
    echo " -smp           number of cpus"
    echo " -console       display console to use (serial or gxl)"
    echo " -vnc           VNC port to use"
    echo " -bios          bios to use (default $UEFI_BIOS_CODE)"
    echo " -kernel        kernel to use"
    echo " -initrd        initrd to use"
    echo " -cdrom         CDROM image"
    echo " -virtio        use virtio devices"
    echo " -cbitpos       location of the C-bit"
    echo " -hosthttp      host http port"
    echo " -guesthttp     guest http port"
    echo " -hostgrpc      host grpc port"
    echo " -guestgrpc     guest grpc port"
    echo " -origuefivars  UEFI BIOS vars original file (default $UEFI_BIOS_VARS_ORIG)"
    echo " -copyuefivars  UEFI BIOS vars copy file (default $UEFI_BIOS_VARS_COPY)"
    echo " -exec          execute the QEMU command (default $EXEC_QEMU_CMDLINE)"
    echo " -filelog       enable/disable QEMU cmd line file log (default: $ENABLE_FILE_LOG)"
    exit 1
}

while [[ $1 != "" ]]; do
    case "$1" in
        -hda)
            HDA_FILE=${2}
            shift
            ;;
        -nosev)
            SEV_GUEST="0"
            ;;
        -mem)
            GUEST_SIZE_IN_MB=${2}
            shift
            ;;
        -console)
            CONSOLE=${2}
            shift
            ;;
        -smp)
            SMP_NCPUS=$2
            shift
            ;;
        -vnc)
            VNC_PORT=$2
            shift
            ;;
        -bios)
            UEFI_BIOS_CODE=$2
            shift
            ;;
        -initrd)
            INITRD_FILE=$2
            shift
            ;;
        -kernel)
            KERNEL_FILE=$2
            shift
            ;;
        -cdrom)
            CDROM_FILE=$2
            shift
            ;;
        -virtio)
            USE_VIRTIO="1"
            ;;
        -cbitpos)
            CBITPOS=$2
            shift
            ;;
        -hosthttp)
            HOST_HTTP_PORT=$2
            shift
            ;;
        -guesthttp)
            GUEST_HTTP_PORT=$2
            shift
            ;;
        -guestgrpc)
            GUEST_GRPC_PORT=$2
            shift
            ;;
        -hostgrpc)
            HOST_GRPC_PORT=$2
            shift
            ;;
        -origuefivars)
            UEFI_BIOS_VARS_ORIG=$2
            shift
            ;;
        -copyuefivars)
            UEFI_BIOS_VARS_COPY=$2
            shift
            ;;        
        -exec)
            EXEC_QEMU_CMDLINE="1"
            ;;      
        -filelog)
            ENABLE_FILE_LOG="1"
            ;;                           
        *)
            usage;;
    esac
    shift
done

#
# func definitions
#

add_opts() {
    echo -n "$* " >> ${QEMU_CMDLINE}
}

run_cmd() {
    if ! "$@"; then
        echo "Command '$*' failed"
        exit 1
    fi
}

# if [ "$(id -u)" -ne 0 ]; then
#     echo "This script must be run as root!"
#     exit 1
# fi

# copy BIOS variables to new dest for VM use without modifying the original ones
cp "$UEFI_BIOS_VARS_ORIG" "$UEFI_BIOS_VARS_COPY"

#
# Qemu cmd line construction
#

# we add all the qemu command line options into a file
QEMU_CMDLINE=/tmp/cmdline.$$
rm -rf ${QEMU_CMDLINE}

add_opts "$(which qemu-system-x86_64)"

# Basic virtual machine property
add_opts "-enable-kvm -cpu EPYC -machine q35"

# add number of VCPUs
[ -n "$SMP_NCPUS" ] && add_opts "-smp ${SMP_NCPUS},maxcpus=64"

# define guest memory
add_opts "-m ${GUEST_SIZE_IN_MB}M,slots=5,maxmem=30G"

# The OVMF binary, including the non-volatile variable store, appears as a
# "normal" qemu drive on the host side, and it is exposed to the guest as a
# persistent flash device.
add_opts "-drive if=pflash,format=raw,unit=0,file=${UEFI_BIOS_CODE},readonly=on"
add_opts "-drive if=pflash,format=raw,unit=1,file=${UEFI_BIOS_VARS_COPY}"

# add CDROM if specified
[ -n "$CDROM_FILE" ] && add_opts "-drive file=${CDROM_FILE},media=cdrom -boot d"

add_opts "-netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::$HOST_HTTP_PORT-:$GUEST_HTTP_PORT,hostfwd=tcp::$HOST_GRPC_PORT-:$GUEST_GRPC_PORT"
add_opts "-device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile="

# If harddisk file is specified then add the HDD drive
if [ -n "$HDA_FILE" ]; then
    if [ "$USE_VIRTIO" = "1" ]; then
        if [[ ${HDA_FILE} = *"qcow2" ]]; then
            add_opts "-drive file=${HDA_FILE},if=none,id=disk0,format=qcow2"
        else
            add_opts "-drive file=${HDA_FILE},if=none,id=disk0,format=raw"
        fi
        add_opts "-device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true"
        add_opts "-device scsi-hd,drive=disk0"
    else
        if [[ ${HDA_FILE} = *"qcow2" ]]; then
            add_opts "-drive file=${HDA_FILE},format=qcow2"
        else
            add_opts "-drive file=${HDA_FILE},format=raw"
        fi
    fi
fi

# If this is SEV guest then add the encryption device objects to enable support
if [ ${SEV_GUEST} = "1" ]; then
    add_opts "-object sev-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=1"
    add_opts "-machine memory-encryption=sev0"
fi

# if console is serial then disable graphical interface
if [ "${CONSOLE}" = "serial" ]; then
    add_opts "-nographic"
else
    add_opts "-vga ${CONSOLE}"
fi

# if -kernel arg is specified then use the kernel provided in command line for boot
if [ "${KERNEL_FILE}" != "" ]; then
    add_opts "-kernel $KERNEL_FILE"
    add_opts "-append \"console=ttyS0 earlyprintk=serial root=/dev/sda2\""
    [ -n "$INITRD_FILE" ] && add_opts "-initrd ${INITRD_FILE}"
fi

# start vnc server
[ -n "$VNC_PORT" ] && add_opts "-vnc :${VNC_PORT}" && echo "Starting VNC on port ${VNC_PORT}"

# start monitor on pty
add_opts "-monitor pty"

#
# Qemu cmd line log
#

# Set the log file path if ENABLE_FILE_LOG is 1
if [ "$ENABLE_FILE_LOG" = "1" ]; then
    LOG_FILE=$(pwd)/stdout.log

    # Save the command line args into log file
    cat "$QEMU_CMDLINE" > "$LOG_FILE"
    echo >> "$LOG_FILE"
fi

 # Log the command line to the console
cat "$QEMU_CMDLINE"

#
# Qemu cmd line execution
#

if [[ "${EXEC_QEMU_CMDLINE}" = "0" ]]; then
    exit 0
fi

# map CTRL-C to CTRL ]
echo "Mapping CTRL-C to CTRL-]"
stty intr ^]

echo "Launching VM ..."
if [ "$ENABLE_FILE_LOG" = "1" ]; then
    bash ${QEMU_CMDLINE} 2>&1 | tee -a "${LOG_FILE}"
else 
    bash ${QEMU_CMDLINE} 2>&1
fi

# restore the mapping
stty intr ^c

rm -rf ${QEMU_CMDLINE}

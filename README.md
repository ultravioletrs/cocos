# Manager for Cocos AI

## Setup

```sh
git clone https://github.com/ultravioletrs/manager
cd manager
```

NB: all relative paths in this document are relative to `manager` repository directory.

### QEMU-KVM

[QEMU-KVM](https://www.qemu.org/) is a virtualization platform that allows you to run multiple operating systems on the same physical machine. It is a combination of two technologies: QEMU and KVM.

- QEMU is an emulator that can run a variety of operating systems, including Linux, Windows, and macOS.
- [KVM](https://wiki.qemu.org/Features/KVM) is a Linux kernel module that allows QEMU to run virtual machines.

To install QEMU-KVM on a Debian based machine, run

```sh
sudo apt update
sudo apt install qemu-kvm
```

Create `img` directory in `cmd/manager`.

### focal-server-cloudimg-amd64.img

First, we will download *focal-server-cloudimg-amd64*. It is a `qcow2` file with Ubuntu server preinstalled, ready to use with the QEMU virtual machine.

```sh
cd cmd/manager/img
wget https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img
# focal-server-cloudimg-amd64 comes without the root password.
sudo apt-get install libguestfs-tools
sudo virt-customize -a focal-server-cloudimg-amd64.img --root-password password:coolpass
```

### OVMF

We need [Open Virtual Machine Firmware](https://wiki.ubuntu.com/UEFI/OVMF). OVMF is a port of Intel's tianocore firmware - an open source implementation of the Unified Extensible Firmware Interface (UEFI) - to the qemu virtual machine. We need OVMF in order to run virtual machine with *focal-server-cloudimg-amd64*. When we install QEMU, we get two files that we need to start a VM: `OVMF_VARS.fd` and `OVMF_CODE.fd`. We will make a local copy of `OVMF_VARS.fd` since a VM will modify this file. On the other hand, `OVMF_CODE.fd` is only used as a reference, so we only record its path in an environment variable.

```sh
cd cmd/manager/img

sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
MANAGER_QEMU_OVMF_CODE_FILE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd
cp /usr/share/OVMF/OVMF_VARS.fd .
MANAGER_QEMU_OVMF_VARS_FILE=img/OVMF_VARS.fd
```

## Run

We need to run `manager` in the directory where `img`, `iso` and `xml` directories are. `cd` to `cmd/manager` and run

```sh
cd cmd/manager
MANAGER_LOG_LEVEL=info MANAGER_AGENT_GRPC_URL=192.168.122.251:7002 MANAGER_QEMU_USE_SUDO=false MANAGER_QEMU_ENABLE_SEV=false go run main.go
```

To enable [AMD SEV](https://www.amd.com/en/developer/sev.html) support, start manager like this 

```sh
cd cmd/manager
MANAGER_LOG_LEVEL=info MANAGER_AGENT_GRPC_URL=192.168.122.251:7002 MANAGER_QEMU_USE_SUDO=true MANAGER_QEMU_ENABLE_SEV=true MANAGER_QEMU_SEV_CBITPOS=51 go run main.go
```

Manager will start an HTTP server on port `9021`, and a gRPC server on port `7001`.

To check whether the manager launched the VM successfully, run

```sh
ps aux | grep qemu-system-x86_64
```

You should get something similar to this
```
darko     324763 95.3  6.0 6398136 981044 ?      Sl   16:17   0:15 /usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty
```

If you run a command as `sudo`, you should get the output similar to this one

```
root       37982  0.0  0.0   9444  4572 pts/0    S+   16:18   0:00 sudo /usr/local/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0 -nographic -monitor pty
root       37989  122 13.1 5345816 4252312 pts/0 Sl+  16:19   0:04 /usr/local/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0 -nographic -monitor pty
```

The two processes are due to the fact that we run the command `/usr/bin/qemu-system-x86_64` as `sudo`, so there is one process for `sudo` command and the other for `/usr/bin/qemu-system-x86_64`.
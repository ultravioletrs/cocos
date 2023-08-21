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

Create `img` directory in `cmd/manager`. Create `tmp` directory in `cmd/manager`.

### focal-server-cloudimg-amd64.img

First, we will download *focal-server-cloudimg-amd64*. It is a `qcow2` file with Ubuntu server preinstalled, ready to use with the QEMU virtual machine.

```sh
FOCAL=focal-server-cloudimg-amd64.img
cd cmd/manager
wget -O img/$FOCAL$ https://cloud-images.ubuntu.com/focal/current/$FOCAL
# focal-server-cloudimg-amd64 comes without the root password
sudo apt-get install libguestfs-tools
PASSWORD=coolpass
sudo virt-customize -a img/$FOCAL --root-password password:$PASSWORD
```

### OVMF

We need [Open Virtual Machine Firmware](https://wiki.ubuntu.com/UEFI/OVMF). OVMF is a port of Intel's tianocore firmware - an open source implementation of the Unified Extensible Firmware Interface (UEFI) - used by a qemu virtual machine. We need OVMF in order to run virtual machine with *focal-server-cloudimg-amd64*. When we install QEMU, we get two files that we need to start a VM: `OVMF_VARS.fd` and `OVMF_CODE.fd`. We will make a local copy of `OVMF_VARS.fd` since a VM will modify this file. On the other hand, `OVMF_CODE.fd` is only used as a reference, so we only record its path in an environment variable.

```sh
sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
MANAGER_QEMU_OVMF_CODE_FILE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd
MANAGER_QEMU_OVMF_VARS_FILE=/usr/share/OVMF/OVMF_VARS.fd
```

NB: we set environment variables that we will use in the shell process where we run `manager`.

## Run

We need to run `manager` in the directory containing `img` directory:

```sh
cd cmd/manager
MANAGER_LOG_LEVEL=info MANAGER_AGENT_GRPC_URL=localhost:7002 MANAGER_QEMU_USE_SUDO=false MANAGER_QEMU_ENABLE_SEV=false go run main.go
```

To enable [AMD SEV](https://www.amd.com/en/developer/sev.html) support, start manager like this 

```sh
cd cmd/manager
MANAGER_LOG_LEVEL=info MANAGER_AGENT_GRPC_URL=192.168.122.251:7002 MANAGER_QEMU_USE_SUDO=true MANAGER_QEMU_ENABLE_SEV=true MANAGER_QEMU_SEV_CBITPOS=51 go run main.go
```

Manager will start an HTTP server on port `9021`, and a gRPC server on port `7001`.

### Create QEMU virtual machine (VM)

To create an instance of VM and run a computation, run

```sh
curl -sSi -X POST \
  http://localhost:9021/run \
  -H "Content-Type: application/json" \
  -d '{
    "computation": [123, 34, 105, 100, 34, 58, 34, 48, 48, 97, 99, 102, 101, 57, 100, 45, 53, 101, 49, 98, 45, 52, 97, 101, 99, 45, 56, 50, 99, 48, 45, 56, 48, 97, 98, 56, 101, 100, 53, 101, 99, 48, 98, 34, 44, 34, 110, 97, 109, 101, 34, 58, 34, 77, 97, 99, 104, 105, 110, 101, 32, 68, 105, 97, 103, 110, 111, 115, 116, 105, 99, 115, 32, 65, 110, 97, 108, 121, 115, 105, 115, 34, 44, 34, 100, 101, 115, 99, 114, 105, 112, 116, 105, 111, 110, 34, 58, 34, 80, 101, 114, 102, 111, 114, 109, 105, 110, 103, 32, 100, 105, 97, 103, 110, 111, 115, 116, 105, 99, 115, 32, 97, 110, 97, 108, 121, 115, 105, 115, 32, 111, 110, 32, 109, 97, 99, 104, 105, 110, 101, 32, 100, 97, 116, 97, 34, 44, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 101, 120, 101, 99, 117, 116, 97, 98, 108, 101, 34, 44, 34, 111, 119, 110, 101, 114, 34, 58, 34, 77, 97, 99, 104, 105, 110, 101, 32, 73, 110, 100, 117, 115, 116, 114, 105, 101, 115, 32, 73, 110, 99, 46, 34, 44, 34, 115, 116, 97, 114, 116, 95, 116, 105, 109, 101, 34, 58, 34, 50, 48, 50, 51, 45, 48, 56, 45, 50, 49, 84, 49, 50, 58, 48, 50, 58, 51, 49, 46, 48, 48, 55, 53, 48, 53, 90, 34, 44, 34, 101, 110, 100, 95, 116, 105, 109, 101, 34, 58, 34, 48, 48, 48, 49, 45, 48, 49, 45, 48, 49, 84, 48, 48, 58, 48, 48, 58, 48, 48, 90, 34, 44, 34, 100, 97, 116, 97, 115, 101, 116, 115, 34, 58, 91, 34, 83, 101, 110, 115, 111, 114, 32, 68, 97, 116, 97, 32, 76, 111, 103, 115, 34, 44, 34, 77, 97, 99, 104, 105, 110, 101, 32, 72, 101, 97, 108, 116, 104, 32, 82, 101, 99, 111, 114, 100, 115, 34, 44, 34, 77, 97, 105, 110, 116, 101, 110, 97, 110, 99, 101, 32, 82, 101, 112, 111, 114, 116, 115, 34, 93, 44, 34, 97, 108, 103, 111, 114, 105, 116, 104, 109, 115, 34, 58, 91, 34, 83, 117, 112, 112, 111, 114, 116, 32, 86, 101, 99, 116, 111, 114, 32, 77, 97, 99, 104, 105, 110, 101, 115, 34, 44, 34, 75, 45, 78, 101, 97, 114, 101, 115, 116, 32, 78, 101, 105, 103, 104, 98, 111, 114, 115, 34, 44, 34, 72, 105, 101, 114, 97, 114, 99, 104, 105, 99, 97, 108, 32, 67, 108, 117, 115, 116, 101, 114, 105, 110, 103, 34, 93, 44, 34, 100, 97, 116, 97, 115, 101, 116, 95, 112, 114, 111, 118, 105, 100, 101, 114, 115, 34, 58, 91, 34, 83, 101, 110, 115, 111, 114, 84, 101, 99, 104, 32, 83, 111, 108, 117, 116, 105, 111, 110, 115, 34, 44, 34, 77, 97, 99, 104, 105, 110, 101, 114, 121, 32, 68, 97, 116, 97, 32, 83, 121, 115, 116, 101, 109, 115, 34, 93, 44, 34, 97, 108, 103, 111, 114, 105, 116, 104, 109, 95, 112, 114, 111, 118, 105, 100, 101, 114, 115, 34, 58, 91, 34, 65, 108, 103, 111, 65, 73, 32, 82, 101, 115, 101, 97, 114, 99, 104, 32, 76, 97, 98, 115, 34, 44, 34, 84, 101, 99, 104, 66, 111, 116, 115, 32, 73, 110, 110, 111, 118, 97, 116, 105, 111, 110, 115, 34, 93, 44, 34, 114, 101, 115, 117, 108, 116, 95, 99, 111, 110, 115, 117, 109, 101, 114, 115, 34, 58, 91, 34, 77, 97, 99, 104, 105, 110, 101, 32, 77, 97, 105, 110, 116, 101, 110, 97, 110, 99, 101, 32, 68, 101, 112, 97, 114, 116, 109, 101, 110, 116, 34, 44, 34, 80, 114, 101, 100, 105, 99, 116, 105, 118, 101, 32, 65, 110, 97, 108, 121, 116, 105, 99, 115, 32, 84, 101, 97, 109, 34, 44, 34, 73, 110, 100, 117, 115, 116, 114, 105, 97, 108, 32, 65, 117, 116, 111, 109, 97, 116, 105, 111, 110, 32, 68, 105, 118, 105, 115, 105, 111, 110, 34, 93, 44, 34, 116, 116, 108, 34, 58, 52, 56, 44, 34, 109, 101, 116, 97, 100, 97, 116, 97, 34, 58, 123, 34, 97, 110, 97, 108, 121, 115, 105, 115, 95, 112, 117, 114, 112, 111, 115, 101, 34, 58, 34, 79, 112, 116, 105, 109, 105, 122, 101, 32, 109, 97, 99, 104, 105, 110, 101, 32, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 32, 97, 110, 100, 32, 112, 114, 101, 118, 101, 110, 116, 32, 100, 111, 119, 110, 116, 105, 109, 101, 34, 44, 34, 100, 97, 116, 97, 95, 102, 114, 101, 113, 117, 101, 110, 99, 121, 34, 58, 34, 72, 111, 117, 114, 108, 121, 34, 44, 34, 105, 110, 100, 117, 115, 116, 114, 121, 34, 58, 34, 77, 97, 110, 117, 102, 97, 99, 116, 117, 114, 105, 110, 103, 34, 44, 34, 109, 97, 99, 104, 105, 110, 101, 95, 116, 121, 112, 101, 34, 58, 34, 65, 117, 116, 111, 109, 97, 116, 101, 100, 32, 65, 115, 115, 101, 109, 98, 108, 121, 32, 76, 105, 110, 101, 34, 125, 125]
}'

```

You should be able to create multiple instances by reruning the command.    

### Verifying VM launch

NB: To verify that the manager successfully launched the VM, you need to open two terminals on the same machine. In one terminal, you need to launch `go run main.go` (with the environment variables of choice) and in the other, you can run the verification commands.

To verify that the manager launched the VM successfully, run the following command:

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

### Troubleshooting

If the `ps aux | grep qemu-system-x86_64` give you something like this

```
darko      13913  0.0  0.0      0     0 pts/2    Z+   20:17   0:00 [qemu-system-x86] <defunct>
```

means that the a QEMU virtual machine that is currently defunct, meaning that it is no longer running. More precisely, the defunct process in the output is also known as a ["zombie" process](https://en.wikipedia.org/wiki/Zombie_process).

You can troubleshoot the VM launch procedure by running directly `qemu-system-x86_64` command. When you run `manager` with `MANAGER_LOG_LEVEL=info` env var set, it prints out the entire command used to launch a VM. The relevant part of the log might look like this

```
{"level":"info","message":"/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty","ts":"2023-08-14T18:29:19.2653908Z"}
```

You can run the command - the value of the `"message"` key - directly in the terminal:

```sh
/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty
```

and look for the possible problems. This problems can usually be solved by using the adequate env var assignments. Look in the `manager/qemu/config.go` file to see the recognized env vars. Don't forget to prepend `MANAGER_QEMU_` to the name of the env vars.

#### Kill `qemu-system-x86_64` processes

To kill any leftover `qemu-system-x86_64` processes, use

```sh
pkill -f qemu-system-x86_64
```

The pkill command is used to kill processes by name or by pattern. The -f flag to specify that we want to kill processes that match the pattern `qemu-system-x86_64`. It sends the SIGKILL signal to all processes that are running `qemu-system-x86_64`.

If this does not work, i.e. if `ps aux | grep qemu-system-x86_64` still outputs `qemu-system-x86_64` related process(es), you can kill the unwanted process with `kill -9 <PID>`, which also sends a SIGKILL signal to the process.

#### Ports in use

The [NetDevConfig struct](manager/qemu/config.go) defines the network configuration for a virtual machine. The HostFwd* and GuestFwd* fields specify the host and guest ports that are forwarded between the virtual machine and the host machine. By default, these ports are allocated 2222, 9301, and 7020 for HostFwd1, HostFwd2, and HostFwd3, respectively, and 22, 9031, and 7002 for GuestFwd1, GuestFwd2, and GuestFwd3, respectively. However, if these ports are in use, you can configure your own ports by setting the corresponding environment variables. For example, to set the HostFwd1 port to 8080, you would set the MANAGER_QEMU_HOST_FWD_1 environment variable to 8080. For example,

```sh
export MANAGER_LOG_LEVEL=info
export MANAGER_AGENT_GRPC_URL=192.168.122.251:7002
export MANAGER_QEMU_USE_SUDO=false
export MANAGER_QEMU_ENABLE_SEV=false
export MANAGER_QEMU_HOST_FWD_1=8080
export MANAGER_QEMU_GUEST_FWD_1=22
export MANAGER_QEMU_HOST_FWD_2=9301
export MANAGER_QEMU_GUEST_FWD_2=9031
export MANAGER_QEMU_HOST_FWD_3=7020
export MANAGER_QEMU_GUEST_FWD_3=7002

go run main.go
```

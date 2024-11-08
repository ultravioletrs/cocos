# Manager

Manager service provides a barebones gRPC API and Service interface implementation for the development of the manager service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable                                  | Description                                                                                                      | Default                      |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| COCOS_JAEGER_URL                          | The URL for the Jaeger tracing endpoint.                                                                         | http://localhost:4318        |
| COCOS_JAEGER_TRACE_RATIO                  | The ratio of traces to sample.                                                                                   | 1.0                          |
| MANAGER_INSTANCE_ID                       | The instance ID for the manager service.                                                                         |                              |
| MANAGER_BACKEND_MEASUREMENT_BINARY        | The file path for the backend measurement binary.                                                                | ../../build                  |
| MANAGER_GRPC_CLIENT_CERT                  | The file path for the client certificate.                                                                        |                              |
| MANAGER_GRPC_CLIENT_KEY                   | The file path for the client private key.                                                                        |                              |
| MANAGER_GRPC_SERVER_CA_CERTS              | The file path for the server CA certificate(s).                                                                  |                              |
| MANAGER_GRPC_URL                          | The URL for the gRPC endpoint.                                                                                   | localhost:7001               |
| MANAGER_GRPC_TIMEOUT                      | The timeout for gRPC requests.                                                                                   | 60s                          |
| MANAGER_EOS_VERSION                       | The EOS version used for booting SVMs.                                                                           |                              |
| MANAGER_INSTANCE_ID                       | Manager service instance ID                                                                                      |                              |
| MANAGER_QEMU_MEMORY_SIZE                  | The total memory size for the virtual machine. Can be specified in a human-readable format like "2048M" or "4G". | 2048M                        |
| MANAGER_QEMU_MEMORY_SLOTS                 | The number of memory slots for the virtual machine.                                                              | 5                            |
| MANAGER_QEMU_MAX_MEMORY                   | The maximum memory size for the virtual machine. Can be specified in a human-readable format like "30G".         | 30G                          |
| MANAGER_QEMU_OVMF_CODE_IF                 | The interface type for the OVMF code.                                                                            | pflash                       |
| MANAGER_QEMU_OVMF_CODE_FORMAT             | The format of the OVMF code file.                                                                                | raw                          |
| MANAGER_QEMU_OVMF_CODE_UNIT               | The unit number for the OVMF code.                                                                               | 0                            |
| MANAGER_QEMU_OVMF_CODE_FILE               | The file path for the OVMF code.                                                                                 | /usr/share/OVMF/OVMF_CODE.fd |
| MANAGER_QEMU_OVMF_VERSION                 | The version number of EDKII from which OVMF was built                                                            | edk2-stable202408            |
| MANAGER_QEMU_OVMF_CODE_READONLY           | Whether the OVMF code should be read-only.                                                                       | on                           |
| MANAGER_QEMU_OVMF_VARS_IF                 | The interface type for the OVMF variables.                                                                       | pflash                       |
| MANAGER_QEMU_OVMF_VARS_FORMAT             | The format of the OVMF variables file.                                                                           | raw                          |
| MANAGER_QEMU_OVMF_VARS_UNIT               | The unit number for the OVMF variables.                                                                          | 1                            |
| MANAGER_QEMU_OVMF_VARS_FILE               | The file path for the OVMF variables.                                                                            | /usr/share/OVMF/OVMF_VARS.fd |
| MANAGER_QEMU_NETDEV_ID                    | The ID for the network device.                                                                                   | vmnic                        |
| MANAGER_QEMU_HOST_FWD_AGENT               | The port number for the host forward agent.                                                                      | 7020                         |
| MANAGER_QEMU_GUEST_FWD_AGENT              | The port number for the guest forward agent.                                                                     | 7002                         |
| MANAGER_QEMU_VIRTIO_NET_PCI_DISABLE_LEGACY | Whether to disable the legacy PCI device.                                                                       | on                           |
| MANAGER_QEMU_VIRTIO_NET_PCI_IOMMU_PLATFORM | Whether to enable the IOMMU platform for the virtio-net PCI device.                                             | true                         |
| MANAGER_QEMU_VIRTIO_NET_PCI_ADDR           | The PCI address for the virtio-net PCI device.                                                                  | 0x2                          |
| MANAGER_QEMU_VIRTIO_NET_PCI_ROMFILE        | The file path for the ROM image for the virtio-net PCI device.                                                  |                              |
| MANAGER_QEMU_DISK_IMG_KERNEL_FILE          | The file path for the kernel image.                                                                             | img/bzImage                  |
| MANAGER_QEMU_DISK_IMG_ROOTFS_FILE          | The file path for the root filesystem image.                                                                    | img/rootfs.cpio.gz           |
| MANAGER_QEMU_SEV_ID                        | The ID for the Secure Encrypted Virtualization (SEV) device.                                                    | sev0                         |
| MANAGER_QEMU_SEV_CBITPOS                   | The position of the C-bit in the physical address.                                                              | 51                           |
| MANAGER_QEMU_SEV_REDUCED_PHYS_BITS         | The number of reduced physical address bits for SEV.                                                            | 1                            |
| MANAGER_QEMU_HOST_DATA                     | Additional data for the SEV host.                                                                               |                              |
| MANAGER_QEMU_VSOCK_ID                      | The ID for the virtual socket device.                                                                           | vhost-vsock-pci0             |
| MANAGER_QEMU_VSOCK_GUEST_CID               | The guest-side CID (Context ID) for the virtual socket device.                                                  | 3                            |
| MANAGER_QEMU_VSOCK_VNC                     | Whether to enable the virtual socket device for VNC.                                                            | 0                            |
| MANAGER_QEMU_BIN_PATH                      | The file path for the QEMU binary.                                                                              | qemu-system-x86_64           |
| MANAGER_QEMU_USE_SUDO                      | Whether to use sudo to run QEMU.                                                                                | false                        |
| MANAGER_QEMU_ENABLE_SEV                    | Whether to enable Secure Encrypted Virtualization (SEV).                                                        | false                        |
| MANAGER_QEMU_ENABLE_SEV_SNP                | Whether to enable Secure Nested Paging (SEV-SNP).                                                               | true                         |
| MANAGER_QEMU_ENABLE_KVM                    | Whether to enable the Kernel-based Virtual Machine (KVM) acceleration.                                          | true                         |
| MANAGER_QEMU_MACHINE                       | The machine type for QEMU.                                                                                      | q35                          |
| MANAGER_QEMU_CPU                           | The CPU model for QEMU.                                                                                         | EPYC                         |
| MANAGER_QEMU_SMP_COUNT                     | The number of virtual CPUs.                                                                                     | 4                            |
| MANAGER_QEMU_SMP_MAXCPUS                   | The maximum number of virtual CPUs.                                                                             | 64                           |
| MANAGER_QEMU_MEM_ID                        | The ID for the memory device.                                                                                   | ram1                         |
| MANAGER_QEMU_KERNEL_HASH                   | Whether to enable kernel hash verification.                                                                     | false                        |
| MANAGER_QEMU_NO_GRAPHIC                    | Whether to disable the graphical display.                                                                       | true                         |
| MANAGER_QEMU_MONITOR                       | The type of monitor to use.                                                                                     | pty                          |
| MANAGER_QEMU_HOST_FWD_RANGE                | The range of host ports to forward.                                                                             | 6100-6200                    |

## Setup

```sh
git clone https://github.com/ultravioletrs/cocos
cd cocos
```

NB: all relative paths in this document are relative to `cocos` repository directory.

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

#### Add Vsock
The necessary kernel modules must be loaded on the hypervisor. To check if `vhost_vsock` is loaded run:
```shell
lsmod | grep vhost_vsock
```

If `vhost_vsock` is not loaded run the following commands:

```shell
sudo modprobe vhost_vsock
ls -l /dev/vhost-vsock
# crw-rw-rw- 1 root kvm 10, 241 Jan 16 12:05 /dev/vhost-vsock
ls -l /dev/vsock
# crw-rw-rw- 1 root root 10, 121 Jan 16 12:05 /dev/vsock
```

### Prepare Cocos HAL

Cocos HAL for Linux is framework for building custom in-enclave Linux distribution. Use the instructions in [Readme](https://github.com/ultravioletrs/cocos/blob/main/hal/linux/README.md).
Once the image is built copy the kernel and rootfs image to `cmd/manager/img` from `buildroot/output/images/bzImage` and `buildroot/output/images/rootfs.cpio.gz` respectively.

Another option is to use release versions of EOS that can be downloaded from the [Cocos GitHub repository](https://github.com/ultravioletrs/cocos/releases).

#### Test VM creation

```sh
cd cmd/manager

sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
OVMF_CODE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS.fd

KERNEL="img/bzImage"
INITRD="img/rootfs.cpio.gz"

qemu-system-x86_64 \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35 \
    -smp 4 \
    -m 2048M,slots=5,maxmem=10240M \
    -no-reboot \
    -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
    -netdev user,id=vmnic,hostfwd=tcp::7020-:7002 \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
    -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3 -vnc :0 \
    -kernel $KERNEL \
    -append "earlyprintk=serial console=ttyS0" \
    -initrd $INITRD \
    -nographic \
    -monitor pty \
    -monitor unix:monitor,server,nowait
```
Once the VM is booted press enter and on the login use username `root`.

#### Build and run Agent

Agent is started automatically in the VM.
```sh
# List running processes and use 'grep' to filter for processes containing 'agent' in their names.
ps aux | grep cocos-agent
# This command helps verify that the 'agent' process is running.
# The output shows the process ID (PID), resource usage, and other information about the 'cocos-agent' process.
# For example: 118 root     cocos-agent
```

We can also check if `Agent` is reachable from the host machine:

```sh
# Use netcat (nc) to test the connection to localhost on port 7020.
nc -zv localhost 7020
# Output:
# nc: connect to localhost (::1) port 7020 (tcp) failed: Connection refused
# Connection to localhost (127.0.0.1) 7020 port [tcp/*] succeeded!
```

#### Conclusion

Now you are able to use `Manager` with `Agent`. Namely, `Manager` will create a VM with a separate OVMF variables file on manager `/run` request.

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


## Deployment

To start the service, execute the following shell script (note a server needs to be running see  [here](../test/computations/README.md)):

```bash
# Download the latest version of the service
git clone git@github.com:ultravioletrs/cocos.git

cd cocos

# Compile the manager
make manager

# Set the environment variables and run the service
MANAGER_GRPC_URL=localhost:7001
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_USE_SUDO=false \
MANAGER_QEMU_ENABLE_SEV=false \
./build/cocos-manager
```

To enable [AMD SEV](https://www.amd.com/en/developer/sev.html) support, start manager like this 

```sh
MANAGER_GRPC_URL=localhost:7001
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_USE_SUDO=true \
MANAGER_QEMU_ENABLE_SEV=true \
MANAGER_QEMU_SEV_CBITPOS=51 \
./build/cocos-manager
```

To build the OVMF with the kernel hash capability, we must build the AmdSev package of OVMF. The result of the build should be a single `OVMF.fd` file (unlike the regular two OVFM files). The OVMF package is located at `OvmfPkg/AmdSev/AmdSevX64.dsc`.

To enable [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html) support, start manager like this 

```sh
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_ENABLE_SEV=false \
MANAGER_QEMU_ENABLE_SEV_SNP=true \
MANAGER_QEMU_SEV_CBITPOS=51 \
MANAGER_QEMU_BIN_PATH=<path to QEMU binary> \
MANAGER_QEMU_QEMU_OVMF_CODE_FILE=<path to OVMF.fd Amd Sev built package> \
./build/cocos-manager
```

To include the kernel hash into the measurement of the attestation report (SEV or SEV-SNP), start manager like this

```sh
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_ENABLE_SEV=false \
MANAGER_QEMU_ENABLE_SEV_SNP=true \
MANAGER_QEMU_SEV_CBITPOS=51 \
MANAGER_QEMU_KERNEL_HASH=true \
MANAGER_QEMU_BIN_PATH=<path to QEMU binary> \
MANAGER_QEMU_QEMU_OVMF_CODE_FILE=<path to OVMF.fd Amd Sev built package> \
./build/cocos-manager
```

### Verifying VM launch

NB: To verify that the manager successfully launched the VM, you need to open three terminals on the same machine. In one terminal, you need to launch the computations server by executing (with the environment variables of choice):

```bash
go run ./test/computations/main.go <dataset path> <algo path>
```

and in the second the manager by executing (with the environment variables of choice):

```bash
go run ./cmd/manager/main.go
```

Ensure that the Manager can connect to the Manager test server by setting the MANAGER_GRPC_PORT with the port value of the Manager test server. In the last terminal, you can run the verification commands.

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

## Usage

For more information about service capabilities and its usage, please check out the [README documentation](../README.md).

# Manager

Manager service provides a barebones gRPC API and Service interface implementation for the development of the manager service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable                                   | Description                                                                                                      | Default                        |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| COCOS_JAEGER_URL                           | The URL for the Jaeger tracing endpoint.                                                                         | http://localhost:4318          |
| COCOS_JAEGER_TRACE_RATIO                   | The ratio of traces to sample.                                                                                   | 1.0                            |
| MANAGER_INSTANCE_ID                        | The instance ID for the manager service.                                                                         |                                |
| MANAGER_IGVMMEASURE_BINARY                 | The file path for the igvmmeasure binarie.                                                                       | ../../build/igvmmeasure        |
| MANAGER_PCR_VALUES                         | The file path for the file with the expected PCR values.                                                         |                                |
| MANAGER_HTTP_HOST                          | Manager service HTTP host                                                                                        | ""                             |
| MANAGER_HTTP_PORT                          | Manager service HTTP port                                                                                        | 7003                           |
| MANAGER_HTTP_SERVER_CERT                   | Manager to HTTP server certificate in pem format                                                                 | ""                             |
| MANAGER_HTTP_SERVER_KEY                    | Path to HTTP server key in pem format                                                                            | ""                             |
| MANAGER_HTTP_SERVER_CA_CERTS               | Path to HTTP server CA certificate                                                                               | ""                             |
| MANAGER_HTTP_CLIENT_CA_CERTS               | Path to HTTP client CA certificate                                                                               | ""                             |
| MANAGER_GRPC_HOST                          | Manager service gRPC host                                                                                        | ""                             |
| MANAGER_GRPC_PORT                          | Manager service gRPC port                                                                                        | 7001                           |
| MANAGER_GRPC_SERVER_CERT                   | Path to gRPC server certificate in pem format                                                                    | ""                             |
| MANAGER_GRPC_SERVER_KEY                    | Path to gRPC server key in pem format                                                                            | ""                             |
| MANAGER_GRPC_SERVER_CA_CERTS               | Path to gRPC server CA certificate                                                                               | ""                             |
| MANAGER_GRPC_CLIENT_CA_CERTS               | Path to gRPC client CA certificate                                                                               | ""                             |
| MANAGER_EOS_VERSION                        | The EOS version used for booting CVMs.                                                                           |                                |
| MANAGER_INSTANCE_ID                        | Manager service instance ID                                                                                      |                                |
| MANAGER_QEMU_MEMORY_SIZE                   | The total memory size for the virtual machine. Can be specified in a human-readable format like "2048M" or "4G". | 2048M                          |
| MANAGER_QEMU_MEMORY_SLOTS                  | The number of memory slots for the virtual machine.                                                              | 5                              |
| MANAGER_QEMU_MAX_MEMORY                    | The maximum memory size for the virtual machine. Can be specified in a human-readable format like "30G".         | 30G                            |
| MANAGER_QEMU_OVMF_CODE_IF                  | The interface type for the OVMF code.                                                                            | pflash                         |
| MANAGER_QEMU_OVMF_CODE_FORMAT              | The format of the OVMF code file.                                                                                | raw                            |
| MANAGER_QEMU_OVMF_CODE_UNIT                | The unit number for the OVMF code.                                                                               | 0                              |
| MANAGER_QEMU_OVMF_CODE_FILE                | The file path for the OVMF code.                                                                                 | /usr/share/OVMF/OVMF_CODE.fd   |
| MANAGER_QEMU_OVMF_VERSION                  | The version number of EDKII from which OVMF was built                                                            | edk2-stable202408              |
| MANAGER_QEMU_OVMF_CODE_READONLY            | Whether the OVMF code should be read-only.                                                                       | on                             |
| MANAGER_QEMU_OVMF_VARS_IF                  | The interface type for the OVMF variables.                                                                       | pflash                         |
| MANAGER_QEMU_OVMF_VARS_FORMAT              | The format of the OVMF variables file.                                                                           | raw                            |
| MANAGER_QEMU_OVMF_VARS_UNIT                | The unit number for the OVMF variables.                                                                          | 1                              |
| MANAGER_QEMU_OVMF_VARS_FILE                | The file path for the OVMF variables.                                                                            | /usr/share/OVMF/OVMF_VARS.fd   |
| MANAGER_QEMU_NETDEV_ID                     | The ID for the network device.                                                                                   | vmnic                          |
| MANAGER_QEMU_HOST_FWD_AGENT                | The port number for the host forward agent.                                                                      | 7020                           |
| MANAGER_QEMU_GUEST_FWD_AGENT               | The port number for the guest forward agent.                                                                     | 7002                           |
| MANAGER_QEMU_VIRTIO_NET_PCI_DISABLE_LEGACY | Whether to disable the legacy PCI device.                                                                        | on                             |
| MANAGER_QEMU_VIRTIO_NET_PCI_IOMMU_PLATFORM | Whether to enable the IOMMU platform for the virtio-net PCI device.                                              | true                           |
| MANAGER_QEMU_VIRTIO_NET_PCI_ADDR           | The PCI address for the virtio-net PCI device.                                                                   | 0x2                            |
| MANAGER_QEMU_VIRTIO_NET_PCI_ROMFILE        | The file path for the ROM image for the virtio-net PCI device.                                                   |                                |
| MANAGER_QEMU_DISK_IMG_KERNEL_FILE          | The file path for the kernel image.                                                                              | img/bzImage                    |
| MANAGER_QEMU_DISK_IMG_ROOTFS_FILE          | The file path for the root filesystem image.                                                                     | img/rootfs.cpio.gz             |
| MANAGER_QEMU_SEV_SNP_ID                    | The ID for the Secure Encrypted Virtualization (SEV-SNP) device.                                                 | sev0                           |
| MANAGER_QEMU_SEV_SNP_CBITPOS               | The position of the C-bit in the physical address.                                                               | 51                             |
| MANAGER_QEMU_SEV_SNP_REDUCED_PHYS_BITS     | The number of reduced physical address bits for SEV-SNP.                                                         | 1                              |
| MANAGER_QEMU_ENABLE_HOST_DATA              | Enable additional data for the SEV-SNP host.                                                                     | false                          |
| MANAGER_QEMU_HOST_DATA                     | Additional data for the SEV-SNP host.                                                                            |                                |
| MANAGER_QEMU_TDX_ID                        | The ID for the Trust Domain Extensions (TDX) device.                                                             | tdx0                           |
| MANAGER_QEMU_QUOTE_GENERATION_PORT         | The port number for virtual socket used to communicate with the Quote Generation Service (QGS).                  | 4050                           |
| MANAGER_QEMU_OVMF_FILE                     | The file path for the OVMF file (combined OVMF_CODE and OVMF_VARS file).                                         | /usr/share/ovmf/OVMF.fd        |
| MANAGER_QEMU_IGVM_ID                       | The ID of the IGVM file.                                                                                         | igvm0                          |
| MANAGER_QEMU_IGVM_FILE                     | The file path to the IGVM file.                                                                                  | /root/coconut-qemu.igvm        |
| MANAGER_QEMU_BIN_PATH                      | The file path for the QEMU binary.                                                                               | qemu-system-x86_64             |
| MANAGER_QEMU_USE_SUDO                      | Whether to use sudo to run QEMU.                                                                                 | false                          |
| MANAGER_QEMU_ENABLE_SEV_SNP                | Whether to enable Secure Nested Paging (SEV-SNP).                                                                | true                           |
| MANAGER_QEMU_ENABLE_TDX                    | Whether to enable Trust Domain Extensions (TDX).                                                                 | false                          |
| MANAGER_QEMU_ENABLE_KVM                    | Whether to enable the Kernel-based Virtual Machine (KVM) acceleration.                                           | true                           |
| MANAGER_QEMU_MACHINE                       | The machine type for QEMU.                                                                                       | q35                            |
| MANAGER_QEMU_CPU                           | The CPU model for QEMU.                                                                                          | EPYC                           |
| MANAGER_QEMU_SMP_COUNT                     | The number of virtual CPUs.                                                                                      | 4                              |
| MANAGER_QEMU_SMP_MAXCPUS                   | The maximum number of virtual CPUs.                                                                              | 64                             |
| MANAGER_QEMU_MEM_ID                        | The ID for the memory device.                                                                                    | ram1                           |
| MANAGER_QEMU_NO_GRAPHIC                    | Whether to disable the graphical display.                                                                        | true                           |
| MANAGER_QEMU_MONITOR                       | The type of monitor to use.                                                                                      | pty                            |
| MANAGER_QEMU_HOST_FWD_RANGE                | The range of host ports to forward.                                                                              | 6100-6200                      |
| MANAGER_MAX_VMS                            | The maximum number of vms running concurrently on manager.                                                       | 10                             |
| MANAGER_MRSEAM                             | Expected **MRSEAM** measurement (hex).                                                                           |                                |
| MANAGER_TD_ATTRIBUTES                      | Expected **TD Attributes** (hex, 8 bytes).                                                                       |                                |
| MANAGER_XFAM                               | Expected **XFAM** (Extended Features Available Mask) (hex, 8 bytes).                                             |                                |
| MANAGER_MRTD                               | Expected **MRTD** measurement (hex).                                                                             |                                |
| MANAGER_RTMR0                              | Expected **RTMR[0]** (runtime measurement register 0) (hex).                                                     |                                |
| MANAGER_RTMR1                              | Expected **RTMR[1]** (runtime measurement register 1) (hex).                                                     |                                |
| MANAGER_RTMR2                              | Expected **RTMR[2]** (runtime measurement register 2) (hex).                                                     |                                |
| MANAGER_RTMR3                              | Expected **RTMR[3]** (runtime measurement register 3) (hex).                                                     |                                |
| MANAGER_SEV_SNP_POLICY                     | Expected **SEV SNP CVM launch policy**.                                                                          | 196608                         |

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

#### Virtual filesystem

9P (or Plan 9 Filesystem) in QEMU is a lightweight, network-based file-sharing protocol. In Cocos, the 9P is used to transfer environment variables and TLS certificates for cloud communication from the Manager to the Agent.

You should define the environment variables in a file called environment. For the number and meaning of the environment variables, please refer to the Agent [Readme](https://github.com/ultravioletrs/cocos/blob/main/agent/README.md).

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

# Create a local copy of OVMF_VARS.
cp /usr/share/OVMF/OVMF_VARS.fd .

# Create a directory for the environment file and the certificates for cloud certificates.
mkdir env
mkdir certs

# Enter the env directory and create the environemnt file.
cd env
touch environment

# Define Computations endpoint URL for agent.
# Make sure the Computation endpoint is running (like Cocos Prism).
echo AGENT_CVM_GRPC_URL=localhost:7001 >> ./environment
# Define log level for the agent.
echo AGENT_LOG_LEVEL=debug >> ./environment

# Return to cmd/manager
cd ..

OVMF_VARS=./OVMF_VARS.fd
KERNEL="img/bzImage"
INITRD="img/rootfs.cpio.gz"
ENV_PATH=./env
CERTH_PATH=./certs

qemu-system-x86_64 \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35 \
    -smp 4 \
    -m 2048M,slots=5,maxmem=10240M \
    -no-reboot \
    -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=$OVMF_VARS \
    -netdev user,id=vmnic,hostfwd=tcp::7020-:7002 \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
    -kernel $KERNEL \
    -append "earlyprintk=serial console=ttyS0" \
    -initrd $INITRD \
    -nographic \
    -monitor pty \
    -monitor unix:monitor,server,nowait \
    -fsdev local,id=env_fs,path=$ENV_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=env_fs,mount_tag=env_share \
    -fsdev local,id=cert_fs,path=$CERTH_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=cert_fs,mount_tag=certs_share
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

### Trusted Platform Module (TPM)

The Trusted Platform Module (TPM) plays a fundamental role in this process by providing a tamper-resistant foundation for cryptographic operations, securing sensitive artifacts, measuring system state, and enabling attestation mechanisms.

### IGVM

An IGVM file contains all the necessary information to launch a virtual machine on different virtualization platforms. It includes setup commands for the guest system and verification data to ensure the VM is loaded securely and correctly.

Cocos uses the [COCONUT-SVSM](https://github.com/coconut-svsm/svsm/blob/main/Documentation/docs/installation/INSTALL.md) for the vTPM. The IGVM file contains the OVMF file and the vTPM.

## Deployment

To start the service, execute the following shell script (note a server needs to be running see [here](../test/cvms/README.md)):

The manager can be started as a *systemd* service or a standalone executable. To start the manager as a systemd service, look at the systemd service script [here](https://github.com/ultravioletrs/cocos/blob/main/init/systemd/cocos-manager.service). The environment variables are defined in the `cocos-manager.env` file. Below are examples of how to start the manager.

```bash
# Download the latest version of the service
git clone git@github.com:ultravioletrs/cocos.git

cd cocos

# Compile the manager
make manager

# Set the environment variables and run the service
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_USE_SUDO=false \
./build/cocos-manager
```

To start SEV-SNP, define the IGVM file that contains the vTPM and the OVMF (combined OVMF_CODE and OVMF_VARS) of the CVM.

To enable [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html) support, start manager like this 

```sh
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_ENABLE_SEV_SNP=true \
MANAGER_QEMU_SEV_SNP_CBITPOS=51 \
MANAGER_QEMU_BIN_PATH=<path to QEMU binary> \
MANAGER_QEMU_IGVM_FILE=<path to IGVM file> \
./build/cocos-manager
```

To enable [TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) support, start manager like this

```sh
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_ENABLE_SEV_SNP=false \
MANAGER_QEMU_ENABLE_TDX=true \
MANAGER_QEMU_CPU=host \
MANAGER_QEMU_BIN_PATH=<path to QEMU binary> \
MANAGER_QEMU_OVMF_FILE=<path to OVMF file> \
./build/cocos-manager
```

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

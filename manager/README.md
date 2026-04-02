# Manager

The Manager service runs on the AMD SEV-SNP or Intel TDX host and orchestrates the full workload lifecycle: provisioning Confidential Virtual Machines (CVMs) via QEMU, injecting environment variables and TLS certificates, and streaming computation events back to callers. It exposes both a gRPC API and an HTTP API.

## Configuration

The service is configured using environment variables. Unset variables fall back to their defaults.

### Tracing

| Variable | Description | Default |
| --- | --- | --- |
| `COCOS_JAEGER_URL` | Jaeger OTLP endpoint for distributed tracing | `http://localhost:4318` |
| `COCOS_JAEGER_TRACE_RATIO` | Fraction of traces to sample (0.0–1.0) | `1.0` |

### Core

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_INSTANCE_ID` | Unique identifier for this Manager instance | `""` |
| `MANAGER_EOS_VERSION` | EOS version used when booting CVMs | `""` |
| `MANAGER_MAX_VMS` | Maximum number of CVMs running concurrently | `10` |
| `MANAGER_GRPC_HOST` | gRPC server listen address | `""` |
| `MANAGER_GRPC_PORT` | gRPC server port | `7001` |
| `MANAGER_HTTP_HOST` | HTTP server listen address | `""` |
| `MANAGER_HTTP_PORT` | HTTP server port | `7003` |
| `MANAGER_ATTESTATION_POLICY_BINARY_PATH` | Directory containing attestation policy binaries (`igvmmeasure`) | `../../build` |
| `MANAGER_PCR_VALUES` | Path to file with expected PCR values | `""` |

### TLS — gRPC

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_GRPC_SERVER_CERT` | Path to gRPC server certificate (PEM) | `""` |
| `MANAGER_GRPC_SERVER_KEY` | Path to gRPC server key (PEM) | `""` |
| `MANAGER_GRPC_SERVER_CA_CERTS` | Path to gRPC server CA certificate | `""` |
| `MANAGER_GRPC_CLIENT_CA_CERTS` | Path to gRPC client CA certificate | `""` |

### TLS — HTTP

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_HTTP_SERVER_CERT` | Path to HTTP server certificate (PEM) | `""` |
| `MANAGER_HTTP_SERVER_KEY` | Path to HTTP server key (PEM) | `""` |
| `MANAGER_HTTP_SERVER_CA_CERTS` | Path to HTTP server CA certificate | `""` |
| `MANAGER_HTTP_CLIENT_CA_CERTS` | Path to HTTP client CA certificate | `""` |

### QEMU — Memory

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_QEMU_MEMORY_SIZE` | Initial memory size for the VM (e.g., `2048M`, `4G`) | `2048M` |
| `MANAGER_QEMU_MEMORY_SLOTS` | Number of memory slots | `5` |
| `MANAGER_QEMU_MAX_MEMORY` | Maximum memory size for the VM | `30G` |
| `MANAGER_QEMU_MEM_ID` | Memory device ID | `ram1` |

### QEMU — OVMF Firmware

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_QEMU_OVMF_VERSION` | EDKII version from which OVMF was built | `edk2-stable202408` |
| `MANAGER_QEMU_OVMF_CODE_IF` | Interface type for the OVMF code drive | `pflash` |
| `MANAGER_QEMU_OVMF_CODE_FORMAT` | Format of the OVMF code file | `raw` |
| `MANAGER_QEMU_OVMF_CODE_UNIT` | Drive unit number for OVMF code | `0` |
| `MANAGER_QEMU_OVMF_CODE_FILE` | Path to OVMF code firmware | `/usr/share/OVMF/OVMF_CODE.fd` |
| `MANAGER_QEMU_OVMF_CODE_READONLY` | Mount OVMF code as read-only | `on` |
| `MANAGER_QEMU_OVMF_VARS_IF` | Interface type for the OVMF variables drive | `pflash` |
| `MANAGER_QEMU_OVMF_VARS_FORMAT` | Format of the OVMF variables file | `raw` |
| `MANAGER_QEMU_OVMF_VARS_UNIT` | Drive unit number for OVMF variables | `1` |
| `MANAGER_QEMU_OVMF_VARS_FILE` | Path to OVMF variables file (writable copy per VM) | `/usr/share/OVMF/OVMF_VARS.fd` |
| `MANAGER_QEMU_OVMF_FILE` | Path to combined OVMF file (used for TDX) | `/usr/share/ovmf/OVMF.fd` |

### QEMU — Networking

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_QEMU_NETDEV_ID` | Network device ID | `vmnic` |
| `MANAGER_QEMU_HOST_FWD_AGENT` | Host port forwarded to the Agent gRPC port inside the VM | `7020` |
| `MANAGER_QEMU_GUEST_FWD_AGENT` | Guest port used by the Agent inside the VM | `7002` |
| `MANAGER_QEMU_HOST_FWD_RANGE` | Range of host ports available for VM forwarding | `6100-6200` |
| `MANAGER_QEMU_VIRTIO_NET_PCI_DISABLE_LEGACY` | Disable legacy PCI for the virtio-net device | `on` |
| `MANAGER_QEMU_VIRTIO_NET_PCI_IOMMU_PLATFORM` | Enable IOMMU platform for the virtio-net device | `true` |
| `MANAGER_QEMU_VIRTIO_NET_PCI_ADDR` | PCI address for the virtio-net device | `0x2` |
| `MANAGER_QEMU_VIRTIO_NET_PCI_ROMFILE` | ROM image file for the virtio-net device | `""` |

### QEMU — Disk Images

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_QEMU_DISK_IMG_KERNEL_FILE` | Path to the kernel image | `img/bzImage` |
| `MANAGER_QEMU_DISK_IMG_ROOTFS_FILE` | Path to the root filesystem image | `img/rootfs.cpio.gz` |

### QEMU — AMD SEV-SNP

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_QEMU_ENABLE_SEV_SNP` | Enable AMD Secure Nested Paging (SEV-SNP) | `true` |
| `MANAGER_QEMU_SEV_SNP_ID` | SEV-SNP device ID | `sev0` |
| `MANAGER_QEMU_SEV_SNP_CBITPOS` | C-bit position in the physical address | `51` |
| `MANAGER_QEMU_SEV_SNP_REDUCED_PHYS_BITS` | Number of reduced physical address bits for SEV-SNP | `1` |
| `MANAGER_QEMU_ENABLE_HOST_DATA` | Include additional host data in the SEV-SNP launch | `false` |
| `MANAGER_QEMU_HOST_DATA` | Additional host data value for SEV-SNP | `""` |
| `MANAGER_QEMU_IGVM_ID` | IGVM device ID | `igvm0` |
| `MANAGER_QEMU_IGVM_FILE` | Path to the IGVM file (contains COCONUT-SVSM and OVMF) | `/root/coconut-qemu.igvm` |

### QEMU — Intel TDX

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_QEMU_ENABLE_TDX` | Enable Intel Trust Domain Extensions (TDX) | `false` |
| `MANAGER_QEMU_TDX_ID` | TDX device ID | `tdx0` |
| `MANAGER_QEMU_QUOTE_GENERATION_PORT` | vSocket port for the Quote Generation Service (QGS) | `4050` |

### QEMU — Machine

| Variable | Description | Default |
| --- | --- | --- |
| `MANAGER_QEMU_BIN_PATH` | Path to the QEMU binary | `qemu-system-x86_64` |
| `MANAGER_QEMU_USE_SUDO` | Run QEMU with `sudo` | `false` |
| `MANAGER_QEMU_ENABLE_KVM` | Enable KVM acceleration | `true` |
| `MANAGER_QEMU_MACHINE` | QEMU machine type | `q35` |
| `MANAGER_QEMU_CPU` | CPU model | `EPYC` |
| `MANAGER_QEMU_SMP_COUNT` | Number of virtual CPUs | `4` |
| `MANAGER_QEMU_SMP_MAXCPUS` | Maximum number of virtual CPUs | `64` |
| `MANAGER_QEMU_NO_GRAPHIC` | Disable graphical display | `true` |
| `MANAGER_QEMU_MONITOR` | QEMU monitor type | `pty` |

## Setup

NB: all relative paths in this document are relative to the `cocos` repository directory.

### QEMU-KVM

[QEMU-KVM](https://www.qemu.org/) is a virtualization platform that allows you to run multiple operating systems on the same physical machine. It is a combination of two technologies: QEMU and KVM.

- QEMU is an emulator that can run a variety of operating systems, including Linux, Windows, and macOS.
- [KVM](https://wiki.qemu.org/Features/KVM) is a Linux kernel module that allows QEMU to run virtual machines.

To install QEMU-KVM on a Debian based machine, run:

```bash
sudo apt update
sudo apt install qemu-kvm
```

Create `img` directory in `cmd/manager`.

#### Virtual filesystem

9P (or Plan 9 Filesystem) in QEMU is a lightweight, network-based file-sharing protocol. In Cocos, the 9P is used to transfer environment variables and TLS certificates for cloud communication from the Manager to the Agent.

You should define the environment variables in a file called `environment`. For the number and meaning of the environment variables, please refer to the Agent [README](https://github.com/ultravioletrs/cocos/blob/main/agent/README.md).

### Prepare Cocos HAL

Cocos HAL for Linux is a framework for building custom in-enclave Linux distribution. Use the instructions in [README](https://github.com/ultravioletrs/cocos/blob/main/hal/linux/README.md).
Once the image is built copy the kernel and rootfs image to `cmd/manager/img` from `buildroot/output/images/bzImage` and `buildroot/output/images/rootfs.cpio.gz` respectively.

Another option is to use release versions of EOS that can be downloaded from the [Cocos GitHub repository](https://github.com/ultravioletrs/cocos/releases).

#### Test VM creation

```bash
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

# Enter the env directory and create the environment file.
cd env
touch environment

# Define Computations endpoint URL for agent.
# Make sure the Computation endpoint is running (like Cocos Prism).
echo AGENT_CVM_GRPC_URL=localhost:7001 >> ./environment
# Define log level for the agent.
echo AGENT_LOG_LEVEL=debug >> ./environment

# Optional: Add AWS/S3 credentials for remote resource access
# NOTE: AWS credentials can also be passed via the CreateVM API using CLI flags
# (--aws-access-key-id, --aws-secret-access-key, --aws-endpoint-url, --aws-region)
# If using the API approach, you don't need to add them to this file.
# Replace HOST_IP with your host machine IP address (not localhost)
echo AWS_ACCESS_KEY_ID=minioadmin >> ./environment
echo AWS_SECRET_ACCESS_KEY=minioadmin >> ./environment
echo AWS_ENDPOINT_URL=http://HOST_IP:9000 >> ./environment
echo AWS_REGION=us-east-1 >> ./environment

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

```bash
# List running processes and use 'grep' to filter for processes containing 'agent' in their names.
ps aux | grep cocos-agent
# This command helps verify that the 'agent' process is running.
# The output shows the process ID (PID), resource usage, and other information about the 'cocos-agent' process.
# For example: 118 root     cocos-agent
```

We can also check if `Agent` is reachable from the host machine:

```bash
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

```bash
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

## API

### gRPC (port `7001`)

| Method | Description |
| --- | --- |
| `Run` | Submit a computation to be executed on a new CVM; streams back computation events |
| `CreateVM` | Provision a CVM with a given configuration (algorithm, datasets, policy) |
| `StopVM` | Terminate a running CVM |

### HTTP (port `7003`)

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/version` | Returns the running Manager version |
| `GET` | `/health` | Health check endpoint |

## Deployment

To start the service, execute the following shell script (note a server needs to be running — see [test/cvms/README.md](../test/cvms/README.md)):

The manager can be started as a *systemd* service or a standalone executable. To start the manager as a systemd service, look at the [systemd service script](https://github.com/ultravioletrs/cocos/blob/main/init/systemd/cocos-manager.service). The environment variables are defined in the `cocos-manager.env` file. Below are examples of how to start the manager.

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

To enable [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html) support, start manager like this:

```bash
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_ENABLE_SEV_SNP=true \
MANAGER_QEMU_SEV_SNP_CBITPOS=51 \
MANAGER_QEMU_BIN_PATH=<path to QEMU binary> \
MANAGER_QEMU_IGVM_FILE=<path to IGVM file> \
./build/cocos-manager
```

To enable [TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) support, start manager like this:

```bash
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_ENABLE_SEV_SNP=false \
MANAGER_QEMU_ENABLE_TDX=true \
MANAGER_QEMU_CPU=host \
MANAGER_QEMU_BIN_PATH=<path to QEMU binary> \
MANAGER_QEMU_OVMF_FILE=<path to OVMF file> \
./build/cocos-manager
```

## Troubleshooting

If the `ps aux | grep qemu-system-x86_64` gives you something like this:

```text
darko      13913  0.0  0.0      0     0 pts/2    Z+   20:17   0:00 [qemu-system-x86] <defunct>
```

this means that a QEMU virtual machine is currently defunct, meaning it is no longer running. More precisely, the defunct process is also known as a ["zombie" process](https://en.wikipedia.org/wiki/Zombie_process).

You can troubleshoot the VM launch procedure by running directly the `qemu-system-x86_64` command. When you run `manager` with `MANAGER_LOG_LEVEL=info` env var set, it prints out the entire command used to launch a VM. The relevant part of the log might look like this:

```json
{"level":"info","message":"/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty","ts":"2023-08-14T18:29:19.2653908Z"}
```

You can run the command — the value of the `"message"` key — directly in the terminal:

```bash
/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty
```

and look for possible problems. These problems can usually be solved by using the adequate env var assignments. Look in the `manager/qemu/config.go` file to see the recognized env vars. Don't forget to prepend `MANAGER_QEMU_` to the name of the env vars.

### Kill `qemu-system-x86_64` processes

To kill any leftover `qemu-system-x86_64` processes, use:

```bash
pkill -f qemu-system-x86_64
```

The `pkill` command is used to kill processes by name or by pattern. The `-f` flag specifies that we want to kill processes that match the pattern `qemu-system-x86_64`. It sends the SIGKILL signal to all processes that are running `qemu-system-x86_64`.

If this does not work, i.e. if `ps aux | grep qemu-system-x86_64` still outputs `qemu-system-x86_64` related process(es), you can kill the unwanted process with `kill -9 <PID>`, which also sends a SIGKILL signal to the process.

## Usage

For more information about service capabilities and its usage, please check out the [README documentation](../README.md).

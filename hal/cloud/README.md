# Agent Cloud Init Setup

The `hal/cloud` directory contains the files needed to configure an Ubuntu-based VM using cloud-init and deploy the Cocos Agent as a systemd service. This is an alternative to the Buildroot-based HAL for cloud or development environments.

## Directory Contents

| File | Description |
| --- | --- |
| `config.yaml` | Cloud-init user-data: installs packages, writes files, and runs setup commands |
| `meta-data` | VM metadata (instance ID, hostname) |
| `qemu.sh` | Downloads a base Ubuntu cloud image, applies cloud-init, and launches the VM with QEMU |
| `.env` | Environment variables controlling VM hardware parameters |

## Configuration

### `config.yaml`

The cloud-config file drives the automated setup inside the VM:

- **User** — creates `cocos_user` with `sudo` and `docker` group membership
- **Packages** — installs `curl`, `make`, `git`, `python3`, `python3-dev`, `net-tools`
- **Files** — writes TLS certificates to `/etc/cocos/certs/`, the Agent environment file to `/etc/cocos/environment`, and the systemd unit to `/etc/systemd/system/cocos-agent.service`
- **Commands** — creates runtime directories, downloads the Cocos Agent binary, installs Wasmtime and Docker, and enables the `cocos-agent` service

### `meta-data`

Contains instance-specific cloud-init metadata such as the instance ID and local hostname. Edit this file to match your environment before running `qemu.sh`.

## Environment Variables

The `.env` file controls QEMU hardware parameters and image paths. All values below are the defaults from the file — do not change them unless you know what you are overriding.

### Memory

| Variable | Description | Default |
| --- | --- | --- |
| `MEMORY_SIZE` | Initial VM memory | `2048M` |
| `MEMORY_SLOTS` | Number of memory slots | `5` |
| `MAX_MEMORY` | Maximum VM memory | `30G` |

### OVMF Firmware — Code

| Variable | Description | Default |
| --- | --- | --- |
| `OVMF_CODE_IF` | Interface type for OVMF code drive | `pflash` |
| `OVMF_CODE_FORMAT` | Format of OVMF code file | `raw` |
| `OVMF_CODE_UNIT` | Drive unit number for OVMF code | `0` |
| `OVMF_CODE_FILE` | Path to OVMF code firmware | `/usr/share/OVMF/OVMF_CODE.fd` |
| `OVMF_CODE_READONLY` | Mount OVMF code as read-only | `on` |
| `OVMF_VERSION` | EDKII version (leave empty for system default) | `""` |
| `OVMF_CODE` | Alternative combined OVMF code path | `/usr/share/ovmf/x64/OVMF_CODE.4m.fd` |

### OVMF Firmware — Variables

| Variable | Description | Default |
| --- | --- | --- |
| `OVMF_VARS_IF` | Interface type for OVMF variables drive | `pflash` |
| `OVMF_VARS_FORMAT` | Format of OVMF variables file | `raw` |
| `OVMF_VARS_UNIT` | Drive unit number for OVMF variables | `1` |
| `OVMF_VARS_FILE` | Path to OVMF variables file | `/usr/share/OVMF/OVMF_VARS.fd` |
| `OVMF_VARS` | Alternative OVMF variables path | `/usr/share/ovmf/x64/OVMF_VARS.4m.fd` |

### Networking

| Variable | Description | Default |
| --- | --- | --- |
| `NET_DEV_ID` | Network device ID | `vmnic` |
| `NET_DEV_HOST_FWD_AGENT` | Host port forwarded to Agent gRPC inside VM | `7020` |
| `NET_DEV_GUEST_FWD_AGENT` | Agent gRPC port inside VM | `7002` |
| `VIRTIO_NET_PCI_DISABLE_LEGACY` | Disable legacy PCI for virtio-net | `on` |
| `VIRTIO_NET_PCI_IOMMU_PLATFORM` | Enable IOMMU for virtio-net | `true` |
| `VIRTIO_NET_PCI_ADDR` | PCI address for virtio-net device | `0x2` |
| `VIRTIO_NET_PCI_ROMFILE` | ROM image for virtio-net (leave empty) | `""` |
| `HOST_FWD_RANGE` | Host port range for VM forwarding | `6100-6200` |

### Disk Images

| Variable | Description | Default |
| --- | --- | --- |
| `DISK_IMG_KERNEL_FILE` | Path to kernel image (empty = not used in cloud mode) | `""` |
| `DISK_IMG_ROOTFS_FILE` | Path to rootfs image (empty = not used in cloud mode) | `""` |
| `KERNEL_COMMAND_LINE` | Kernel command line arguments | `"quiet console=null"` |

### AMD SEV-SNP

| Variable | Description | Default |
| --- | --- | --- |
| `SEV_SNP_ID` | SEV-SNP device ID | `sev0` |
| `SEV_SNP_CBIT_POS` | C-bit position in physical address | `51` |
| `SEV_SNP_REDUCED_PHYS_BITS` | Number of reduced physical address bits | `1` |
| `SEV_SNP_HOST_DATA` | Additional SEV-SNP host data | `""` |
| `ENABLE_SEV_SNP` | Enable SEV-SNP | `false` |

### Machine

| Variable | Description | Default |
| --- | --- | --- |
| `BIN_PATH` | Path to QEMU binary | `qemu-system-x86_64` |
| `QEMU_BINARY` | Alternative QEMU binary path | `qemu-system-x86_64` |
| `USE_SUDO` | Run QEMU with sudo | `false` |
| `ENABLE_KVM` | Enable KVM acceleration | `true` |
| `MACHINE` | QEMU machine type | `q35` |
| `CPU` | CPU model | `EPYC` |
| `SMP_COUNT` | Number of virtual CPUs | `8` |
| `SMP_MAXCPUS` | Maximum number of virtual CPUs | `64` |
| `MEM_ID` | Memory device ID | `ram1` |
| `NO_GRAPHIC` | Disable graphical display | `true` |
| `MONITOR` | QEMU monitor type | `pty` |
| `KERNEL_HASH` | Verify kernel hash on boot | `false` |

### VM Image

| Variable | Description | Default |
| --- | --- | --- |
| `COCOS_AGENT_VERSION` | Cocos Agent release to install | `v0.3.1` |
| `BASE_IMAGE_URL` | URL of the base Ubuntu cloud image | `https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img` |
| `BASE_IMAGE` | Local filename for the base image | `ubuntu-base.qcow2` |
| `CUSTOM_IMAGE` | Local filename for the customized image | `ubuntu-custom.qcow2` |
| `VM_NAME` | VM display name | `cocos-vm` |
| `RAM` | VM RAM allocation | `16G` |
| `DISK_SIZE` | Root filesystem disk size | `10G` |

### Mounts and Certificates

| Variable | Description | Default |
| --- | --- | --- |
| `CERTS_MOUNT` | Path where certificates are mounted inside the VM | `/etc/cocos/certs` |
| `ENV_MOUNT` | Path where the environment file is mounted inside the VM | `/etc/cocos/environment` |
| `AGENT_GRPC_SERVER_CERT` | Agent gRPC server certificate path | `/etc/cocos/certs/server.pem` |
| `AGENT_GRPC_SERVER_KEY` | Agent gRPC server key path | `/etc/cocos/certs/key.pem` |
| `AGENT_GRPC_SERVER_CA_CERTS` | Agent gRPC CA certificate path | `/etc/cocos/ca.pem` |
| `AGENT_GRPC_CLIENT_CA_CERTS` | Agent gRPC client CA certificate path | `/etc/cocos/ca.pem` |

## Running

```bash
# Must be run as root
sudo ./qemu.sh
```

The script downloads the base Ubuntu cloud image, applies the `config.yaml` cloud-init configuration, and boots the VM. The Cocos Agent starts automatically as a systemd service and is accessible on host port `7020`.

## Debugging

### Manually start or restart the Agent

```bash
sudo systemctl start cocos-agent.service
```

### Check service status

```bash
sudo systemctl status cocos-agent.service
```

### View systemd journal logs

```bash
journalctl -u cocos-agent.service
```

### View file-based logs

```bash
cat /var/log/cocos/agent.stdout.log
cat /var/log/cocos/agent.stderr.log
```

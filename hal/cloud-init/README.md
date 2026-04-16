# Cloud-Init Seed Workflow

This directory contains a host-side workflow for preparing an Ubuntu `qcow2` image with `cloud-init`.

The main flow is:

- create a NoCloud `seed.iso` from [package-services.yaml](./package-services.yaml) and [meta-data](../cloud/meta-data)
- boot a writable Ubuntu `qcow2` overlay with that seed attached
- let `cloud-init` install and configure the Cocos services inside the guest
- grow the root partition and filesystem if the qcow2 disk was created larger than the base image
- power the VM off automatically when provisioning is finished

This workflow is only for preparing the Ubuntu image with `cloud-init`. It is not the SEV-SNP CVM launcher.

## Files

- [package-services.yaml](./package-services.yaml): cloud-init user-data
- [create-seed-iso.sh](./create-seed-iso.sh): builds a NoCloud `seed.iso`
- [qemu.sh](./qemu.sh): creates `seed.iso`, recreates the writable qcow2 overlay, and launches QEMU
- [buildroot](./buildroot): mirrored Buildroot external tree used for the CVM side

## Requirements

Install these on the host:

- `qemu-system-x86_64` or whatever binary is set in [`.env`](../cloud/.env)
- `qemu-img`
- `wget`
- one of `xorriso`, `genisoimage`, or `mkisofs`

The VM defaults are read from [`.env`](../cloud/.env).

## Create The Seed ISO

To create `seed.iso` only:

```bash
cd ./cocos/hal/cloud-init
./create-seed-iso.sh
```

To write the ISO somewhere else:

```bash
./create-seed-iso.sh ./out/seed.iso
```

Supported environment overrides for [create-seed-iso.sh](./create-seed-iso.sh):

- `USER_DATA_SOURCE`
- `META_DATA_SOURCE`
- `NETWORK_CONFIG_SOURCE`

Package toggles for the `hal/linux/package` package set are also supported:

- `COCOS_INSTALL_AGENT`
- `COCOS_INSTALL_ATTESTATION_SERVICE`
- `COCOS_INSTALL_CC_ATTESTATION_AGENT`
- `COCOS_INSTALL_COCO_KEYPROVIDER`
- `COCOS_INSTALL_COMPUTATION_RUNNER`
- `COCOS_INSTALL_EGRESS_PROXY`
- `COCOS_INSTALL_INGRESS_PROXY`
- `COCOS_INSTALL_LOG_FORWARDER`
- `COCOS_INSTALL_WASMEDGE`

Defaults:

- `COCOS_INSTALL_CC_ATTESTATION_AGENT=false`
- `COCOS_INSTALL_COCO_KEYPROVIDER=false`
- all other `COCOS_INSTALL_*` toggles default to `true`

Runtime dependencies are resolved automatically during provisioning:

- `COCOS_INSTALL_AGENT=true` also enables `attestation-service`, `log-forwarder`, `computation-runner`, `ingress-proxy`, and `egress-proxy`
- `COCOS_INSTALL_COMPUTATION_RUNNER=true` also enables `log-forwarder`
- `COCOS_INSTALL_COCO_KEYPROVIDER=true` also enables `cc-attestation-agent`

Example:

```bash
USER_DATA_SOURCE=./package-services.yaml ./create-seed-iso.sh
```

Example with package selection:

```bash
COCOS_INSTALL_AGENT=false COCOS_INSTALL_WASMEDGE=false ./create-seed-iso.sh
```

## Boot The Prep VM

To create the seed ISO and boot the Ubuntu prep VM:

```bash
cd ./cocos/hal/cloud-init
sudo ./qemu.sh
```

What [qemu.sh](./qemu.sh) does:

- loads defaults from [`.env`](../cloud/.env)
- downloads the base Ubuntu image if it is missing
- recreates `seed.iso`
- deletes and recreates the writable qcow2 overlay image
- boots QEMU with the seed ISO attached as a CD-ROM and the writable qcow2 attached as the VM disk

Important:

- [qemu.sh](./qemu.sh) must be run as `root`
- the writable qcow2 at `CUSTOM_IMAGE_PATH` is removed and recreated on each run
- the VM powers itself off after `cloud-init` finishes, so the altered image is left on disk for later use

Useful environment overrides for [qemu.sh](./qemu.sh):

- `SEED_ISO`
- `META_DATA`
- `BASE_IMAGE_PATH`
- `CUSTOM_IMAGE_PATH`
- `OVMF_FILE`
- all `COCOS_INSTALL_*` package toggles listed above

Example:

```bash
sudo BASE_IMAGE_PATH=./ubuntu-base.qcow2 CUSTOM_IMAGE_PATH=./ubuntu-custom.qcow2 ./qemu.sh
```

Example with package selection:

```bash
sudo COCOS_INSTALL_AGENT=false COCOS_INSTALL_WASMEDGE=false ./qemu.sh
```

Example with a single firmware file:

```bash
sudo OVMF_FILE=./OVMF.fd BASE_IMAGE_PATH=./base-image.qcow2 ./qemu.sh
```

## What The Guest Configures

On first boot, [package-services.yaml](./package-services.yaml) will:

- grow the root partition and filesystem to use extra disk space when the qcow2 is larger than the base image
- install build dependencies with `apt`
- build and install the Cocos package-defined services
- optionally build and install `attestation-agent` and `coco_keyprovider`
- optionally install WasmEdge
- configure `/etc/ocicrypt_keyprovider.conf`
- prepare 9P mountpoints and `/etc/fstab` entries for `certs_share` and `env_share`
- enable and restart the configured systemd services
- power the VM off when provisioning is complete

The package install list can be reduced with the `COCOS_INSTALL_*` environment variables when creating the seed ISO or running [qemu.sh](./qemu.sh).

With the default package selection, the configured services are:

- `cocos-agent`
- `log-forwarder`
- `computation-runner`
- `egress-proxy`
- `attestation-service`

Optional services when enabled are:

- `attestation-agent`
- `coco-keyprovider`

## 9P Note

The altered Ubuntu image is prepared to use 9P mounts through `/etc/fstab`, but [qemu.sh](./qemu.sh) 

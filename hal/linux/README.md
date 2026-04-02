# Hardware Abstraction Layer (HAL) — Linux

Cocos HAL for Linux is a framework for building a custom in-enclave Linux distribution. It uses [Buildroot](https://buildroot.org/) to produce a minimal, hardened OS image that runs inside a Confidential Virtual Machine (CVM) and hosts the Cocos Agent.

## Purpose

The HAL provides the trusted software base inside the enclave:

- **Hardened Linux kernel** — stripped-down kernel with only the drivers needed for CVM operation
- **Minimal root filesystem** — smallest possible TCB (Trusted Computing Base) to reduce attack surface
- **Secure bootloader** — ensures the boot chain is measured and verifiable via remote attestation
- **Cocos Agent** — baked into the image and started automatically on boot

The resulting kernel (`bzImage`) and root filesystem (`rootfs.cpio.gz`) are loaded by the Manager when provisioning a new CVM.

## Build

HAL uses Buildroot's [External Tree mechanism](https://buildroot.org/downloads/manual/manual.html#outside-br-custom):

```bash
git clone git@github.com:ultravioletrs/cocos.git
git clone git@github.com:buildroot/buildroot.git
cd buildroot
git checkout 2025.08-rc3
make BR2_EXTERNAL=../cocos/hal/linux cocos_defconfig
# Optional: run menuconfig to make additional Buildroot configuration changes
make menuconfig
make
```

## Output

After a successful build, Buildroot writes the images to `buildroot/output/images/`:

```text
buildroot/output/images/
├── bzImage          # Linux kernel image
└── rootfs.cpio.gz   # Compressed root filesystem (initramfs)
```

Copy these to the Manager's image directory before starting the Manager:

```bash
cp buildroot/output/images/bzImage     /path/to/cocos/cmd/manager/img/
cp buildroot/output/images/rootfs.cpio.gz /path/to/cocos/cmd/manager/img/
```

Pre-built EOS images are also available on the [Cocos releases page](https://github.com/ultravioletrs/cocos/releases).

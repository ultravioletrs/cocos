# Hardware Abstraction Layer (HAL) for Confidential Computing

Cocos HAL for Linux is framework for building custom in-enclave Linux distribution.

## Usage

HAL uses [Buildroot](https://buildroot.org/)'s [_External Tree_ mechanism](https://buildroot.org/downloads/manual/manual.html#outside-br-custom) for building custom distro:

```bash
git clone git@github.com:ultravioletrs/cocos.git
git clone git@github.com:buildroot/buildroot.git
cd buildroot
git checkout 2025.11
make BR2_EXTERNAL=../cocos/hal/linux cocos_defconfig
# Execute 'make menuconfig' only if you want to make additional configuration changes to Buildroot.
make menuconfig
make
```

When launching the CVM, ensure the `src_ip` and `src_port` parameters are included in the kernel command line. These parameters point to the NBD server that hosts the source disk image. For example:

```bash
qemu-system-x86_64 \
    -enable-kvm \
    -cpu EPYC-v4 \
    ...
    -append "console=ttyS0 src_ip=10.172.192.30 src_port=10809" \
    ...
```

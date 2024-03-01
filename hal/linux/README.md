# Hardware Abstraction Layer (HAL) for Confidential Computing
Cocos HAL for Linux is framework for building custom in-enclave Linux distribution. 

## Usage
HAL uses [Buildroot](https://buildroot.org/)'s [_External Tree_ mechanism](https://buildroot.org/downloads/manual/manual.html#outside-br-custom) for building custom distro:

```bash
git clone git@github.com:ultravioletrs/cocos.git
git clone git@github.com:buildroot/buildroot.git
cd buildroot
make BR2_EXTERNAL=../cocos/hal/linux cocos_defconfig
# Execute 'make menuconfig' only if you want to make additional configuration changes to Buildroot.
make menuconfig
make
```

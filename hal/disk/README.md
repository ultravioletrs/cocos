# Disk Image Workflow

This directory is the Buildroot external tree for the current Cocos disk test
VM image and its runtime configuration.

## Layout

- [configs/cocos_defconfig](./configs/cocos_defconfig):
  Buildroot configuration for the bootable image.
- [board/rootfs-overlay/init](./board/rootfs-overlay/init):
  early initramfs script that provisions `/cocos`, mounts the real root, and
  switches into the installed system.
- [board/cocos/genimage.cfg](./board/cocos/genimage.cfg):
  GPT disk layout for the final `disk.img`.
- [board/cocos/post-image.sh](./board/cocos/post-image.sh):
  builds the minimal initramfs, stages EFI files, signs boot artifacts, and
  assembles `disk.img`.
- [external.desc](./external.desc): Buildroot external tree descriptor.
- [external.mk](./external.mk): includes package makefiles from `package/*`.

## Current Buildroot Image

The current Buildroot flow produces a bootable GPT disk image:

- `efi` partition: FAT EFI system partition with GRUB, kernel, and initramfs
- `root` partition: ext4 root filesystem protected by dm-verity
- `verity` partition: dm-verity hash tree for the root filesystem
- `cocos` partition: blank partition provisioned at boot as an encrypted ext4
  filesystem mounted at `/cocos`

The final image is written to:

```bash
output/images/disk.img
```

The root filesystem image is also available separately as:

```bash
output/images/rootfs.ext4
```

## Current Boot Flow

At boot, GRUB loads:

- `bzImage`
- `initrd.cpio.gz`

The initramfs script in
[board/rootfs-overlay/init](./board/rootfs-overlay/init)
then:

1. mounts `/proc`, `/sys`, `devtmpfs`, and `devpts`
2. assumes the boot disk is `/dev/sda`
3. opens a dm-verity mapping for the root filesystem using:
   - `/dev/sda2` as the data partition
   - `/dev/sda3` as the verity hash partition
   - `roothash=` from the kernel command line
4. mounts `/dev/mapper/root_verity` read-only at `/root`
5. generates a fresh ephemeral key
6. formats `/dev/sda4` as LUKS2
7. opens it as `/dev/mapper/cocos_crypt`
8. formats that mapper as ext4 and mounts it at `/root/cocos`
9. creates working directories on `/cocos`, including:
   - `/cocos/.cache/oci`
   - `/cocos/datasets`
   - `/cocos/docker`
   - `/cocos/cocos_init`
10. mounts `tmpfs` on `/tmp` and `/var` because the root filesystem is
   intentionally read-only
11. bind-mounts `/cocos/docker` onto `/var/lib/docker`
12. bind-mounts `/cocos/cocos_init` onto `/cocos_init`
13. rewrites `/etc/fstab` in the mounted root to describe the live runtime
14. preserves or adds 9P mounts for:
    - `certs_share` -> `/etc/certs`
    - `env_share` -> `/etc/cocos`
15. securely wipes the temporary LUKS key file
16. runs `switch_root /root /sbin/init`

Important details:

- the root filesystem is verified through dm-verity before it is mounted
- `/cocos` is encrypted with an ephemeral per-boot key
- that key is not persisted, so `/cocos` is provisioned fresh on each boot

## Runtime Filesystem Model

The running system is split into:

- read-only root on `/`
- encrypted writable storage on `/cocos`
- `tmpfs` on `/tmp`
- `tmpfs` on `/var`

Service state that must survive within a boot session is redirected away from
the read-only root:

- Docker data lives on `/cocos/docker`
- agent setup scripts work through `/cocos_init`, which is backed by
  `/cocos/cocos_init`
- algorithm datasets and results live under `/cocos`

This means services can use `/cocos` like a regular directory tree after boot,
even though it is backed by an encrypted mapper created in early userspace.

## systemd Runtime Expectations

Several services depend on files mounted from 9P shares under `/etc/certs` and
`/etc/cocos`. To avoid boot-order races, the rootfs overlay includes systemd
drop-ins under:

```bash
board/rootfs-overlay/usr/lib/systemd/system/*service.d/
```

These drop-ins require the relevant mount points before starting services such
as:

- `egress-proxy.service`
- `log-forwarder.service`
- `computation-runner.service`
- `cocos-agent.service`

The overlay also ships tmpfiles rules in
[board/rootfs-overlay/usr/lib/tmpfiles.d/cocos.conf](./board/rootfs-overlay/usr/lib/tmpfiles.d/cocos.conf)
to create:

- `/var/log/cocos`
- `/run/cocos`

## Agent Packaging In Buildroot

The Buildroot `agent` package is wired to build the binary from the local Cocos
checkout, not only from a downloaded release snapshot. The package definition is
in [package/agent/agent.mk](./package/agent/agent.mk).

That package currently:

- builds `cocos-agent` from the local source tree
- installs the local
  [cocos-agent.service](../../init/systemd/cocos-agent.service)
- installs the local
  [agent_setup.sh](../../init/systemd/agent_setup.sh)
- installs the local
  [agent_start_script.sh](../../init/systemd/agent_start_script.sh)

So changes under:

- `cocos/agent/...`
- `cocos/init/systemd/...`

are intended to be picked up by the next Buildroot rebuild.

## Buildroot Packages And Tools

The current `cocos_defconfig` includes the components needed by the boot flow
and runtime image, including:

- systemd
- DHCP client
- `cryptsetup`
- `eudev`
- `e2fsprogs`
- Docker, containerd, and runc
- `skopeo`
- TPM2 tools
- 9P filesystem support
- GRUB2 EFI boot support
- host `genimage`

The initramfs built in `post-image.sh` is intentionally minimal and contains
only the binaries needed for early boot, dm-verity root verification, and
`/cocos` provisioning.

## Secure Boot Notes

During `post-image.sh`:

- GRUB is rebuilt with `--disable-shim-lock`
- `bootx64.efi` and `bzImage` are signed with the configured Secure Boot keys
  when those keys are present

This flow is designed for booting directly through OVMF with your own enrolled
keys. It does not currently rely on booting through `shim`.

## Rebuilding

This directory is meant to be used as a Buildroot external tree. From this
directory, configure a Buildroot checkout with:

```bash
make -C /path/to/buildroot BR2_EXTERNAL=$PWD cocos_defconfig
```

Then build with:

```bash
make -C /path/to/buildroot BR2_EXTERNAL=$PWD -j$(nproc)
```

The resulting boot image is:

```bash
/path/to/buildroot/output/images/disk.img
```

Additional generated artifacts include:

```bash
/path/to/buildroot/output/images/rootfs.ext4
/path/to/buildroot/output/images/rootfs.verity
/path/to/buildroot/output/images/rootfs.roothash
```

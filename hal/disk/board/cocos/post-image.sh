#!/bin/bash

COCOS_BOARD_DIR="$(dirname "$0")"
DEFCONFIG_NAME="$(basename "$2")"
README_FILES="${COCOS_BOARD_DIR}/readme.txt"
START_QEMU_SCRIPT="${BINARIES_DIR}/start-qemu.sh"

# ---------------------------------------------------------------------------
# Build a minimal FDE initramfs (rootfs.cpio.gz) containing only the tools
# needed to mount the root partition read-only, provision LUKS2, and switch_root.
# All other packages live
# on the ext4 disk image and are available after switch_root.
# ---------------------------------------------------------------------------
echo "[post-image] Building minimal FDE initramfs..."

INITRAMFS_STAGE="${BUILD_DIR}/initramfs-staging"
rm -rf "${INITRAMFS_STAGE}"

# Merged-usr layout: bin/sbin/lib/lib64 are symlinks into usr/, matching the
# Buildroot target layout so that hardcoded ELF interpreter paths (ld-linux)
# and the #!/bin/sh shebang both resolve correctly inside the initramfs.
mkdir -p "${INITRAMFS_STAGE}/usr/bin" \
         "${INITRAMFS_STAGE}/usr/sbin" \
         "${INITRAMFS_STAGE}/usr/lib" \
         "${INITRAMFS_STAGE}/dev" \
         "${INITRAMFS_STAGE}/proc" \
         "${INITRAMFS_STAGE}/sys" \
         "${INITRAMFS_STAGE}/tmp" \
         "${INITRAMFS_STAGE}/run" \
         "${INITRAMFS_STAGE}/root" \
         "${INITRAMFS_STAGE}/etc/udev/rules.d"
ln -s usr/bin  "${INITRAMFS_STAGE}/bin"
ln -s usr/sbin "${INITRAMFS_STAGE}/sbin"
ln -s usr/lib  "${INITRAMFS_STAGE}/lib"
ln -s usr/lib  "${INITRAMFS_STAGE}/lib64"

# init script (PID 1)
install -m 0755 "${BR2_EXTERNAL_COCOS_PATH}/board/rootfs-overlay/init" \
    "${INITRAMFS_STAGE}/init"

# Binaries required by the init script
FDE_BINS="
    bash
    cryptsetup
    veritysetup
    mkfs.ext4
    mount
    umount
    losetup
    switch_root
    dd
    shred
    tr
    cut
    grep
    awk
    cat
    ls
    cp
    mkdir
    readlink
    dirname
    lsblk
    udevadm
    blkid
    rm
"

for BIN in ${FDE_BINS}; do
    SRC="$(find "${TARGET_DIR}/usr/bin" "${TARGET_DIR}/usr/sbin" \
               "${TARGET_DIR}/bin"      "${TARGET_DIR}/sbin" \
               -name "${BIN}" \( -type f -o -type l \) 2>/dev/null | head -1)"
    if [ -n "${SRC}" ]; then
        cp -P "${SRC}" "${INITRAMFS_STAGE}/usr/bin/${BIN}"
        chmod 0755 "${INITRAMFS_STAGE}/usr/bin/${BIN}" 2>/dev/null || true
        # If this is a symlink, also copy the resolved target binary (e.g. busybox, coreutils, mke2fs)
        # so that other applet symlinks pointing to the same target also work at runtime.
        if [ -L "${SRC}" ]; then
            REAL_SRC="$(readlink -f "${SRC}")"
            REAL_NAME="$(basename "${REAL_SRC}")"
            if [ -f "${REAL_SRC}" ] && [ ! -e "${INITRAMFS_STAGE}/usr/bin/${REAL_NAME}" ]; then
                cp "${REAL_SRC}" "${INITRAMFS_STAGE}/usr/bin/${REAL_NAME}"
                chmod 0755 "${INITRAMFS_STAGE}/usr/bin/${REAL_NAME}" 2>/dev/null || true
            fi
        fi
    else
        echo "[post-image] WARNING: ${BIN} not found in target, skipping"
    fi
done

# sh symlink so #!/bin/sh in the init script resolves correctly
ln -sf bash "${INITRAMFS_STAGE}/usr/bin/sh"

# Shared libraries from usr/lib (TARGET_DIR uses merged-usr so lib → usr/lib)
# Skip large runtimes that are only needed on the real root.
find "${TARGET_DIR}/usr/lib" \( \
        -path "*/python3*" -o \
        -path "*/gcc*"     -o \
        -path "*/wasmedge*" \
    \) -prune -o \
    \( -name "*.so" -o -name "*.so.*" \) -print | while read -r LIB; do
    REL="${LIB#${TARGET_DIR}/usr/lib/}"
    DEST="${INITRAMFS_STAGE}/usr/lib/${REL}"
    mkdir -p "$(dirname "${DEST}")"
    cp -P "${LIB}" "${DEST}"
done

# udev rules (needed for udevadm settle)
if [ -d "${TARGET_DIR}/etc/udev" ]; then
    cp -a "${TARGET_DIR}/etc/udev/." "${INITRAMFS_STAGE}/etc/udev/"
fi

# /dev seed nodes
mknod -m 0600 "${INITRAMFS_STAGE}/dev/console" c 5 1 2>/dev/null || true
mknod -m 0666 "${INITRAMFS_STAGE}/dev/null"    c 1 3 2>/dev/null || true

echo "[post-image] Packing initramfs..."
( cd "${INITRAMFS_STAGE}" && \
    find . | cpio --quiet -o -H newc -R 0:0 | gzip -9 \
    > "${BINARIES_DIR}/rootfs.cpio.gz" )
echo "[post-image] rootfs.cpio.gz: $(du -sh "${BINARIES_DIR}/rootfs.cpio.gz" | cut -f1)"

ROOTFS_IMAGE="${BINARIES_DIR}/rootfs.ext4"
VERITY_IMAGE="${BINARIES_DIR}/rootfs.verity"
ROOT_HASH_FILE="${BINARIES_DIR}/rootfs.roothash"
VERITYSETUP_BIN="${HOST_DIR}/bin/veritysetup"

if [ ! -x "${VERITYSETUP_BIN}" ]; then
    VERITYSETUP_BIN="${HOST_DIR}/sbin/veritysetup"
fi

if [ ! -x "${VERITYSETUP_BIN}" ]; then
    echo "[post-image] FATAL: host veritysetup not found at ${VERITYSETUP_BIN}"
    exit 1
fi

echo "[post-image] Building dm-verity hash image..."
rm -f "${VERITY_IMAGE}" "${ROOT_HASH_FILE}"
truncate -s 256M "${VERITY_IMAGE}"
VERITY_FORMAT_OUTPUT="$("${VERITYSETUP_BIN}" format "${ROOTFS_IMAGE}" "${VERITY_IMAGE}")" || {
    echo "[post-image] FATAL: veritysetup format failed"
    exit 1
}

ROOT_HASH="$(printf '%s\n' "${VERITY_FORMAT_OUTPUT}" | awk -F': ' '/^Root hash:/ {print $2}' | tr -d '[:space:]')"
if [ -z "${ROOT_HASH}" ]; then
    echo "[post-image] FATAL: failed to parse dm-verity root hash"
    printf '%s\n' "${VERITY_FORMAT_OUTPUT}"
    exit 1
fi
printf '%s\n' "${ROOT_HASH}" > "${ROOT_HASH_FILE}"
echo "[post-image] dm-verity root hash: ${ROOT_HASH}"

# Stage kernel and initramfs for the EFI partition.
# Buildroot's GRUB2 package has already placed bootx64.efi at
# ${BINARIES_DIR}/efi-part/EFI/BOOT/bootx64.efi; we add the kernel,
# initramfs, and overwrite the default grub.cfg with our boot entry.
echo "[post-image] Staging EFI partition files..."
mkdir -p "${BINARIES_DIR}/efi-part/EFI/BOOT"
cp "${BINARIES_DIR}/bzImage"        "${BINARIES_DIR}/efi-part/bzImage"
cp "${BINARIES_DIR}/rootfs.cpio.gz" "${BINARIES_DIR}/efi-part/initrd.cpio.gz"

cat > "${BINARIES_DIR}/efi-part/EFI/BOOT/grub.cfg" << GRUBCFG
set default=0
set timeout=0

menuentry "Cocos" {
    linux /bzImage console=ttyS0 roothash=${ROOT_HASH} systemd.verity=0 systemd.gpt_auto=0
    initrd /initrd.cpio.gz
}
GRUBCFG

# Regenerate bootx64.efi with --disable-shim-lock so GRUB can load the kernel
# directly without requiring the shim bootloader (OVMF still verifies GRUB via
# Secure Boot; shim is not needed when booting from a custom OVMF with own DB key).
GRUB_CORE="$(ls -d "${BUILD_DIR}"/grub2-*/build-x86_64-efi/grub-core 2>/dev/null | head -1)"
if [ -n "${GRUB_CORE}" ]; then
    echo "[post-image] Regenerating bootx64.efi with --disable-shim-lock..."
    "${HOST_DIR}/bin/grub-mkimage" \
        -d "${GRUB_CORE}" \
        -O x86_64-efi \
        -o "${BINARIES_DIR}/efi-part/EFI/BOOT/bootx64.efi" \
        -p "/EFI/BOOT" \
        --disable-shim-lock \
        boot linux echo normal part_gpt fat ls search || {
        echo "[post-image] FATAL: grub-mkimage failed"
        exit 1
    }
else
    echo "[post-image] WARNING: GRUB core dir not found, skipping --disable-shim-lock rebuild"
fi

# Sign GRUB and kernel for UEFI Secure Boot.
# Keys are resolved in order: env var → board/secure-boot/ defaults.
SB_KEY="${SB_KEY:-${COCOS_BOARD_DIR}/secure-boot/db.key}"
SB_CERT="${SB_CERT:-${COCOS_BOARD_DIR}/secure-boot/db.crt}"
if [ -f "${SB_KEY}" ] && [ -f "${SB_CERT}" ]; then
    echo "[post-image] Signing EFI binaries for Secure Boot..."
    sbsign --key "${SB_KEY}" --cert "${SB_CERT}" \
        --output "${BINARIES_DIR}/efi-part/EFI/BOOT/bootx64.efi" \
        "${BINARIES_DIR}/efi-part/EFI/BOOT/bootx64.efi" || {
        echo "[post-image] FATAL: Failed to sign bootx64.efi"
        exit 1
    }
    sbsign --key "${SB_KEY}" --cert "${SB_CERT}" \
        --output "${BINARIES_DIR}/efi-part/bzImage" \
        "${BINARIES_DIR}/efi-part/bzImage" || {
        echo "[post-image] FATAL: Failed to sign bzImage"
        exit 1
    }
    echo "[post-image] Secure Boot signing complete"
else
    echo "[post-image] WARNING: Secure Boot keys not found — EFI binaries are unsigned"
    echo "[post-image]   Default location: ${COCOS_BOARD_DIR}/secure-boot/db.key + db.crt"
    echo "[post-image]   Override:         SB_KEY=/path/to/db.key SB_CERT=/path/to/db.crt make"
fi

GENIMAGE_CFG="${COCOS_BOARD_DIR}/genimage.cfg"
if [ -f "${GENIMAGE_CFG}" ]; then
    GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"
    rm -rf "${GENIMAGE_TMP}"
    genimage \
        --rootpath "${TARGET_DIR}" \
        --tmppath "${GENIMAGE_TMP}" \
        --inputpath "${BINARIES_DIR}" \
        --outputpath "${BINARIES_DIR}" \
        --config "${GENIMAGE_CFG}"
fi

if [[ "${DEFCONFIG_NAME}" =~ ^"cocos_*" ]]; then
    # Not a Qemu defconfig, can't test.
    exit 0
fi

# Search for "# qemu_*_defconfig" tag in all readme.txt files.
# Qemu command line on multilines using back slash are accepted.
# shellcheck disable=SC2086 # glob over each readme file
QEMU_CMD_LINE="$(sed -r ':a; /\\$/N; s/\\\n//; s/\t/ /; ta; /# '"${DEFCONFIG_NAME}"'$/!d; s/#.*//' ${README_FILES})"

if [ -z "${QEMU_CMD_LINE}" ]; then
    # No Qemu cmd line found, can't test.
    exit 0
fi

# Remove output/images path since the script will be in
# the same directory as the kernel and the rootfs images.
QEMU_CMD_LINE="${QEMU_CMD_LINE//output\/images\//}"

# Remove -serial stdio if present, keep it as default args
DEFAULT_ARGS="$(sed -r -e '/-serial stdio/!d; s/.*(-serial stdio).*/\1/' <<<"${QEMU_CMD_LINE}")"
QEMU_CMD_LINE="${QEMU_CMD_LINE//-serial stdio/}"

# Remove any string before qemu-system-*
QEMU_CMD_LINE="$(sed -r -e 's/^.*(qemu-system-)/\1/' <<<"${QEMU_CMD_LINE}")"

# Disable graphical output and redirect serial I/Os to console
case ${DEFCONFIG_NAME} in
  (qemu_sh4eb_r2d_defconfig|qemu_sh4_r2d_defconfig)
    # Special case for SH4
    SERIAL_ARGS="-serial stdio -display none"
    ;;
  (*)
    SERIAL_ARGS="-nographic"
    ;;
esac

sed -e "s|@SERIAL_ARGS@|${SERIAL_ARGS}|g" \
    -e "s|@DEFAULT_ARGS@|${DEFAULT_ARGS}|g" \
    -e "s|@QEMU_CMD_LINE@|${QEMU_CMD_LINE}|g" \
    -e "s|@HOST_DIR@|${HOST_DIR}|g" \
    <"${COCOS_BOARD_DIR}/start-qemu.sh.in" \
    >"${START_QEMU_SCRIPT}"
chmod +x "${START_QEMU_SCRIPT}"

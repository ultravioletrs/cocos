# QEMU qcow2 NBD Export Script

This script launches a **read-only NBD server** backed by a `qcow2` disk image.  
It is used as the **trusted source image** for an SEV-SNP/TDX CVM initramfs, where the VM:

1. Connects to the NBD server  
2. Creates a fresh encrypted LUKS2 disk  
3. Copies the qcow2 contents into the encrypted disk  
4. Hashes the content  
5. Extends a vTPM PCR with that hash (only for vTPM with SEV-SNP)
6. Boots into the newly-cloned encrypted disk  

This script runs **outside** the VM and simply starts the qcow2 → NBD export.

The `qcow2` disk image can be downloaded from [Ubuntu Cloud Images](https://cloud-images.ubuntu.com/).

---

## Features

✔ Exports a qcow2 image through `qemu-nbd` on a specified port  
✔ Runs in **persistent** mode (keeps serving even after disconnects)  
✔ Ensures **read-only** access for safety  
✔ Automatically kills previous NBD processes bound to the same port  
✔ Produces a stable `nbd:localhost:<PORT>` endpoint for VM consumption  

---

## Requirements

You need:

- QEMU with NBD support (`qemu-utils` or `qemu-tools`)
- `sudo` privileges
- A qcow2 image to export

Verify installation:

```sh
qemu-nbd --version
```

## Create a QCOW2 destination image

A blank destination QCOW2 image can be created using this code:

```bash
SRC_IMAGE=<path-to-src-image>
DST_IMAGE=<path-to-dst-image>

SIZE=$(qemu-img info "$SRC_IMAGE" | awk '/virtual size:/ {
    # Extract bytes from parentheses: (10737418240 bytes)
    match($0, /\(([0-9]+) bytes\)/, arr)
    bytes = arr[1]
    
    # Convert to GB and round up, add 1GB headroom
    gb = int(bytes / 1024 / 1024 / 1024) + 1
    print gb "G"
}')

qemu-img create -f qcow2 $DST_IMAGE $SIZE
```

The destination image can be now used for a fresh CVM.

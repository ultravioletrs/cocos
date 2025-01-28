#!/bin/bash

source ./.env

# File paths
SERVER_CA=$(<./ca.pem)
SERVER_CERT=$(<./cert.pem)
SERVER_KEY=$(<./key.pem)
AGENT_ENV=$(<./.env)

# Required commands
REQUIRED_CMDS=("wget" "cloud-localds" "$QEMU_BINARY" "qemu-img")

# Check for required commands
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed. Please install it and try again."
        exit 1
    fi
done

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi


# Create the root filesystem image if it doesn't exist
if [ ! -f $BASE_IMAGE ]; then
  echo "Downloading base Ubuntu image..."
  wget -q $BASE_IMAGE_URL -O $BASE_IMAGE --show-progress
fi

# Create custom image
echo "Creating custom QEMU image..."
qemu-img create -f qcow2 -b $BASE_IMAGE -F qcow2 $CUSTOM_IMAGE $DISK_SIZE

# Cloud-init configuration files
USER_DATA="user-data"
META_DATA="meta-data"
SEED_IMAGE="seed.img"

cat <<EOF > $USER_DATA
#cloud-config
package_update: true
package_upgrade: false

users:
  - default
  - name: cocos
    gecos: Default User
    groups:
      - sudo
    sudo:
      - ALL=(ALL:ALL) ALL
    shell: /bin/bash

chpasswd:
  list: |
    cocos:password
  expire: False

ssh_pwauth: True

packages:
  - curl
  - make
  - install
  - git
  - python3
  - python3-dev

write_files:
  - path: /etc/cocos/environment
    content: |
      $AGENT_ENV
    permissions: '0644'

  - path: /etc/cocos/certs/cert.pem
    content: |
      $SERVER_CERT
    permissions: '0644'

  - path: /etc/cocos/certs/ca.pem
    content: |
      $SERVER_CA
    permissions: '0644'

  - path: /etc/cocos/certs/key.pem
    content: |
      $SERVER_KEY
    permissions: '0600'

runcmd:
  # Install Docker
  - curl -fsSL https://get.docker.com -o get-docker.sh
  - sh ./get-docker.sh
  - groupadd docker
  - usermod -aG docker cocos_user
  - newgrp docker

  # Install Wasmtime
  - curl https://wasmtime.dev/install.sh -sSf | bash
  - echo "export WASMTIME_HOME=$HOME/.wasmtime" >> /etc/profile.d/wasm_env.sh
  - echo "export PATH=\$WASMTIME_HOME/bin:\$PATH" >> /etc/profile.d/wasm_env.sh
  - source /etc/profile.d/wasm_env.sh

  # Clone and set up the cocos repository
  - git clone https://github.com/ultravioletrs/cocos.git /home/cocos_user/cocos

  # Download and Install the agent binary
  - wget -q https://github.com/ultravioletrs/cocos/releases/download/$COCOS_AGENT_VERSION/cocos-agent
  - install -D -m 0755 /home/cocos_user/cocos-agent /usr/local/bin/cocos-agent
  - mkdir -p /var/log/cocos
  - mkdir -p /etc/cocos

  # Install systemd service file
  - install -D -m 0644 /home/cocos_user/cocos/init/systemd/cocos-agent.service /etc/systemd/system/cocos-agent.service
  - install -D -m 0755 /home/cocos_user/cocos/init/systemd/agent_start_script.sh /etc/cocos/agent_start_script.sh

  # Reload systemd and enable the service
  - systemctl daemon-reload
  - systemctl enable cocos-agent.service
  - systemctl start cocos-agent.service

final_message: "Cocos agent setup complete and service started successfully."

EOF

# Create seed image for cloud-init
echo "Creating seed image..."
cloud-localds $SEED_IMAGE $USER_DATA $META_DATA

# Construct QEMU arguments from environment variables
construct_qemu_args() {
    args=()

    args+=("-name $VM_NAME")

    # Virtualization (Enable KVM)
    if [ "$ENABLE_KVM" == "true" ]; then
        args+=("-enable-kvm")
    fi

    # Machine, CPU, RAM
    if [ -n "$MACHINE" ]; then
        args+=("-machine" "$MACHINE")
    fi

    if [ -n "$CPU" ]; then
        args+=("-cpu" "$CPU")
    fi

    args+=("-smp" "$SMP_COUNT,maxcpus=$SMP_MAXCPUS")

    args+=("-m" "$MEMORY_SIZE,slots=$MEMORY_SLOTS,maxmem=$MAX_MEMORY")

    # OVMF (if applicable)
    if [ "$ENABLE_SEV_SNP" != "true" ]; then
        args+=("-drive" "if=$OVMF_CODE_IF,format=$OVMF_CODE_FORMAT,unit=$OVMF_CODE_UNIT,file=$OVMF_CODE,readonly=$OVMF_CODE_READONLY")
        args+=("-drive" "if=$OVMF_VARS_IF,format=$OVMF_VARS_FORMAT,unit=$OVMF_VARS_UNIT,file=$OVMF_VARS")
    fi

    # Network configuration
    args+=("-netdev" "user,id=$NET_DEV_ID,hostfwd=tcp::$NET_DEV_HOST_FWD_AGENT-:$NET_DEV_GUEST_FWD_AGENT")
    args+=("-device" "virtio-net-pci,disable-legacy=$VIRTIO_NET_PCI_DISABLE_LEGACY,iommu_platform=$VIRTIO_NET_PCI_IOMMU_PLATFORM,netdev=$NET_DEV_ID,addr=$VIRTIO_NET_PCI_ADDR,romfile=$VIRTIO_NET_PCI_ROMFILE")
    args+=("-device" "vhost-vsock-pci,id=$VSOCK_ID,guest-cid=$VSOCK_GUEST_CID")

    # SEV (if enabled)
    if [ "$ENABLE_SEV" == "true" ] || [ "$ENABLE_SEV_SNP" == "true" ]; then
        sev_type="sev-guest"
        kernel_hash=""
        host_data=""

        args+=("-machine" "confidential-guest-support=$SEV_ID,memory-backend=$MEM_ID")

        if [ "$ENABLE_SEV_SNP" == "true" ]; then
            args+=("-bios" "$OVMF_CODE_FILE")
            sev_type="sev-snp-guest"

            if [ -n "$SEV_HOST_DATA" ]; then
                host_data=",host-data=$SEV_HOST_DATA"
            fi
        fi

        if [ "$ENABLE_KERNEL_HASH" == "true" ]; then
            kernel_hash=",kernel-hashes=on"
        fi

        args+=("-object" "memory-backend-memfd,id=$MEM_ID,size=$MEMORY_SIZE,share=true,prealloc=false")
        args+=("-object" "$sev_type,id=$SEV_ID,cbitpos=$SEV_CBIT_POS,reduced-phys-bits=$SEV_REDUCED_PHYS_BITS$kernel_hash$host_data")
    fi

    # Disk image configuration
    args+=("-drive file=$SEED_IMAGE,media=cdrom")
    args+=("-drive file=$CUSTOM_IMAGE,if=none,id=disk0,format=qcow2")
    args+=("-device scsi-hd,drive=disk0")

    # Display options
    if [ "$NO_GRAPHIC" == "true" ]; then
        args+=("-nographic")
    fi

    args+=("-monitor" "$MONITOR")
    args+=("-no-reboot")
    args+=("-vnc :9")

    # Mount configuration
    if [ -n "$CERTS_MOUNT" ]; then
        args+=("-fsdev" "local,id=cert_fs,path=$CERTS_MOUNT,security_model=mapped")
        args+=("-device" "virtio-9p-pci,fsdev=cert_fs,mount_tag=certs_share")
    fi

    if [ -n "$ENV_MOUNT" ]; then
        args+=("-fsdev" "local,id=env_fs,path=$ENV_MOUNT,security_model=mapped")
        args+=("-device" "virtio-9p-pci,fsdev=env_fs,mount_tag=env_share")
    fi

    echo "${args[@]}"
}

qemu_args=$(construct_qemu_args)

echo "Running QEMU with the following arguments: $qemu_args"
$QEMU_BINARY $qemu_args
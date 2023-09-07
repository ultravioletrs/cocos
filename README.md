# Manager for Cocos AI

## Setup

```sh
git clone https://github.com/ultravioletrs/manager
cd manager
```

NB: all relative paths in this document are relative to `manager` repository directory.

### QEMU-KVM

[QEMU-KVM](https://www.qemu.org/) is a virtualization platform that allows you to run multiple operating systems on the same physical machine. It is a combination of two technologies: QEMU and KVM.

- QEMU is an emulator that can run a variety of operating systems, including Linux, Windows, and macOS.
- [KVM](https://wiki.qemu.org/Features/KVM) is a Linux kernel module that allows QEMU to run virtual machines.

To install QEMU-KVM on a Debian based machine, run

```sh
sudo apt update
sudo apt install qemu-kvm
```

Create `img` directory in `cmd/manager`. Create `tmp` directory in `cmd/manager`.

### Prepare focal-server-cloudimg-amd64.img

*focal-server-cloudimg-amd64* is a `qcow2` file with Ubuntu server preinstalled, ready to use with the QEMU virtual machine. We will put [Agent](https://github.com/ultravioletrs/agent) in the *focal-server-cloudimg-amd64*. In order to do that, we need to prepare the disk image.

#### Download focal-server-cloudimg-amd64.img and set up the root password

First, we will download *focal-server-cloudimg-amd64*. It is a `qcow2` file with Ubuntu server preinstalled, ready to use with the QEMU virtual machine.

```sh
cd cmd/manager
# Use this dir for focal-server-cloudimg-amd64.img and a test copy of firmware vars file.
mkdir img
# Use this dir for temporary firmware vars file and temporary disk image per virtual machine.
mkdir tmp

FOCAL=focal-server-cloudimg-amd64.img
wget -O img/$FOCAL https://cloud-images.ubuntu.com/focal/current/$FOCAL
# focal-server-cloudimg-amd64 comes without the root password
sudo apt-get install libguestfs-tools
PASSWORD=coolpass
sudo virt-customize -a img/$FOCAL --root-password password:$PASSWORD
```
#### Resize disk image, partition and filesystem

We need to resize the disk image:

```sh
qemu-img resize img/focal-server-cloudimg-amd64.img +1G
```

To resize `ext4` partition and filesystem on the `qcow2` disk image, start the virtual machine:

```sh
cd cmd/manager

sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
export MANAGER_QEMU_OVMF_CODE_FILE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd
export MANAGER_QEMU_OVMF_VARS_FILE=/usr/share/OVMF/OVMF_VARS.fd

# Exported env vars are visible in subshell: start_VM.sh relies on MANAGER_QEMU_OVMF_CODE_FILE and MANAGER_QEMU_OVMF_VARS_FILE
./start_VM.sh
```

Once the VM is booted up, we need to find out the partition with `ext4` filesystem, i.e. partition that contains the root file system:

```sh
mount | grep "on / type"
```

An example (for focal) of this output is:
```sh
# /dev/sda1 on / type ext4 (rw,relatime)
```
So, the partition that holds the root file system is `/dev/sda1`.

Check the current size of the partition:
```sh
df -h
# Output: /dev/sda1       2.0G  1.5G  520M  74% /
```

Run the `parted` command to increase the `ext4` partition size. We will resize the `/dev/sda` because this is the QEMU hard disk containing the `/dev/sda1` partition and the newly added free space.
```sh
parted /dev/sda
```
In the prompt of the parted command, execute `print free` to display the partition table and to see the free space.
```
print free
```
After executing the `print free` command, the parted command may issue a warning.
```
Warning: Not all of the space available to /dev/sda appears to be used, you can
fix the GPT to use all of the space (an extra 16777216 blocks) or continue with
the current setting?
Fix/Ignore?
```
Type `fix` here to use all of the available space.

An example of the output of the `print free` command should be something like this:
```
Model: QEMU QEMU HARDDISK (scsi)
Disk /dev/sda: 11.0GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags:

Number  Start   End     Size    File system  Name  Flags
        17.4kB  1049kB  1031kB  Free Space
14      1049kB  5243kB  4194kB                     bios_grub
15      5243kB  116MB   111MB   fat32              boot, esp
 1      116MB   2361MB  2245MB  ext4
        2361MB  3435MB  1074MB  Free Space
```

Partition 1 contains the root file system. To resize this partition type:
```
resizepart 1
```
The parted command will then ask you the following question:
```
Warning: Partition /dev/sda1 is being used. Are you sure you want to continue?
Yes/No?
```
Type `yes`.

Next, when asked about the root partition's new end number, enter the free space's end number. In our example, this is the number 11GB. Example:
```
End?  [2361MB]? 3435MB
```
Exit the parted command by typing `quit`.

The last step is to resize the filesystem of the root file system partition. To resize it, execute:
```sh
resize2fs /dev/sda1
```
Check the new size of the partition:
```sh
df -h
# Output: /dev/sda1       3.0G  1.5G  1.5G  50% /
```

#### Set up the network interface

We need to set up the network interface in order to be establish an HTTP and gRPC communication of the VM and the "external world".

We are still in the VM. If the VM is not started, start it with `./start_VM` and log in with root. Set up the network interface:

```sh
# Find out the virtual network interface and store it in NETWORK_INTERFACE env var.
NETWORK_INTERFACE=$(ip addr | awk '/^2: /{sub(/:/, "", $2); print $2}')
# To be sure, you can compare the output of the following command with the output of 'ip addr' command.
echo $NETWORK_INTERFACE

# Bring the specified network interface up.
ip link set dev $NETWORK_INTERFACE up
# Use dhclient to automatically obtain an IP address and configure the specified network interface.
dhclient $NETWORK_INTERFACE
```

#### Install Go language

We install go language in our VM in order to compile an `Agent` in the VM.

```sh
# Download the Go programming language distribution version 1.21.0 for Linux AMD64.
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz

# Remove any existing Go installation in /usr/local/go and extract the downloaded Go archive there.
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz

# Update the PATH environment variable to include the directory containing the Go binary.
export PATH=$PATH:/usr/local/go/bin

# Verify the installed Go version by running the "go version" command.
go version
# => # go version go1.21.0 linux/amd64
```

#### Build and run Agent

```sh
git clone https://github.com/ultravioletrs/agent
cd agent

# Build the 'agent' executable and save it to the 'build' directory.
go build -o build/agent cmd/agent/main.go

# Start the 'agent' executable in the background using '&' at the end.
./build/agent &

# List running processes and use 'grep' to filter for processes containing 'agent' in their names.
ps aux | grep agent
# This command helps verify that the 'agent' process is running.
# The output shows the process ID (PID), resource usage, and other information about the 'agent' process.
# For example: root 1035 0.7 0.7 1237968 14908 ttyS0 Sl 09:23 0:00 ./build/agent
```

Now we can quickly check for `Agent` from the inside of VM:

```sh
apt install net-tools

# Use netstat to list listening (LISTEN) TCP ports and filter for port 9031.
netstat -tuln | grep 9031
# Example output: tcp6 0 0 :::9031 :::* LISTEN

# Use netstat to list listening (LISTEN) TCP ports and filter for port 7002.
netstat -tuln | grep 7002
# Example output: tcp6 0 0 :::7002 :::* LISTEN
```

We can also check if the `Agent` HTTP `/run` endpoint is running:

```sh
GUEST_ADDR=localhost:9031
curl -sSi -X POST $GUEST_ADDR/run -H "Content-Type: application/json" -d @- <<EOF
{
  "name": "computation_24",
  "description": "this_computes_the_number_24",
  "datasets": [
    "red", "green", "blue", "black", "white", "grey"
  ],
  "algorithms": [
    "toHSV", "toRGB"
  ],
  "status": "executed",
  "owner": "Hector",
  "dataset_providers": [
    "Maxi", "Idea", "Lidl"
  ],
  "algorithm_providers": [
    "ETF", "FON", "FTN"
  ],
  "result_consumers": [
    "Intesa", "KomBank", "OTP"
  ],
  "ttl": 32,
  "metadata": {}
}
EOF
```

Output should look something like this:

```
EOF
HTTP/1.1 200 OK
Content-Type: application/json
Date: Tue, 05 Sep 2023 12:01:25 GMT
Content-Length: 493

{"computation":"{\"name\":\"computation_24\",\"description\":\"this_computes_the_number_24\",\"status\":\"executed\",\"owner\":\"Hector\",\"start_time\":\"0001-01-01T00:00:00Z\",\"end_time\":\"0001-01-01T00:00:00Z\",\"datasets\":[\"red\",\"green\",\"blue\",\"black\",\"white\",\"grey\"],\"algorithms\":[\"toHSV\",\"toRGB\"],\"dataset_providers\":[\"Maxi\",\"Idea\",\"Lidl\"],\"algorithm_providers\":[\"ETF\",\"FON\",\"FTN\"],\"result_consumers\":[\"Intesa\",\"KomBank\",\"OTP\"],\"ttl\":32}"}
```

We can also check if `Agent` is reachable from the host machine:

```sh
# Use netcat (nc) to test the connection to localhost on port 9301.
nc -zv localhost 9301
# Output:
# nc: connect to localhost (::1) port 9301 (tcp) failed: Connection refused
# Connection to localhost (127.0.0.1) 9301 port [tcp/*] succeeded!

# Use netcat (nc) to test the connection to localhost on port 7020.
nc -zv localhost 7020
# Output:
# nc: connect to localhost (::1) port 7020 (tcp) failed: Connection refused
# Connection to localhost (127.0.0.1) 7020 port [tcp/*] succeeded!
```

We can also test `Agent's` HTTP `/run` endpoint from the the host machine:

```sh
GUEST_ADDR=localhost:9301
curl -sSi -X POST $GUEST_ADDR/run -H "Content-Type: application/json" -d @- <<EOF
{
  "name": "computation_24",
  "description": "this_computes_the_number_24",
  "datasets": [
    "red", "green", "blue", "black", "white", "grey"
  ],
  "algorithms": [
    "toHSV", "toRGB"
  ],
  "status": "executed",
  "owner": "Hector",
  "dataset_providers": [
    "Maxi", "Idea", "Lidl"
  ],
  "algorithm_providers": [
    "ETF", "FON", "FTN"
  ],
  "result_consumers": [
    "Intesa", "KomBank", "OTP"
  ],
  "ttl": 32,
  "metadata": {}
}
EOF
```
You should get the similar output to the one above.

#### Set up agent as systemd daemon service

Before proceeding, you should ensure that your are logged in as root in the VM and that the `agent` process is not running.

Make directories for an agent executable and agent logs:

```sh
mkdir -p /cocos
mkdir -p /var/log/cocos
```

`cd` to the cloned `agent` repo:

```sh
# Build the 'agent' executable from the main.go source file and save it as 'build/agent'.
go build -o build/agent cmd/agent/main.go

# Copy the 'agent' executable to the '/cocos/agent' directory.
cp build/agent /cocos/agent

# Copy the 'cocos-agent.service' systemd unit file to the '/etc/systemd/system/' directory.
cp systemd/cocos-agent.service /etc/systemd/system/
```
Now we are ready to set up `agent` executable as a systemd daemon service:

```sh
# Enable the 'cocos-agent.service' systemd unit to start automatically on system boot.
systemctl enable cocos-agent.service

# Start the 'cocos-agent.service' systemd unit immediately.
systemctl start cocos-agent.service

# Check the status of the 'cocos-agent.service' systemd unit to verify if it's running and view its current status.
systemctl status cocos-agent.service
```
#### Conclusion

Now you are able to use `Manager` with `Agent`. Namely, `Manager` will create a VM with a separate OVMF variables file and with a separate copy of `focal-server-cloudimg-amd64.img` on manager `/run` request.

### OVMF

We need [Open Virtual Machine Firmware](https://wiki.ubuntu.com/UEFI/OVMF). OVMF is a port of Intel's tianocore firmware - an open source implementation of the Unified Extensible Firmware Interface (UEFI) - used by a qemu virtual machine. We need OVMF in order to run virtual machine with *focal-server-cloudimg-amd64*. When we install QEMU, we get two files that we need to start a VM: `OVMF_VARS.fd` and `OVMF_CODE.fd`. We will make a local copy of `OVMF_VARS.fd` since a VM will modify this file. On the other hand, `OVMF_CODE.fd` is only used as a reference, so we only record its path in an environment variable.

```sh
sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
MANAGER_QEMU_OVMF_CODE_FILE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd
MANAGER_QEMU_OVMF_VARS_FILE=/usr/share/OVMF/OVMF_VARS.fd
```

NB: we set environment variables that we will use in the shell process where we run `manager`.

## Run

We need to run `manager` in the directory containing `img` directory:

```sh
cd cmd/manager
MANAGER_LOG_LEVEL=info MANAGER_AGENT_GRPC_URL=localhost:7002 MANAGER_QEMU_USE_SUDO=false MANAGER_QEMU_ENABLE_SEV=false go run main.go
```

To enable [AMD SEV](https://www.amd.com/en/developer/sev.html) support, start manager like this 

```sh
cd cmd/manager
MANAGER_LOG_LEVEL=info MANAGER_AGENT_GRPC_URL=192.168.122.251:7002 MANAGER_QEMU_USE_SUDO=true MANAGER_QEMU_ENABLE_SEV=true MANAGER_QEMU_SEV_CBITPOS=51 go run main.go
```

Manager will start an HTTP server on port `9021`, and a gRPC server on port `7001`.

### Create QEMU virtual machine (VM)

To create an instance of VM and run a computation, run

```sh
curl -sSi -X POST \
  http://localhost:9021/run \
  -H "Content-Type: application/json" \
  -d '{
    "computation": [123, 34, 105, 100, 34, 58, 34, 48, 48, 97, 99, 102, 101, 57, 100, 45, 53, 101, 49, 98, 45, 52, 97, 101, 99, 45, 56, 50, 99, 48, 45, 56, 48, 97, 98, 56, 101, 100, 53, 101, 99, 48, 98, 34, 44, 34, 110, 97, 109, 101, 34, 58, 34, 77, 97, 99, 104, 105, 110, 101, 32, 68, 105, 97, 103, 110, 111, 115, 116, 105, 99, 115, 32, 65, 110, 97, 108, 121, 115, 105, 115, 34, 44, 34, 100, 101, 115, 99, 114, 105, 112, 116, 105, 111, 110, 34, 58, 34, 80, 101, 114, 102, 111, 114, 109, 105, 110, 103, 32, 100, 105, 97, 103, 110, 111, 115, 116, 105, 99, 115, 32, 97, 110, 97, 108, 121, 115, 105, 115, 32, 111, 110, 32, 109, 97, 99, 104, 105, 110, 101, 32, 100, 97, 116, 97, 34, 44, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 101, 120, 101, 99, 117, 116, 97, 98, 108, 101, 34, 44, 34, 111, 119, 110, 101, 114, 34, 58, 34, 77, 97, 99, 104, 105, 110, 101, 32, 73, 110, 100, 117, 115, 116, 114, 105, 101, 115, 32, 73, 110, 99, 46, 34, 44, 34, 115, 116, 97, 114, 116, 95, 116, 105, 109, 101, 34, 58, 34, 50, 48, 50, 51, 45, 48, 56, 45, 50, 49, 84, 49, 50, 58, 48, 50, 58, 51, 49, 46, 48, 48, 55, 53, 48, 53, 90, 34, 44, 34, 101, 110, 100, 95, 116, 105, 109, 101, 34, 58, 34, 48, 48, 48, 49, 45, 48, 49, 45, 48, 49, 84, 48, 48, 58, 48, 48, 58, 48, 48, 90, 34, 44, 34, 100, 97, 116, 97, 115, 101, 116, 115, 34, 58, 91, 34, 83, 101, 110, 115, 111, 114, 32, 68, 97, 116, 97, 32, 76, 111, 103, 115, 34, 44, 34, 77, 97, 99, 104, 105, 110, 101, 32, 72, 101, 97, 108, 116, 104, 32, 82, 101, 99, 111, 114, 100, 115, 34, 44, 34, 77, 97, 105, 110, 116, 101, 110, 97, 110, 99, 101, 32, 82, 101, 112, 111, 114, 116, 115, 34, 93, 44, 34, 97, 108, 103, 111, 114, 105, 116, 104, 109, 115, 34, 58, 91, 34, 83, 117, 112, 112, 111, 114, 116, 32, 86, 101, 99, 116, 111, 114, 32, 77, 97, 99, 104, 105, 110, 101, 115, 34, 44, 34, 75, 45, 78, 101, 97, 114, 101, 115, 116, 32, 78, 101, 105, 103, 104, 98, 111, 114, 115, 34, 44, 34, 72, 105, 101, 114, 97, 114, 99, 104, 105, 99, 97, 108, 32, 67, 108, 117, 115, 116, 101, 114, 105, 110, 103, 34, 93, 44, 34, 100, 97, 116, 97, 115, 101, 116, 95, 112, 114, 111, 118, 105, 100, 101, 114, 115, 34, 58, 91, 34, 83, 101, 110, 115, 111, 114, 84, 101, 99, 104, 32, 83, 111, 108, 117, 116, 105, 111, 110, 115, 34, 44, 34, 77, 97, 99, 104, 105, 110, 101, 114, 121, 32, 68, 97, 116, 97, 32, 83, 121, 115, 116, 101, 109, 115, 34, 93, 44, 34, 97, 108, 103, 111, 114, 105, 116, 104, 109, 95, 112, 114, 111, 118, 105, 100, 101, 114, 115, 34, 58, 91, 34, 65, 108, 103, 111, 65, 73, 32, 82, 101, 115, 101, 97, 114, 99, 104, 32, 76, 97, 98, 115, 34, 44, 34, 84, 101, 99, 104, 66, 111, 116, 115, 32, 73, 110, 110, 111, 118, 97, 116, 105, 111, 110, 115, 34, 93, 44, 34, 114, 101, 115, 117, 108, 116, 95, 99, 111, 110, 115, 117, 109, 101, 114, 115, 34, 58, 91, 34, 77, 97, 99, 104, 105, 110, 101, 32, 77, 97, 105, 110, 116, 101, 110, 97, 110, 99, 101, 32, 68, 101, 112, 97, 114, 116, 109, 101, 110, 116, 34, 44, 34, 80, 114, 101, 100, 105, 99, 116, 105, 118, 101, 32, 65, 110, 97, 108, 121, 116, 105, 99, 115, 32, 84, 101, 97, 109, 34, 44, 34, 73, 110, 100, 117, 115, 116, 114, 105, 97, 108, 32, 65, 117, 116, 111, 109, 97, 116, 105, 111, 110, 32, 68, 105, 118, 105, 115, 105, 111, 110, 34, 93, 44, 34, 116, 116, 108, 34, 58, 52, 56, 44, 34, 109, 101, 116, 97, 100, 97, 116, 97, 34, 58, 123, 34, 97, 110, 97, 108, 121, 115, 105, 115, 95, 112, 117, 114, 112, 111, 115, 101, 34, 58, 34, 79, 112, 116, 105, 109, 105, 122, 101, 32, 109, 97, 99, 104, 105, 110, 101, 32, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 32, 97, 110, 100, 32, 112, 114, 101, 118, 101, 110, 116, 32, 100, 111, 119, 110, 116, 105, 109, 101, 34, 44, 34, 100, 97, 116, 97, 95, 102, 114, 101, 113, 117, 101, 110, 99, 121, 34, 58, 34, 72, 111, 117, 114, 108, 121, 34, 44, 34, 105, 110, 100, 117, 115, 116, 114, 121, 34, 58, 34, 77, 97, 110, 117, 102, 97, 99, 116, 117, 114, 105, 110, 103, 34, 44, 34, 109, 97, 99, 104, 105, 110, 101, 95, 116, 121, 112, 101, 34, 58, 34, 65, 117, 116, 111, 109, 97, 116, 101, 100, 32, 65, 115, 115, 101, 109, 98, 108, 121, 32, 76, 105, 110, 101, 34, 125, 125]
}'

```

You should be able to create multiple instances by reruning the command.    

### Verifying VM launch

NB: To verify that the manager successfully launched the VM, you need to open two terminals on the same machine. In one terminal, you need to launch `go run main.go` (with the environment variables of choice) and in the other, you can run the verification commands.

To verify that the manager launched the VM successfully, run the following command:

```sh
ps aux | grep qemu-system-x86_64
```

You should get something similar to this
```
darko     324763 95.3  6.0 6398136 981044 ?      Sl   16:17   0:15 /usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty
```

If you run a command as `sudo`, you should get the output similar to this one

```
root       37982  0.0  0.0   9444  4572 pts/0    S+   16:18   0:00 sudo /usr/local/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0 -nographic -monitor pty
root       37989  122 13.1 5345816 4252312 pts/0 Sl+  16:19   0:04 /usr/local/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0 -nographic -monitor pty
```

The two processes are due to the fact that we run the command `/usr/bin/qemu-system-x86_64` as `sudo`, so there is one process for `sudo` command and the other for `/usr/bin/qemu-system-x86_64`.

### Troubleshooting

If the `ps aux | grep qemu-system-x86_64` give you something like this

```
darko      13913  0.0  0.0      0     0 pts/2    Z+   20:17   0:00 [qemu-system-x86] <defunct>
```

means that the a QEMU virtual machine that is currently defunct, meaning that it is no longer running. More precisely, the defunct process in the output is also known as a ["zombie" process](https://en.wikipedia.org/wiki/Zombie_process).

You can troubleshoot the VM launch procedure by running directly `qemu-system-x86_64` command. When you run `manager` with `MANAGER_LOG_LEVEL=info` env var set, it prints out the entire command used to launch a VM. The relevant part of the log might look like this

```
{"level":"info","message":"/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty","ts":"2023-08-14T18:29:19.2653908Z"}
```

You can run the command - the value of the `"message"` key - directly in the terminal:

```sh
/usr/bin/qemu-system-x86_64 -enable-kvm -machine q35 -cpu EPYC -smp 4,maxcpus=64 -m 4096M,slots=5,maxmem=30G -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,unit=1,file=img/OVMF_VARS.fd -device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -drive file=img/focal-server-cloudimg-amd64.img,if=none,id=disk0,format=qcow2 -device scsi-hd,drive=disk0 -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= -nographic -monitor pty
```

and look for the possible problems. This problems can usually be solved by using the adequate env var assignments. Look in the `manager/qemu/config.go` file to see the recognized env vars. Don't forget to prepend `MANAGER_QEMU_` to the name of the env vars.

#### Kill `qemu-system-x86_64` processes

To kill any leftover `qemu-system-x86_64` processes, use

```sh
pkill -f qemu-system-x86_64
```

The pkill command is used to kill processes by name or by pattern. The -f flag to specify that we want to kill processes that match the pattern `qemu-system-x86_64`. It sends the SIGKILL signal to all processes that are running `qemu-system-x86_64`.

If this does not work, i.e. if `ps aux | grep qemu-system-x86_64` still outputs `qemu-system-x86_64` related process(es), you can kill the unwanted process with `kill -9 <PID>`, which also sends a SIGKILL signal to the process.

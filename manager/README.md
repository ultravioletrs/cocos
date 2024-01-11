# Manager

Manager service provides a barebones HTTP and gRPC API and Service interface implementation for the development of the manager service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable                      | Description                                              | Default                           |
| ----------------------------- | -------------------------------------------------------- | --------------------------------- |
| MANAGER_LOG_LEVEL             | Log level for manager service (debug, info, warn, error) | info                              |
| MANAGER_HTTP_HOST             | Manager service HTTP host                                |                                   |
| MANAGER_HTTP_PORT             | Manager service HTTP port                                | 9021                              |
| MANAGER_HTTP_SERVER_CERT      | Path to server certificate in pem format                 |                                   |
| MANAGER_HTTP_SERVER_KEY       | Path to server key in pem format                         |                                   |
| MANAGER_GRPC_HOST             | Manager service gRPC host                                |                                   |
| MANAGER_GRPC_PORT             | Manager service gRPC port                                | 7001                              |
| MANAGER_GRPC_SERVER_CERT      | Path to server certificate in pem format                 |                                   |
| MANAGER_GRPC_SERVER_KEY       | Path to server key in pem format                         |                                   |
| COCOS_JAEGER_URL              | Jaeger server URL                                        | http://localhost:14268/api/traces |
| MANAGER_INSTANCE_ID           | Manager service instance ID                              |                                   |
| COCOS_NOTIFICATION_SERVER_URL | Server to receive notification events from agent.        | http:/localhost:9000              |
| MANAGER_HOST_IP               | Mnagaer host IP address                                  | localhost                         |

## Setup

```sh
git clone https://github.com/ultravioletrs/cocos
cd cocos
```

NB: all relative paths in this document are relative to `cocos` repository directory.

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

### Prepare Cocos HAL

Cocos HAL for Linux is framework for building custom in-enclave Linux distribution. Use the instructions in [Readme](https://github.com/ultravioletrs/cocos/blob/main/hal/linux/README.md).
Once the image is built copy the kernel and rootfs image to `cmd/manager/img` from `buildroot/output/images/bzImage` and `buildroot/output/images/rootfs.cpio.gz` respectively.

#### Test VM creation

```sh
cd cmd/manager

sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
OVMF_CODE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS.fd

KERNEL="img/bzImage"
INITRD="img/rootfs.cpio.gz"

qemu-system-x86_64 \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35 \
    -smp 4 \
    -m 2048M,slots=5,maxmem=10240M \
    -no-reboot \
    -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
    -netdev user,id=vmnic,hostfwd=tcp::2222-:22,hostfwd=tcp::9301-:9031,hostfwd=tcp::7020-:7002 \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
    -kernel $KERNEL \
    -append "earlyprintk=serial console=ttyS0 computation={\"id\":\"c0d15c5e-e37d-4426-b3b7-b432c966fb09\",\"name\":\"Sample_Computation\",\"description\":\"A_sample_computation\",\"datasets\":[{\"provider\":\"Provider1\",\"id\":\"Dataset1\"},{\"provider\":\"Provider2\",\"id\":\"Dataset2\"}],\"algorithms\":[{\"provider\":\"AlgorithmProvider1\",\"id\":\"Algorithm1\"}],\"result_consumers\":[\"Consumer1\"], \"timeout\":\"10m\"}" \
    -initrd $INITRD \
    -nographic \
    -monitor pty \
    -monitor unix:monitor,server,nowait
```
Once the VM is booted press enter and on the login use username `root`.

#### Build and run Agent
```sh
# Start the 'agent' executable in the background using '&' at the end.
cocos-agent &

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
  "id": "some_id",
  "name": "computation_24",
  "description": "this_computes_the_number_24",
  "datasets":[{"provider":"Provider1","id":"Dataset1"},{"provider":"Provider2","id":"Dataset2"}],
  "algorithms":[{"provider":"AlgorithmProvider1","id":"Algorithm1"}],
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
  "start_time":"2023-11-03T12:03:21.705171284+03:00",
  "end_time":"2023-11-03T13:03:21.705171532+03:00",
  "metadata": {},
  "timeout": "20m"
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

{"id": "7778cd80be286dba0d748c6f3d88c9e82bb8e5cb00dea05d3b63cab2ccfbe89a"}
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
  "id": "some_id",
  "name": "computation_24",
  "description": "this_computes_the_number_24",
  "datasets":[{"provider":"Provider1","id":"Dataset1"},{"provider":"Provider2","id":"Dataset2"}],
  "algorithms":[{"provider":"AlgorithmProvider1","id":"Algorithm1"}],
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
  "start_time":"2023-11-03T12:03:21.705171284+03:00",
  "end_time":"2023-11-03T13:03:21.705171532+03:00",
  "metadata": {},
  "timeout": "20m"
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
cp init/systemd/cocos-agent.service /etc/systemd/system/
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


## Deployment

### Standalone

To start the service outside of the container, execute the following shell script:

```bash
# download the latest version of the service
go get github.com/ultravioletrs/cocos

cd $GOPATH/src/github.com/ultravioletrs/cocos

# compile the manager
make manager

# copy binary to bin
make install

# set the environment variables and run the service
MANAGER_LOG_LEVEL=debug \
MANAGER_AGENT_GRPC_URL=localhost:7002 \
MANAGER_QEMU_USE_SUDO=false \
MANAGER_QEMU_ENABLE_SEV=false \
./build/cocos-manager
```

To enable [AMD SEV](https://www.amd.com/en/developer/sev.html) support, start manager like this 

```sh
MANAGER_LOG_LEVEL=debug \
MANAGER_AGENT_GRPC_URL=192.168.122.251:7002 \
MANAGER_QEMU_USE_SUDO=true \
MANAGER_QEMU_ENABLE_SEV=true \
MANAGER_QEMU_SEV_CBITPOS=51 \
./build/cocos-manager
```


### Docker
```bash
go get github.com/ultravioletrs/cocos

cd $GOPATH/src/github.com/ultravioletrs/cocos

# compile the manager
make manager

# create manager docker image
make docker_dev_manager

# start docker composition
make run
```

### Create QEMU virtual machine (VM)

To create an instance of VM and run a computation, run

```sh
curl -sSi -X POST \
  http://localhost:9021/run \
  -H "Content-Type: application/json" \
  -d '{
    "computation": [123, 34, 105, 100, 34, 58, 34, 49, 50, 51, 34, 44, 34, 110, 97, 109, 101, 34, 58, 34, 83, 97, 109, 112, 108, 101, 32, 67, 111, 109, 112, 117, 116, 97, 116, 105, 111, 110, 34, 44, 34, 100, 101, 115, 99, 114, 105, 112, 116, 105, 111, 110, 34, 58, 34, 65, 32, 115, 97, 109, 112, 108, 101, 32, 99, 111, 109, 112, 117, 116, 97, 116, 105, 111, 110, 34, 44, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 80, 114, 111, 99, 101, 115, 115, 105, 110, 103, 34, 44, 34, 111, 119, 110, 101, 114, 34, 58, 34, 74, 111, 104, 110, 32, 68, 111, 101, 34, 44, 34, 115, 116, 97, 114, 116, 95, 116, 105, 109, 101, 34, 58, 34, 50, 48, 50, 51, 45, 49, 49, 45, 48, 51, 84, 49, 50, 58, 48, 51, 58, 50, 49, 46, 55, 48, 53, 49, 55, 49, 50, 56, 52, 43, 48, 51, 58, 48, 48, 34, 44, 34, 101, 110, 100, 95, 116, 105, 109, 101, 34, 58, 34, 50, 48, 50, 51, 45, 49, 49, 45, 48, 51, 84, 49, 51, 58, 48, 51, 58, 50, 49, 46, 55, 48, 53, 49, 55, 49, 53, 51, 50, 43, 48, 51, 58, 48, 48, 34, 44, 34, 100, 97, 116, 97, 115, 101, 116, 115, 34, 58, 91, 123, 34, 112, 114, 111, 118, 105, 100, 101, 114, 34, 58, 34, 80, 114, 111, 118, 105, 100, 101, 114, 49, 34, 44, 34, 105, 100, 34, 58, 34, 68, 97, 116, 97, 115, 101, 116, 49, 34, 125, 44, 123, 34, 112, 114, 111, 118, 105, 100, 101, 114, 34, 58, 34, 80, 114, 111, 118, 105, 100, 101, 114, 50, 34, 44, 34, 105, 100, 34, 58, 34, 68, 97, 116, 97, 115, 101, 116, 50, 34, 125, 93, 44, 34, 97, 108, 103, 111, 114, 105, 116, 104, 109, 115, 34, 58, 91, 123, 34, 112, 114, 111, 118, 105, 100, 101, 114, 34, 58, 34, 65, 108, 103, 111, 114, 105, 116, 104, 109, 80, 114, 111, 118, 105, 100, 101, 114, 49, 34, 44, 34, 105, 100, 34, 58, 34, 65, 108, 103, 111, 114, 105, 116, 104, 109, 49, 34, 125, 93, 44, 34, 114, 101, 115, 117, 108, 116, 95, 99, 111, 110, 115, 117, 109, 101, 114, 115, 34, 58, 91, 34, 67, 111, 110, 115, 117, 109, 101, 114, 49, 34, 44, 34, 67, 111, 110, 115, 117, 109, 101, 114, 50, 34, 93, 44, 34, 116, 116, 108, 34, 58, 51, 54, 48, 48, 44, 34, 109, 101, 116, 97, 100, 97, 116, 97, 34, 58, 123, 34, 107, 101, 121, 49, 34, 58, 34, 118, 97, 108, 117, 101, 49, 34, 44, 34, 107, 101, 121, 50, 34, 58, 52, 50, 125, 44, 34, 116, 105, 109, 101, 111, 117, 116, 34, 58, 34, 51, 109, 48, 115, 34, 125]
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

## Usage

For more information about service capabilities and its usage, please check out the [README documentation](../README.md).

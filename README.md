# Manager for Cocos AI

## Setup

### Libvirt

```sh
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system
```

After installing `libvirt-daemon-system`, the user that will be used to manage virtual machines needs to be added to the `libvirt` group. This is done automatically for members of the sudo group, otherwise

```sh
sudo adduser $USER libvirt
```

### iso & img

Create `img` directory in `cmd/manager`. Create `iso` directory in `cmd/manager`. Save [alpine-standard-3.17.2-x86_64.iso](https://dl-cdn.alpinelinux.org/alpine/v3.17/releases/x86_64/alpine-standard-3.17.2-x86_64.iso) in `cmd/manager/iso` directory.

```sh
cd cmd/manager/iso
wget https://dl-cdn.alpinelinux.org/alpine/v3.17/releases/x86_64/alpine-standard-3.17.2-x86_64.iso
```

## Run

`cd` to `cmd/manager` and run
```sh
CC_MANAGER_LOG_LEVEL=info go run main.go
```

This will start an HTTP server on port `9021`, a gRPC server on port `7001` and will establish a connection to [libvirtd](https://libvirt.org/manpages/libvirtd.html).

## Domain

To create a `libvirt` domain - basically a QEMU instance or a virtual machine (VM) - run

```sh
curl -i -X POST -H "Content-Type: application/json" localhost:9021/domain -d '{"pool":"<path/to/pool.xml>", "volume":"<path/to/vol.xml", "domain":"<path/to/dom.xml"}'
```

If you have already created a domain, you can remove it with

```sh
virsh undefine QEmu-alpine-standard-x86_64; \
virsh shutdown QEmu-alpine-standard-x86_64; \
virsh destroy QEmu-alpine-standard-x86_64; \
rm -rf ~/go/src/github.com/ultravioletrs/manager/cmd/manager/img/boot.img; \
virsh pool-destroy --pool virtimages
```

This will destroy the domain together with volumes and a pool where the volume was logically stored.

## Computation

To run a computation, run

```sh
curl -X POST \
  http://localhost:9021/run \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "my-run",
        "description": "this is a test run",
        "owner": "John Doe",
        "datasets": ["dataset1", "dataset2"],
        "algorithms": ["algorithm1", "algorithm2"],
        "dataset_providers": ["provider1", "provider2"],
        "algorithm_providers": ["provider3", "provider4"],
        "result_consumers": ["consumer1", "consumer2"],
        "ttl": 3600
    }'
```

## Agent

```sh
sudo apt install guestfish

QCOW2_PATH=~/go/src/github.com/ultravioletrs/manager/cmd/manager/img/boot.img
HOST_AGENT_PATH=~/Development/go-playground/hello_world/main
GUEST_AGENT_PATH=/root/agent
sudo virt-copy-in -a $QCOW2_PATH $HOST_AGENT_PATH $GUEST_AGENT_PATH
```
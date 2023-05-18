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

### CD iso & hard drive img for virtual machine (VM)

Create `img` directory in `cmd/manager`. Create `iso` directory in `cmd/manager`. Save [alpine-standard-3.17.2-x86_64.iso](https://dl-cdn.alpinelinux.org/alpine/v3.17/releases/x86_64/alpine-standard-3.17.2-x86_64.iso) in `cmd/manager/iso` directory:

```sh
cd cmd/manager/iso
wget https://dl-cdn.alpinelinux.org/alpine/v3.17/releases/x86_64/alpine-standard-3.17.2-x86_64.iso
```

## Run

We need to run `manager` in the directory where `img`, `iso` and `xml` directories are. `cd` to `cmd/manager` and run

```sh
CC_MANAGER_LOG_LEVEL=info go run main.go
```

This will start an HTTP server on port `9021`, a gRPC server on port `7001` and will establish a connection to [libvirtd](https://libvirt.org/manpages/libvirtd.html).

## Domain 

### Domain creation & destruction
To create a `libvirt` domain - basically a QEMU instance or a virtual machine (VM) - run

```sh
curl -i -X POST -H "Content-Type: application/json" localhost:9021/domain -d '{"pool":"<path/to/pool.xml>", "volume":"<path/to/vol.xml>", "domain":"<path/to/dom.xml>"}'
```

If you have already created a domain, you can remove it with

```sh
virsh undefine QEmu-alpine-standard-x86_64; \
virsh shutdown QEmu-alpine-standard-x86_64; \
virsh destroy QEmu-alpine-standard-x86_64; \
rm -rf ~/go/src/github.com/ultravioletrs/manager/cmd/manager/img/boot.img; \
virsh pool-destroy --pool virtimages
```

This will destroy the domain together with volumes and a pool where the volume was logically stored. It is not necessary to remove a domain, since the manager will reuse the existing VM.

### Domain management

```sh
sudo apt-get install virt-manager
```

Start virtual manager. Open `QEmu-alpine-standard-x86_64` virtual machine. Log in as root, no password needed, and follow instructions to install and set up Alpine Linux on virtual drive.

Once you have installed and set up Alpine Linux, follow the instructions in `Agent` [README.md](https://github.com/ultravioletrs/agent) in order to see how to set up `Cocos.ai` `Agent` in the virtual machine.

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

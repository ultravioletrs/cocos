# Manager for Cocos AI

## Setup

Create `img` directory in `cmd/manager`. Create `iso` directory in `cmd/manager`. Save [alpine-standard-3.17.2-x86_64.iso](https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-standard-3.17.2-x86_64.iso) in `cmd/manager/iso` directory.

## Run

`cd` to `cmd/manager` and run
```sh
go run main.go
```

This will start an HTTP server on port `9021`, a gRPC server on port `7001` and will establish a connection to [libvirtd](https://libvirt.org/manpages/libvirtd.html).

## Domain

To create a `libvirt` domain - basically a QEMU instance or a virtual machine (VM) - run

```sh
curl -i -X POST -H "Content-Type: application/json" localhost:9021/domain -d '{"pool":"/home/darko/go/src/github.com/ultravioletrs/manager/cmd/manager/xml/pool.xml", "volume":"/home/darko/go/src/github.com/ultravioletrs/manager/cmd/manager/xml/vol.xml", "domain":"/home/darko/go/src/github.com/ultravioletrs/manager/cmd/manager/xml/dom.xml"}'
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


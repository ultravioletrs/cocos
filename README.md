# Agent

## Build Agent

To create a stand-alone `agent` executable, on the host machine, in the root of the `agent` repository run

```sh
go build -o ./bin/agent -ldflags="-linkmode=external -extldflags=-static -s -w" cmd/agent/main.go
```

## Copy files to virtual drive

Log in the VM and create `/cocos` directory. Shut down `QEmu-alpine-standard-x86_64` virtual machine.

On the host machine install [libguestfs-tools](https://libguestfs.org/). `libguestfs-tools` is "a set of tools for accessing and modifying virtual machine (VM) disk images".

```sh
sudo apt-get install libguestfs-tools
```

Set path to the VM disk image:

```sh
QCOW2_PATH=~/go/src/github.com/ultravioletrs/manager/cmd/manager/img/boot.img
```

Set path to the `agent` executable and its VM image path, and copy `agent` to the VM disk image.

```sh
HOST_AGENT_BIN_PATH=~/go/src/github.com/ultravioletrs/agent/bin/agent; \
GUEST_AGENT_BIN_PATH=/cocos/; \
sudo virt-copy-in -a $QCOW2_PATH $HOST_AGENT_BIN_PATH $GUEST_AGENT_BIN_PATH
```

Copy [OpenRC](https://wiki.alpinelinux.org/wiki/OpenRC) init script to the VM disk image:

```sh
HOST_AGENT_SCRIPT_PATH=~/go/src/github.com/ultravioletrs/agent/alpine/agent; \
GUEST_AGENT_SCRIPT_PATH=/etc/init.d/; \
sudo virt-copy-in -a $QCOW2_PATH $HOST_AGENT_SCRIPT_PATH $GUEST_AGENT_SCRIPT_PATH
```

OpenRC init script is used to start `agent` executable as a system service (daemon) on the Alpine Linux boot.

### OpenRC

Once the OpenRC `agent` script is copied into the `/etc/init.d/`, i.e. on the guest system, log into the guest system and run

```sh
rc-update add agent default
```

and reboot.

To see if the `agent` service (or deamon) is running, inside Alpine linux run

```sh
ps aux | grep agent
```

To see if the ports are correctly configured, inside Alpine linux, i.e. _guest machine_, run

```sh
netstat -tuln | grep 9031
netstat -tuln | grep 7002
```

In the _host machine_, you can check if the ports of the guest machine are open and reachable from the host machine with

```sh
nc -zv 192.168.122.251 9031
nc -zv 192.168.122.251 7002
```

NB: to find out `192.168.122.251`, i.e. the concrete address of the guest machine, you need to

```sh
ip addr show eth0
```

in the host machine and

```sh
ip addr show virbr0
```

on the host machine. In both cases, you will get something like inet `192.168.122.x/24`, where `192.168.122` stands for the network part of the machine's virtual network interface address.

### cURL

To check if the `agent` deamon is responding to the requests, run on the host

```sh
GUEST_ADDR=192.168.122.251:9031
```

To run a computation

```sh
curl -sSi -X POST ${GUEST_ADDR}/run -H "Content-Type: application/json" -d @- <<EOF
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

### Interaction with Cocos microservice

If the [cocos](https://github.com/ultravioletrs/cocos) is running, you can use `cocos` to send computation request to the `agent` via gRPC.

NB: you need to run `cocos` `computations` microservice with `COCOS_COMPUTATIONS_AGENT_GRPC_URL=192.168.122.251:7002`, i.e. with the correct address and port of the agent gRPC client running in the VM.

Create computation with

```sh
curl -sSi -X POST http://localhost:9000/computations -H "Content-Type: application/json" -d @- <<EOF
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

You will get as a response

```
HTTP/1.1 201 Created
Content-Type: application/json
Location: /computations/9429a679-173e-4c2d-856f-74c92e08ab76
Date: Fri, 19 May 2023 12:30:56 GMT
Content-Length: 0
```

Note the computation id in the `Location` header. Set the environmnet variable `COMPUTATION_ID=9429a679-173e-4c2d-856f-74c92e08ab76` and run it with

```sh
curl -sSi -X POST http://localhost:9000/computations/$COMPUTATION_ID/run
```

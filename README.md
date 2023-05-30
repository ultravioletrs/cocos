# Agent

## Build Agent
On the host machine in the root of `agent` repository run

```sh
go build -o ./bin/cocos-agent -ldflags="-linkmode=external -extldflags=-static -s -w" cmd/agent/main.go
```

## Copy files to virtual drive

Shut down `QEmu-alpine-standard-x86_64` virtual machine. 

On the host machine

```sh
sudo apt-get install libguestfs-tools

QCOW2_PATH=~/go/src/github.com/ultravioletrs/manager/cmd/manager/img/boot.img

HOST_AGENT_BIN_PATH=~/go/src/github.com/ultravioletrs/agent/bin/cocos-agent; \
GUEST_AGENT_BIN_PATH=/root/; \
sudo virt-copy-in -a $QCOW2_PATH $HOST_AGENT_BIN_PATH $GUEST_AGENT_BIN_PATH

HOST_AGENT_SCRIPT_PATH=~/go/src/github.com/ultravioletrs/agent/alpine/agent; \
GUEST_AGENT_SCRIPT_PATH=/etc/init.d/; \
sudo virt-copy-in -a $QCOW2_PATH $HOST_AGENT_SCRIPT_PATH $GUEST_AGENT_SCRIPT_PATH
```

### OpenRC

OpenRC is an Alpine's service manager.

Once the `agent` script is copied in `/etc/init.d/` on the guest system, log into the guest system and run

```sh
rc-update add agent default
```

and reboot.

To see if the service is running, inside Alpine linux run

```sh
ps aux | grep cocos
```

To see if the ports are correctly configured, inside Alpine linux run

```sh
netstat -tuln | grep 9031
netstat -tuln | grep 7002
```

### cURL

To check if the `cocos-agent` deamon is running in the virtual machine Alpine Linux, run on the host

```sh
GUEST_ADDR=192.168.122.251:9031
```

```sh
curl -i -X POST -H "Content-Type: application/json" ${GUEST_ADDR}/agent -d '{"secret":"secret"}'
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
# Agent

## Build Agent
On the host machine in the root of `agent` repository

```sh
go build -o ./bin/cocos-agent -ldflags="-linkmode=external -extldflags=-static -s -w" cmd/agent/main.go
```

## Copy files to virtual drive

Shut down `QEmu-alpine-standard-x86_64` virtual machine. 

On the host machine

```sh
sudo apt-get install libguestfs-tools

QCOW2_PATH=~/go/src/github.com/ultravioletrs/manager/cmd/manager/img/boot.img

HOST_AGENT_PATH=~/go/src/github.com/ultravioletrs/agent/bin/cocos-agent; \
GUEST_AGENT_PATH=/root/; \
sudo virt-copy-in -a $QCOW2_PATH $HOST_AGENT_PATH $GUEST_AGENT_PATH

HOST_AGENT_PATH=~/go/src/github.com/ultravioletrs/agent/alpine/agent; \
GUEST_AGENT_PATH=/etc/init.d/; \
sudo virt-copy-in -a $QCOW2_PATH $HOST_AGENT_PATH $GUEST_AGENT_PATH
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

To see if the ports are correctly configured, , inside Alpine linux run

```sh
netstat -tuln | grep 9031
netstat -tuln | grep 7002
```

### cURL

To check if the `cocos-agent` deamon is running in the virtual machine Alpine linux

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
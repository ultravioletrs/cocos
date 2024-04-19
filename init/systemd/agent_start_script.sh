#!/bin/sh

ETH_IFACE=enp0s2
AGENT_GRPC_HOST=$(ip -4 addr show $ETH_IFACE | grep inet | awk '{print $2}' | cut -d/ -f1)

export AGENT_GRPC_HOST

exec /bin/cocos-agent

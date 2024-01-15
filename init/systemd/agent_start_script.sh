#!/bin/sh

ip link set dev enp0s2 up
dhclient enp0s2
AGENT_GRPC_HOST=$(ip -4 addr show enp0s2 | grep inet | awk '{print $2}' | cut -d/ -f1)

export AGENT_GRPC_HOST

exec /bin/cocos-agent

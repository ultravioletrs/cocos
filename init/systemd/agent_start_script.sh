#!/bin/sh

dhclient eth0
AGENT_GRPC_HOST=$(ip -4 addr show eth0 | grep inet | awk '{print $2}' | cut -d/ -f1)

export AGENT_GRPC_HOST

exec /bin/cocos-agent

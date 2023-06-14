#!/bin/bash
ip link set dev enp0s2 up
dhclient enp0s2

# export AGENT_GRPC_ADDR=$(ifconfig enp0s2 | grep 'inet ' | awk '{print $2}'):7002
export AGENT_GRPC_ADDR=10.0.2.15:7002
export AGENT_LOG_LEVEL=info

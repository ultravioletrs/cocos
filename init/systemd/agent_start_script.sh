#!/bin/sh

# The variable ETH_IFACE contains the name the systemd gave to the network interface. 
# The systemd configures the name based on the QEMU parameters. 
# The parts of the name enp0s2 mean:
#   et - ethernet card. It means this is the ethernet interface.
#   p - means that the interface is connected to a PCI bus.
#   0 - the interface is connected to bus 0.
#   s2 -the interface is connected to slot 2.
#
# The variable should be configured through QEMU parameters for the network device,
# addr (for slot number), and bus (for bus number).
ETH_IFACE=enp0s2

ip link set dev $ETH_IFACE up
dhclient $ETH_IFACE
AGENT_GRPC_HOST=$(ip -4 addr show $ETH_IFACE | grep inet | awk '{print $2}' | cut -d/ -f1)

export AGENT_GRPC_HOST

exec /bin/cocos-agent

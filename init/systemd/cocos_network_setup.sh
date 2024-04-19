#!/bin/sh

# The variable ETH_IFACE contains the name the systemd gave to the network interface. 
# The systemd configures the name based on the QEMU parameters. 
# The parts of the name enp0s2 mean:
#  en - ethernet interface.
#  p  - means that the interface is connected to a PCI bus.
#  0  - the interface is connected to bus 0.
#  s2 - the interface is connected to slot 2.

# The variable ETH_IFACE value must match the name configured through QEMU parameters for the network device. 
# The bus number and slot number are configured through QEMU device parameters, parameters
# addr (for slot number), and bus (for bus number).
ETH_IFACE=enp0s2

dhclient $ETH_IFACE

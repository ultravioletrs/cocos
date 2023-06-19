#!/bin/bash
ip link set dev enp0s2 up
dhclient enp0s2

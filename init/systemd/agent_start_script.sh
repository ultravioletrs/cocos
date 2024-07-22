#!/bin/sh

# Change the docker.service file to allow the Docker to run in RAM
mkdir -p /etc/systemd/system/docker.service.d

# Create or overwrite the override.conf file with the new Environment variable
tee /etc/systemd/system/docker.service.d/override.conf > /dev/null <<EOF
[Service]
Environment=DOCKER_RAMDISK=true
EOF

systemctl daemon-reload

NUM_OF_PERMITED_IFACE=1

NUM_OF_IFACE=$(ip route | grep -Eo 'dev [a-z0-9]+' | awk '{ print $2 }' | sort | uniq | wc -l)

if [ $NUM_OF_IFACE -gt $NUM_OF_PERMITED_IFACE ]; then
    echo "More then one network interface in the VM"
    exit 1
fi

DEFAULT_IFACE=$(route | grep '^default' | grep -o '[^ ]*$')
AGENT_GRPC_HOST=$(ip -4 addr show $DEFAULT_IFACE | grep inet | awk '{print $2}' | cut -d/ -f1)

export AGENT_GRPC_HOST

exec /bin/cocos-agent

#!/bin/bash

set -euo pipefail

BASE=$(pwd)
SRC_QCOW="$BASE/noble.qcow2"
SRC_PORT=10809

[[ -f "$SRC_QCOW" ]] || { echo "Missing $SRC_QCOW"; exit 1; }

sudo pkill -f "qemu-nbd.*:$SRC_PORT" || true

sudo qemu-nbd --read-only --persistent --fork  --export-name=src --port=$SRC_PORT -f qcow2 "$SRC_QCOW"
echo "Source up: nbd:localhost:$SRC_PORT -> $SRC_QCOW (RO)"

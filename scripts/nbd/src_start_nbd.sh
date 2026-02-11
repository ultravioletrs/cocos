#!/bin/bash

set -euo pipefail

usage() {
  echo "Usage: $0 <SRC_QCOW> [SRC_PORT]"
  echo "  SRC_QCOW: path to qcow2 image"
  echo "  SRC_PORT: optional, default 10809"
}

BASE=$(pwd)

SRC_QCOW="${1:-}"
SRC_PORT="${2:-10809}"

[[ -n "$SRC_QCOW" ]] || { usage; exit 2; }

# Allow relative paths
if [[ "$SRC_QCOW" != /* ]]; then
  SRC_QCOW="$BASE/$SRC_QCOW"
fi

[[ -f "$SRC_QCOW" ]] || { echo "Missing $SRC_QCOW"; exit 1; }

sudo pkill -f "qemu-nbd.*:$SRC_PORT"

sudo qemu-nbd --read-only --persistent --fork --export-name=src \
  --port="$SRC_PORT" -f qcow2 "$SRC_QCOW"

echo "Source up: nbd:localhost:$SRC_PORT -> $SRC_QCOW (RO)"

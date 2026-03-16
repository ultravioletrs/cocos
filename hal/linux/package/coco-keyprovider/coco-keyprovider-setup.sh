#!/bin/sh
set -e

# Read kernel command line
CMDLINE=$(cat /proc/cmdline)

# Extract agent.aa_kbc_params value
# Format: agent.aa_kbc_params=cc_kbc::URL
PARAMS=$(echo "$CMDLINE" | tr ' ' '\n' | grep '^agent.aa_kbc_params=' | cut -d= -f2-)

if [ -n "$PARAMS" ]; then
    # Extract URL part (after ::)
    KBS_URL="${PARAMS#*::}"
    if [ -n "$KBS_URL" ]; then
        echo "[coco-keyprovider-setup] Detected KBS URL from kernel cmdline: $KBS_URL"
        KBS_ARG="--kbs $KBS_URL"
    fi
else
    echo "[coco-keyprovider-setup] No agent.aa_kbc_params found in kernel cmdline. Starting without --kbs."
fi

# COCO_KP_SOCKET is set by EnvironmentFile in .service
if [ -z "$COCO_KP_SOCKET" ]; then
    COCO_KP_SOCKET="127.0.0.1:50011"
fi

echo "[coco-keyprovider-setup] Starting coco_keyprovider listening on $COCO_KP_SOCKET $KBS_ARG"
exec /usr/local/bin/coco_keyprovider --socket "$COCO_KP_SOCKET" $KBS_ARG

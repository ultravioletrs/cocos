#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_DIR="$(cd "$SCRIPT_DIR/../cloud" && pwd)"
USER_DATA_SOURCE="${USER_DATA_SOURCE:-$SCRIPT_DIR/package-services.yaml}"
META_DATA_SOURCE="${META_DATA_SOURCE:-$CLOUD_DIR/meta-data}"
NETWORK_CONFIG_SOURCE="${NETWORK_CONFIG_SOURCE:-}"
OUTPUT_ISO="${1:-$SCRIPT_DIR/seed.iso}"
PACKAGE_TOGGLE_VARS=(
    COCOS_INSTALL_AGENT
    COCOS_INSTALL_ATTESTATION_SERVICE
    COCOS_INSTALL_CC_ATTESTATION_AGENT
    COCOS_INSTALL_COCO_KEYPROVIDER
    COCOS_INSTALL_COMPUTATION_RUNNER
    COCOS_INSTALL_EGRESS_PROXY
    COCOS_INSTALL_INGRESS_PROXY
    COCOS_INSTALL_LOG_FORWARDER
    COCOS_INSTALL_WASMEDGE
)

usage() {
    cat <<EOF
Usage: $(basename "$0") [output-iso]

Creates a NoCloud seed ISO containing:
  - user-data from: $USER_DATA_SOURCE
  - meta-data from: $META_DATA_SOURCE

Defaults:
  output-iso:     $SCRIPT_DIR/seed.iso

Environment overrides:
  USER_DATA_SOURCE
  META_DATA_SOURCE
  NETWORK_CONFIG_SOURCE

Package toggles:
  COCOS_INSTALL_AGENT
  COCOS_INSTALL_ATTESTATION_SERVICE
  COCOS_INSTALL_CC_ATTESTATION_AGENT
  COCOS_INSTALL_COCO_KEYPROVIDER
  COCOS_INSTALL_COMPUTATION_RUNNER
  COCOS_INSTALL_EGRESS_PROXY
  COCOS_INSTALL_INGRESS_PROXY
  COCOS_INSTALL_LOG_FORWARDER
  COCOS_INSTALL_WASMEDGE

Defaults:
  COCOS_INSTALL_CC_ATTESTATION_AGENT=false
  COCOS_INSTALL_COCO_KEYPROVIDER=false
  all others=true
EOF
}

normalize_toggle() {
    local value="${1:-}"

    case "$value" in
        "")
            printf '%s\n' true
            ;;
        1|true|TRUE|True|yes|YES|Yes|on|ON|On|y|Y)
            printf '%s\n' true
            ;;
        0|false|FALSE|False|no|NO|No|off|OFF|Off|n|N)
            printf '%s\n' false
            ;;
        *)
            echo "invalid package toggle value: $value" >&2
            exit 1
            ;;
    esac
}

default_toggle_for() {
    case "$1" in
        COCOS_INSTALL_CC_ATTESTATION_AGENT|COCOS_INSTALL_COCO_KEYPROVIDER)
            printf '%s\n' false
            ;;
        *)
            printf '%s\n' true
            ;;
    esac
}

render_user_data() {
    local output_file="$1"
    local var_name
    local value

    cp "$USER_DATA_SOURCE" "$output_file"

    for var_name in "${PACKAGE_TOGGLE_VARS[@]}"; do
        if [ -n "${!var_name-}" ]; then
            value="$(normalize_toggle "${!var_name-}")"
        else
            value="$(default_toggle_for "$var_name")"
        fi
        sed -i "s/__${var_name}__/${value}/g" "$output_file"
    done
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ ! -f "$USER_DATA_SOURCE" ]; then
    echo "user-data file not found: $USER_DATA_SOURCE" >&2
    exit 1
fi

if [ ! -f "$META_DATA_SOURCE" ]; then
    echo "meta-data file not found: $META_DATA_SOURCE" >&2
    exit 1
fi

ISO_TOOL=""
if command -v xorriso >/dev/null 2>&1; then
    ISO_TOOL="xorriso"
elif command -v genisoimage >/dev/null 2>&1; then
    ISO_TOOL="genisoimage"
elif command -v mkisofs >/dev/null 2>&1; then
    ISO_TOOL="mkisofs"
else
    echo "missing ISO creation tool; install xorriso, genisoimage, or mkisofs" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$(dirname "$OUTPUT_ISO")"

render_user_data "$TMP_DIR/user-data"
cp "$META_DATA_SOURCE" "$TMP_DIR/meta-data"

if [ -n "$NETWORK_CONFIG_SOURCE" ]; then
    if [ ! -f "$NETWORK_CONFIG_SOURCE" ]; then
        echo "network-config file not found: $NETWORK_CONFIG_SOURCE" >&2
        exit 1
    fi
    cp "$NETWORK_CONFIG_SOURCE" "$TMP_DIR/network-config"
fi

rm -f "$OUTPUT_ISO"

case "$ISO_TOOL" in
    xorriso)
        xorriso -as mkisofs \
            -output "$OUTPUT_ISO" \
            -volid cidata \
            -joliet \
            -rock \
            "$TMP_DIR" >/dev/null
        ;;
    genisoimage|mkisofs)
        "$ISO_TOOL" \
            -output "$OUTPUT_ISO" \
            -volid cidata \
            -joliet \
            -rock \
            "$TMP_DIR" >/dev/null
        ;;
esac

echo "Created seed ISO: $OUTPUT_ISO"

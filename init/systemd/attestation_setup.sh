#!/bin/bash
set -e

# Setup permissions for attestation socket directory
mkdir -p /run/cocos
chmod 755 /run/cocos

#!/bin/bash

REPO_URL="https://github.com/coconut-svsm/svsm.git"
BUILD_DIR="$(cd "$(dirname "$0")/../.." && pwd)/build"


mkdir -p "$BUILD_DIR"

# Define the target directory for cloning inside the build directory
TARGET_DIR="$BUILD_DIR/svsm"
SUBDIR="igvmmeasure"

# Clone the repository if it doesn't exist
if [ -d "$TARGET_DIR" ]; then
    echo "Repository already exists in $TARGET_DIR. Pulling latest changes..."
    cd "$TARGET_DIR" && git pull
else
    echo "Cloning repository into $TARGET_DIR..."
    git clone --recurse-submodules "$REPO_URL" "$TARGET_DIR"
fi

# Ensure submodules are up to date
cd "$TARGET_DIR"
git submodule update --init --recursive

# Check if the required subdirectory exists
if [ -d "$SUBDIR" ]; then
    echo "Successfully cloned repository and found '$SUBDIR' directory."
else
    echo "Error: '$SUBDIR' directory not found inside '$TARGET_DIR'."
    exit 1
fi

echo "Building the Rust crate..."

RELEASE=1 make bin/igvmmeasure BUILDDIR="$BUILD_DIR"

mv bin/igvmmeasure "$BUILD_DIR/"

echo "Binary stored in: $BUILD_DIR/igvmmeasure"

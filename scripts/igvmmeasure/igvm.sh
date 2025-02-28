#!/bin/bash

# Define variables
REPO_URL="https://github.com/coconut-svsm/svsm.git"
TARGET_DIR="svsm"
SUBDIR="igvmmeasure"

# Clone the repository if it doesn't exist
if [ -d "$TARGET_DIR" ]; then
    echo "Repository already exists. Pulling latest changes..."
    cd "$TARGET_DIR" && git pull
else
    echo "Cloning repository..."
    git clone --recurse-submodules "$REPO_URL"
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
RELEASE=1 make bin/igvmmeasure

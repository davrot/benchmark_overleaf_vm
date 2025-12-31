#!/usr/bin/env bash
IMAGE_DIR="$(pwd)/images"

# Create images directory if it doesn't exist
mkdir -p "$(pwd)/images"
chmod 755 "$(pwd)/images"

BASE_IMAGE="$IMAGE_DIR/ubuntu-24.04-base.img"

if [ ! -f "$BASE_IMAGE" ]; then
    echo "📥 Downloading Ubuntu 24.04 cloud image..."
    curl -L -o "$BASE_IMAGE" \
        https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
fi


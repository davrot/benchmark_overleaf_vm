#!/usr/bin/env bash
set -e

SOURCE_VM="overleaf-base-config"
TARGET_VM="overleaf-dev_build"
IMAGE_DIR="$(pwd)/images"
SSH_PORT="2223" # Use a different port than your other VMs

echo "🔄 Cloning $SOURCE_VM to $TARGET_VM..."

# Get the source disk path
SOURCE_DISK=$(virsh -c qemu:///session domblklist "$SOURCE_VM" --details | grep 'disk' | awk '{print $4}')

# 'convert' is better as it flattens the snapshot into the new image
qemu-img convert -O qcow2 "$SOURCE_DISK" "$IMAGE_DIR/${TARGET_VM}.qcow2"

# 3. Create the new VM (using the same logic as your create script)
virt-install \
  --import \
  --connect qemu:///session \
  --name "$TARGET_VM" \
  --memory 8192 \
  --vcpus 4 \
  --disk path="$IMAGE_DIR/${TARGET_VM}.qcow2",device=disk,bus=virtio \
  --os-variant ubuntu24.04 \
  --network none \
  --graphics none \
  --console pty,target_type=serial \
  --noautoconsole \
  --qemu-commandline="-netdev user,id=net0,hostfwd=tcp::$SSH_PORT-:22 -device virtio-net-pci,netdev=net0,addr=0x03"

echo "⏳ Waiting for VM to boot..."
sleep 20


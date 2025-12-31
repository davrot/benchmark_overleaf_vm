#!/usr/bin/env bash
set -e

# Configuration
VM_NAME="${1:-overleaf-base-config}"
MEMORY="${2:-8192}"
CPUS="${3:-4}"
DISK_SIZE="${4:-150}"
SSH_PORT="${5:-2220}"  # Host port for SSH

YAML_FILE="configs/cloud-init-base-config.yaml"

# --- Protection: Check if YAML exists ---
if [ ! -f "$YAML_FILE" ]; then
    echo "❌ ERROR: Cloud-init configuration not found at: $YAML_FILE"
    echo "Please ensure the file exists before running this script."
    exit 1
fi

# Use local directory instead of system directory
IMAGE_DIR="$(pwd)/images"
CLOUD_INIT_CMD="cloud-localds"

# Create images directory if it doesn't exist
mkdir -p "$(pwd)/images"
chmod 755 "$(pwd)/images"

BASE_IMAGE="$IMAGE_DIR/ubuntu-24.04-base.img"
VM_IMAGE="$IMAGE_DIR/${VM_NAME}.qcow2"
CLOUD_INIT_ISO="$IMAGE_DIR/${VM_NAME}-cloud-init.iso"

# --- Cleanup: Remove existing VM if it exists ---
echo "🧹 Checking for existing VM..."
virsh --connect qemu:///session destroy "$VM_NAME" 2>/dev/null || true
virsh --connect qemu:///session undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true

echo "🚀 Creating VM: $VM_NAME"
echo "   Images directory: $IMAGE_DIR"
echo "   SSH will be available on: localhost:$SSH_PORT"

# Download base image if not exists
if [ ! -f "$BASE_IMAGE" ]; then
    echo "📥 Downloading Ubuntu 24.04 cloud image..."
    curl -L -o "$BASE_IMAGE" \
        https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
fi

# Create cloud-init config
cat ${YAML_FILE} | sed "s/VM_NAME_PLACEHOLDER/${VM_NAME}/g" > /tmp/cloud-init-${VM_NAME}.yaml

# Create cloud-init ISO
$CLOUD_INIT_CMD "$CLOUD_INIT_ISO" /tmp/cloud-init-${VM_NAME}.yaml

# Create VM disk
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$VM_IMAGE" ${DISK_SIZE}G

# Create VM with port forwarding via QEMU command-line passthrough
virt-install \
  --import \
  --connect qemu:///session \
  --name "$VM_NAME" \
  --memory "$MEMORY" \
  --vcpus "$CPUS" \
  --disk path="$(realpath $VM_IMAGE)",device=disk,bus=virtio \
  --disk path="$(realpath $CLOUD_INIT_ISO)",device=cdrom \
  --os-variant ubuntu24.04 \
  --network none \
  --graphics none \
  --console pty,target_type=serial \
  --noautoconsole \
  --qemu-commandline="-netdev user,id=net0,hostfwd=tcp::$SSH_PORT-:22 -device virtio-net-pci,netdev=net0,addr=0x03"

echo "✅ VM created!"
echo ""
echo "📡 Connection Info:"
echo "=================="
echo "User: ubuntu"
echo "Password: LLM"
echo ""
echo "🔌 SSH Connection:"
echo "Wait ~30s for boot, then connect: ssh -p $SSH_PORT ubuntu@localhost"
echo "ssh -p $SSH_PORT -i ./cloud-init-key ubuntu@localhost"
echo "or with password:"
echo "ssh -p $SSH_PORT ubuntu@localhost"
echo ""
echo "📟 Console Access:"
echo "virsh -c qemu:///session console $VM_NAME"
echo "(Exit with Ctrl + ])"
echo ""
echo "🛑 VM Control:"
echo "Start: virsh -c qemu:///session start $VM_NAME"
echo "Stop: virsh -c qemu:///session shutdown $VM_NAME"
echo "Force stop: virsh -c qemu:///session destroy $VM_NAME"
echo "Delete: virsh -c qemu:///session undefine $VM_NAME --remove-all-storage"
echo ""
echo "📸 Snapshot Commands:"
echo "Create: virsh -c qemu:///session snapshot-create-as $VM_NAME --name \"snap-name\" --description \"Description\""
echo "List: virsh -c qemu:///session snapshot-list $VM_NAME"
echo "Revert: virsh -c qemu:///session snapshot-revert $VM_NAME --snapshotname snap-name"
echo "Delete: virsh -c qemu:///session snapshot-delete $VM_NAME --snapshotname snap-name"
echo "📋 List VMs: virsh -c qemu:///session list --all"
echo ""
echo "⏸ ️Pausing: virsh -c qemu:///session suspend $VM_NAME"
echo "▶ ️Resuming: virsh -c qemu:///session resume $VM_NAME"


rm /tmp/cloud-init-${VM_NAME}.yaml

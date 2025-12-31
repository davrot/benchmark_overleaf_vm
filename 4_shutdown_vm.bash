#!/usr/bin/env bash
# We remove set -e for the loop section to handle grep exit codes gracefully
# set -e

SOURCE_VM="overleaf-base-config"

# Check if VM is even running
STATE=$(virsh -c qemu:///session domstate "$SOURCE_VM" 2>/dev/null || echo "not found")

if [[ "$STATE" == "running" || "$STATE" == "paused" ]]; then
    echo "🛑 Shutting down $SOURCE_VM..."
    
    # Try graceful shutdown
    virsh -c qemu:///session shutdown "$SOURCE_VM" >/dev/null 2>&1

    echo "⏳ Waiting up to 10s for graceful exit..."
    for i in {1..10}; do
        if ! virsh -c qemu:///session list --name | grep -qx "$SOURCE_VM"; then
            break
        fi
        sleep 1
    done

    # Force kill if still alive
    if virsh -c qemu:///session list --name | grep -qx "$SOURCE_VM"; then
        echo "⚠️  Forcing power off (destroy)..."
        virsh -c qemu:///session destroy "$SOURCE_VM" >/dev/null 2>&1
    fi
else
    echo "ℹ️  VM is already stopped or not found."
fi

echo "✅ VM process terminated. Locks released."

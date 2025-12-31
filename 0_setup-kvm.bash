#!/usr/bin/env bash
set -e

echo "🔍 Detecting operating system..."

if [ -f /etc/fedora-release ]; then
    OS="fedora"
    echo "✓ Detected Fedora"
elif [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    if [ "$DISTRIB_ID" = "Ubuntu" ]; then
        OS="ubuntu"
        echo "✓ Detected Ubuntu"
    fi
else
    echo "❌ Unsupported OS"
    exit 1
fi

echo "📦 Installing KVM/QEMU packages..."

if [ "$OS" = "fedora" ]; then
    sudo dnf install -y \
        @virtualization \
        libguestfs-tools-c \
        cloud-utils \
        virt-install \
        virt-manager \
        virt-viewer
        
elif [ "$OS" = "ubuntu" ]; then
    sudo apt update
    sudo apt install -y \
        qemu-kvm \
        libvirt-daemon-system \
        libvirt-clients \
        virtinst \
        virt-manager \
        libguestfs-tools \
        cloud-image-utils
fi

echo "🔧 Configuring libvirt..."

# Start and enable libvirt
sudo systemctl start libvirtd
sudo systemctl enable libvirtd

# Add user to libvirt group
if [ "$OS" = "fedora" ]; then
    sudo usermod -aG libvirt $USER
elif [ "$OS" = "ubuntu" ]; then
    sudo usermod -aG libvirt $USER
    sudo usermod -aG kvm $USER
fi

echo "✅ Installation complete!"
echo ""
echo "⚠️  IMPORTANT: Log out and back in (or reboot) for group changes to take effect"
echo ""
echo "Verify with: virt-host-validate"

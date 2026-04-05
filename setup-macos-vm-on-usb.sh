#!/bin/bash
# setup-macos-vm-on-usb.sh
# Run this AFTER your USB is mounted at /mnt/usb
# Usage: sudo bash setup-macos-vm-on-usb.sh /dev/sda

set -e

USB_DEVICE="${1:-/dev/sda}"
USB_PARTITION="${USB_DEVICE}1"
MOUNT_POINT="/mnt/usb"
VM_DIR="${MOUNT_POINT}/macos-vm"
DOCKER_DATA_DIR="${MOUNT_POINT}/docker-data"

echo "=========================================="
echo " Monitoring Agent - macOS VM on USB Setup"
echo "=========================================="
echo ""

# ── Step 1: Detect USB ────────────────────────
echo "[1/7] Detecting USB device: $USB_DEVICE"
if ! lsblk "$USB_DEVICE" &>/dev/null; then
    echo "ERROR: Device $USB_DEVICE not found."
    echo "Run 'sudo lsblk' to find your USB device name."
    exit 1
fi
lsblk -o NAME,SIZE,FSTYPE,LABEL "$USB_DEVICE"
echo ""

# ── Step 2: Format USB (WARNING: destructive) ──
echo "[2/7] Formatting USB drive (ALL DATA WILL BE ERASED)..."
read -p "  Confirm formatting $USB_DEVICE? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi
parted "$USB_DEVICE" --script mklabel gpt
parted "$USB_DEVICE" --script mkpart primary ext4 0% 100%
sleep 2
mkfs.ext4 "${USB_PARTITION}" -L "macos-vm"
echo "  Done."
echo ""

# ── Step 3: Mount USB ─────────────────────────
echo "[3/7] Mounting USB at $MOUNT_POINT..."
mkdir -p "$MOUNT_POINT"
mount "${USB_PARTITION}" "$MOUNT_POINT"
mkdir -p "$VM_DIR"
mkdir -p "$DOCKER_DATA_DIR"
echo "  Mounted. Free space:"
df -h "$MOUNT_POINT" | tail -1
echo ""

# ── Step 4: Install QEMU ──────────────────────
echo "[4/7] Installing QEMU + KVM tools..."
apt-get install -y \
    qemu-system-x86 \
    qemu-kvm \
    qemu-utils \
    libvirt-daemon-system \
    libvirt-clients \
    bridge-utils \
    virt-manager \
    ovmf \
    swtpm \
    git \
    wget \
    curl
echo ""

# ── Step 5: Add user to kvm/libvirt groups ────
echo "[5/7] Adding $SUDO_USER to kvm and libvirt groups..."
REAL_USER="${SUDO_USER:-$USER}"
usermod -aG kvm "$REAL_USER"
usermod -aG libvirt "$REAL_USER"
usermod -aG docker "$REAL_USER" 2>/dev/null || true
echo "  Done. Groups will apply on next login."
echo ""

# ── Step 6: Configure Docker to use USB ───────
echo "[6/7] Pointing Docker data directory to USB..."
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"

# Back up current config
cp "$DOCKER_DAEMON_JSON" "${DOCKER_DAEMON_JSON}.bak" 2>/dev/null || true

# Write new config preserving existing settings
python3 - <<EOF
import json, os

config_file = "$DOCKER_DAEMON_JSON"
new_data_root = "$DOCKER_DATA_DIR"

try:
    with open(config_file, 'r') as f:
        config = json.load(f)
except:
    config = {}

config["data-root"] = new_data_root
print(f"  Setting Docker data-root to: {new_data_root}")

with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)
print("  Docker daemon.json updated.")
EOF

systemctl restart docker
echo "  Docker restarted with new data root."
echo ""

# ── Step 7: Pull Docker-OSX ───────────────────
echo "[7/7] Pulling Docker-OSX (macOS Monterey) image..."
echo "  NOTE: This downloads ~5-10 GB. May take 10-30 minutes."
echo ""
sudo -u "$REAL_USER" docker pull sickcodes/docker-osx:monterey
echo ""

# ── Done ───────────────────────────────────────
echo "=========================================="
echo " Setup Complete!"
echo "=========================================="
echo ""
echo "USB mounted at  : $MOUNT_POINT"
echo "VM files stored : $VM_DIR"
echo "Docker data dir : $DOCKER_DATA_DIR"
echo ""
echo "NEXT STEP: Run the macOS VM:"
echo ""
echo "  bash /mnt/usb/macos-vm/run-macos-vm.sh"
echo ""
echo "Or use the quick one-liner (as your normal user, not root):"
echo ""
cat << 'RUNSCRIPT'

  docker run -it \
    --device /dev/kvm \
    -p 50922:10022 \
    -p 5999:5999 \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -e "DISPLAY=${DISPLAY:-:0}" \
    -e GENERATE_UNIQUE=true \
    -e MASTER_PLIST_URL='https://raw.githubusercontent.com/sickcodes/osx-serial-generator/master/config-custom.plist' \
    sickcodes/docker-osx:monterey

RUNSCRIPT
echo ""
echo "After macOS boots, copy your .pkg file into the VM to test installation."
echo "See MACOS_BUILD_GUIDE.md for full instructions."

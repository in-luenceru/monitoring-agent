#!/bin/bash
# run-macos-vm.sh
# Launches the macOS VM using Docker-OSX with KVM acceleration
# Stores the persistent macOS disk image on the USB drive so
# you get full 170 GB and keep your macOS install between reboots.

set -e

MOUNT_POINT="/mnt/usb"
VM_DIR="${MOUNT_POINT}/macos-vm"
DISK_IMAGE="${VM_DIR}/macOS.img"

# ── Ensure USB is mounted ─────────────────────
if ! mountpoint -q "$MOUNT_POINT"; then
    echo "USB not mounted. Mounting..."
    # Find the USB partition by label
    USB_PART=$(blkid -L macos-vm 2>/dev/null)
    if [ -z "$USB_PART" ]; then
        echo "ERROR: Cannot find USB partition labeled 'macos-vm'."
        echo "Run: sudo blkid  to find your USB, then: sudo mount /dev/sdX1 /mnt/usb"
        exit 1
    fi
    sudo mount "$USB_PART" "$MOUNT_POINT"
fi

mkdir -p "$VM_DIR"

echo "======================================"
echo " Monitoring Agent - macOS VM Launcher"
echo "======================================"
echo " VM disk  : $DISK_IMAGE"
df -h "$MOUNT_POINT" | tail -1
echo ""

# ── Create persistent disk image if first run ──
if [ ! -f "$DISK_IMAGE" ]; then
    echo "[*] First run: creating 80 GB persistent macOS disk image..."
    qemu-img create -f qcow2 "$DISK_IMAGE" 80G
    echo "    Created: $DISK_IMAGE"
    echo ""
fi

# ── Check KVM access ──────────────────────────
if [ ! -r /dev/kvm ]; then
    echo "WARNING: /dev/kvm not accessible. Run: sudo usermod -aG kvm $USER && newgrp kvm"
    exit 1
fi

echo "[*] Starting macOS VM (Docker-OSX / Monterey)..."
echo "    VNC available at vnc://localhost:5999 (use Remmina or TigerVNC)"
echo "    SSH available at: ssh -p 50922 user@localhost (after macOS boots)"
echo ""
echo "    FIRST BOOT: macOS installer will open - install to 'QEMU HARDDISK'"
echo "    SUBSEQUENT BOOTS: macOS loads directly from the saved disk image."
echo ""

# ── Run Docker-OSX with persistent disk ───────
docker run -it \
    --name macos-vm \
    --rm \
    --device /dev/kvm \
    --device /dev/snd \
    -e RAM=8 \
    -e CPUS=4 \
    -p 50922:10022 \
    -p 5999:5999 \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -e "DISPLAY=${DISPLAY:-:0}" \
    -e GENERATE_UNIQUE=true \
    -e MASTER_PLIST_URL='https://raw.githubusercontent.com/sickcodes/osx-serial-generator/master/config-custom.plist' \
    -v "${DISK_IMAGE}:/image" \
    sickcodes/docker-osx:monterey

echo ""
echo "VM session ended. Your macOS install is saved at:"
echo "  $DISK_IMAGE"

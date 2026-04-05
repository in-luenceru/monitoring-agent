#!/bin/bash
# run-macos-vm.sh
# Launches the macOS VM using Docker-OSX with KVM acceleration.
# The persistent macOS disk image is stored at ~/macos-vm/macOS.img

set -e

DISK_IMAGE="/home/anandhu/macos-vm/macOS.img"

echo "======================================"
echo " Monitoring Agent - macOS VM Launcher"
echo "======================================"
echo " VM disk  : $DISK_IMAGE ($(du -sh "$DISK_IMAGE" 2>/dev/null | cut -f1) used)"
df -h / | awk 'NR==2 {printf " Host disk: %s free of %s\n", $4, $2}'
echo ""

# ── Create persistent disk image if missing ───
if [ ! -f "$DISK_IMAGE" ]; then
    echo "[*] Creating 30 GB persistent macOS disk image..."
    mkdir -p "$(dirname "$DISK_IMAGE")"
    qemu-img create -f qcow2 "$DISK_IMAGE" 30G
    echo "    Created: $DISK_IMAGE"
    echo ""
fi

# ── Check KVM access ──────────────────────────
if [ ! -r /dev/kvm ]; then
    echo "ERROR: /dev/kvm not accessible."
    echo "Run: sudo chmod 666 /dev/kvm"
    exit 1
fi

echo "[*] Starting macOS VM (Docker-OSX)..."
echo "    VNC  : open vnc://localhost:5999 in Remmina or TigerVNC"
echo "    SSH  : ssh -p 50922 user@localhost  (once macOS boots)"
echo ""
echo "    FIRST BOOT : macOS installer opens → install to 'QEMU HARDDISK'"
echo "    LATER BOOTS: macOS loads directly from the saved disk image."
echo ""

# ── Run Docker-OSX with persistent disk ───────
docker run -it \
    --name macos-vm \
    --rm \
    --device /dev/kvm \
    --device /dev/snd \
    -e RAM=6 \
    -e CPUS=4 \
    -p 50922:10022 \
    -p 5999:5999 \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -e "DISPLAY=${DISPLAY:-:0}" \
    -e GENERATE_UNIQUE=true \
    -e MASTER_PLIST_URL='https://raw.githubusercontent.com/sickcodes/osx-serial-generator/master/config-custom.plist' \
    -v "${DISK_IMAGE}:/image" \
    sickcodes/docker-osx:latest

echo ""
echo "VM session ended. Your macOS install is saved at:"
echo "  $DISK_IMAGE"

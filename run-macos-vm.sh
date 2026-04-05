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

# ── Ensure /dev/kvm is accessible ────────────
if [ ! -r /dev/kvm ]; then
    echo "[*] Fixing /dev/kvm permissions..."
    sudo chmod 666 /dev/kvm
fi

echo "[*] Starting macOS VM (headless - VNC only)..."
echo "    ┌─────────────────────────────────────────────┐"
echo "    │  Connect VNC to see the screen:             │"
echo "    │  Open Remmina → New → VNC → localhost:5999  │"
echo "    │  OR run:  vncviewer localhost:5999           │"
echo "    │                                             │"
echo "    │  SSH (after macOS boots):                   │"
echo "    │  ssh -p 50922 user@localhost                │"
echo "    └─────────────────────────────────────────────┘"
echo ""
echo "    FIRST BOOT : macOS installer opens in VNC → install to 'QEMU HARDDISK'"
echo "    LATER BOOTS: macOS loads directly from the saved disk image."
echo ""

# ── Run Docker-OSX detached + headless (VNC only) ─────────────────
# -d                 : detached — runs in background, safe from Ctrl+C
# EXTRA display flag : forces QEMU to use its built-in VNC server
#                      instead of GTK (GTK fails without a desktop display)
# Port 5999          : QEMU VNC display :99  (5900 + 99 = 5999)
docker run -d \
    --name macos-vm \
    --device /dev/kvm \
    -e RAM=4 \
    -e CPUS=2 \
    -p 50922:10022 \
    -p 5999:5999 \
    -e GENERATE_UNIQUE=true \
    -e EXTRA="-display vnc=0.0.0.0:99,password=off -audiodev none,id=noaudio -machine q35,usb=on" \
    -e MASTER_PLIST_URL='https://raw.githubusercontent.com/sickcodes/osx-serial-generator/master/config-custom.plist' \
    -v "${DISK_IMAGE}:/image" \
    sickcodes/docker-osx:latest

echo ""
echo "[*] VM container started in background (ID: $(docker ps -qf name=macos-vm))"
echo ""
echo "Waiting for macOS to download and boot (this takes 5-15 min)..."
echo "Follow progress with:  docker logs -f macos-vm"
echo ""

# Wait for VNC port to be ready
echo -n "Waiting for VNC port 5999"
for i in $(seq 1 120); do
    if nc -z localhost 5999 2>/dev/null; then
        echo " READY!"
        break
    fi
    echo -n "."
    sleep 5
done

echo ""
echo "======================================"
echo " VNC is ready — connecting now..."
echo "======================================"
vncviewer 127.0.0.1:5999 &

echo ""
echo "VM session ended. Your macOS install is saved at:"
echo "  $DISK_IMAGE"

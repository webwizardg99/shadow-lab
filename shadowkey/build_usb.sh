#!/bin/bash
# ShadowKey USB Builder
# Creates a bootable Debian-based live image with ShadowKey pre-installed.
#
# Requirements: live-build, debootstrap, xorriso, grub-pc-bin, grub-efi-amd64-bin
# Usage: sudo bash build_usb.sh [--output shadowkey.iso] [--write /dev/sdX]
#
# The resulting ISO can be:
#   - Written to USB:  dd if=shadowkey.iso of=/dev/sdX bs=4M status=progress
#   - Written via:     bash build_usb.sh --write /dev/sdX
#   - Tested in VM:    qemu-system-x86_64 -cdrom shadowkey.iso -m 2G

set -euo pipefail

OUTPUT="${OUTPUT:-shadowkey.iso}"
WRITE_TARGET=""
BUILD_DIR="/tmp/shadowkey-build"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LB_CONFIG="$BUILD_DIR/lb"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --write)  WRITE_TARGET="$2"; shift 2 ;;
        --clean)  rm -rf "$BUILD_DIR"; echo "Build dir cleaned."; exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Checks ────────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash build_usb.sh"; exit 1; }

for dep in lb debootstrap xorriso mksquashfs; do
    command -v "$dep" &>/dev/null || { echo "Missing: $dep (apt install live-build squashfs-tools xorriso)"; exit 1; }
done

echo "==> ShadowKey USB Builder"
echo "    Output: $OUTPUT"
echo "    Source: $REPO_DIR"
echo ""

# ── live-build config ─────────────────────────────────────────────────────────
mkdir -p "$LB_CONFIG"
cd "$LB_CONFIG"

lb config \
    --distribution bookworm \
    --debian-installer none \
    --bootappend-live "boot=live components quiet splash \
        hostname=shadowkey username=shadow \
        nopersistence" \
    --bootappend-live-failsafe "boot=live components memtest noapic noapm nodma nomce nolapic nosmp nosplash vga=normal" \
    --memtest none \
    --win32-loader false \
    --iso-volume "ShadowKey" \
    --image-name "shadowkey" \
    --bootloaders "grub-efi,grub-pc" \
    --uefi-secure-boot disable

# ── Package list ──────────────────────────────────────────────────────────────
mkdir -p config/package-lists
cat > config/package-lists/shadowkey.list.chroot << 'EOF'
# Base system
python3
python3-pip
curl
wget
nftables
iproute2
iputils-ping
isc-dhcp-client
dhcpcd5
net-tools
dnsutils
nmap
openssh-client
git
jq

# ShadowKey services
suricata
tor
wireguard-tools
tcpdump
netcat-openbsd
dnscrypt-proxy

# Web dashboard deps
uvicorn
python3-fastapi
python3-aiofiles
python3-sqlalchemy

# UI
chromium
openbox
tint2
xorg
xinit
lightdm
lightdm-gtk-greeter
EOF

# ── GRUB boot menu ────────────────────────────────────────────────────────────
mkdir -p config/bootloaders/grub-pc/live-theme
cat > config/bootloaders/grub-pc/grub.cfg << 'GRUBEOF'
set default=0
set timeout=8

# ShadowKey theme
set menu_color_normal=white/black
set menu_color_highlight=black/cyan

menuentry "ShadowKey — Stealth Mode (no trace)" {
    set SHADOWKEY_BOOT_MODE=stealth
    linux /live/vmlinuz boot=live components quiet splash \
        SHADOWKEY_BOOT_MODE=stealth \
        hostname=shadowkey username=shadow
    initrd /live/initrd.img
}

menuentry "ShadowKey — Persistent Mode (encrypted)" {
    linux /live/vmlinuz boot=live components quiet splash persistence \
        persistence-encryption=luks \
        SHADOWKEY_BOOT_MODE=persistent \
        hostname=shadowkey username=shadow
    initrd /live/initrd.img
}

menuentry "ShadowKey — Work Profile (forced)" {
    linux /live/vmlinuz boot=live components quiet \
        SHADOWKEY_BOOT_MODE=stealth SHADOWKEY_PROFILE=work \
        hostname=shadowkey username=shadow
    initrd /live/initrd.img
}

menuentry "ShadowKey — Corporate Profile (forced)" {
    linux /live/vmlinuz boot=live components quiet \
        SHADOWKEY_BOOT_MODE=stealth SHADOWKEY_PROFILE=corporate \
        hostname=shadowkey username=shadow
    initrd /live/initrd.img
}

menuentry "Boot from first hard disk" {
    chainloader (hd0)+1
}
GRUBEOF

# ── Install ShadowKey files into live system ──────────────────────────────────
mkdir -p config/includes.chroot/opt/shadowkey
mkdir -p config/includes.chroot/opt/shadowlab
mkdir -p config/includes.chroot/etc/shadowmesh

# Copy shadowkey components
cp "$REPO_DIR/shadowkey/shadowkey_init.sh"      config/includes.chroot/opt/shadowkey/
cp "$REPO_DIR/shadowkey/shadowkey_profile.py"   config/includes.chroot/opt/shadowkey/
cp "$REPO_DIR/shadowbridge_recon.py"            config/includes.chroot/opt/shadowkey/
cp "$REPO_DIR/shadowbridge_honeypot.py"         config/includes.chroot/opt/shadowkey/
cp -r "$REPO_DIR/shadowmesh"                    config/includes.chroot/opt/shadowkey/

# Copy dashboard
cp "$REPO_DIR/main.py"                          config/includes.chroot/opt/shadowlab/
cp "$REPO_DIR/database.py"                      config/includes.chroot/opt/shadowlab/
cp "$REPO_DIR/shadowbridge_agent.py"            config/includes.chroot/opt/shadowlab/
cp "$REPO_DIR/shadowbridge_telegram.py"         config/includes.chroot/opt/shadowlab/
[[ -d "$REPO_DIR/templates" ]] && cp -r "$REPO_DIR/templates" config/includes.chroot/opt/shadowlab/
[[ -d "$REPO_DIR/static"    ]] && cp -r "$REPO_DIR/static"    config/includes.chroot/opt/shadowlab/

chmod +x config/includes.chroot/opt/shadowkey/shadowkey_init.sh

# ── Systemd service for init ──────────────────────────────────────────────────
mkdir -p config/includes.chroot/etc/systemd/system
cat > config/includes.chroot/etc/systemd/system/shadowkey-init.service << 'SVCEOF'
[Unit]
Description=ShadowKey Boot Init
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/shadowkey/shadowkey_init.sh
EnvironmentFile=-/proc/cmdline
Restart=no
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=graphical.target
SVCEOF

# ── Enable service in live system ─────────────────────────────────────────────
mkdir -p config/includes.chroot/etc/systemd/system/graphical.target.wants
ln -sf /etc/systemd/system/shadowkey-init.service \
    config/includes.chroot/etc/systemd/system/graphical.target.wants/shadowkey-init.service

# ── Openbox autostart (launches browser after init) ──────────────────────────
mkdir -p config/includes.chroot/home/shadow/.config/openbox
cat > config/includes.chroot/home/shadow/.config/openbox/autostart << 'OBEOF'
# ShadowKey Openbox autostart
tint2 &
# Dashboard browser will be launched by shadowkey_init.sh
OBEOF

# ── LightDM autologin ─────────────────────────────────────────────────────────
mkdir -p config/includes.chroot/etc/lightdm
cat > config/includes.chroot/etc/lightdm/lightdm.conf << 'LDMEOF'
[Seat:*]
autologin-user=shadow
autologin-user-timeout=0
user-session=openbox
greeter-session=lightdm-gtk-greeter
LDMEOF

# ── /etc/rc.local — pass kernel cmdline vars to env ──────────────────────────
cat > config/includes.chroot/etc/rc.local << 'RCEOF'
#!/bin/bash
# Parse SHADOWKEY_* vars from kernel cmdline and export to environment
for param in $(cat /proc/cmdline); do
    case "$param" in
        SHADOWKEY_*)
            echo "export $param" >> /etc/environment
            ;;
    esac
done
exit 0
RCEOF
chmod +x config/includes.chroot/etc/rc.local

# ── pip install for dashboard ─────────────────────────────────────────────────
mkdir -p config/hooks/live
cat > config/hooks/live/0100-pip-install.hook.chroot << 'HOOKEOF'
#!/bin/bash
pip3 install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    aiofiles \
    sqlalchemy \
    python-multipart \
    httpx
HOOKEOF
chmod +x config/hooks/live/0100-pip-install.hook.chroot

# ── Build ─────────────────────────────────────────────────────────────────────
echo ""
echo "==> Starting live-build (this takes 10-30 minutes)..."
lb build 2>&1 | tee /tmp/shadowkey-build.log

# Move output
if [[ -f "$LB_CONFIG/shadowkey-amd64.hybrid.iso" ]]; then
    mv "$LB_CONFIG/shadowkey-amd64.hybrid.iso" "$OLDPWD/$OUTPUT"
    echo ""
    echo "==> Build complete: $OUTPUT"
    echo "    Size: $(du -sh "$OLDPWD/$OUTPUT" | cut -f1)"
else
    echo "Build failed. Check /tmp/shadowkey-build.log"
    exit 1
fi

# ── Write to USB ──────────────────────────────────────────────────────────────
if [[ -n "$WRITE_TARGET" ]]; then
    echo ""
    echo "==> Writing to $WRITE_TARGET..."
    echo "    WARNING: This will erase $WRITE_TARGET"
    read -p "    Continue? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

    dd if="$OLDPWD/$OUTPUT" of="$WRITE_TARGET" bs=4M status=progress conv=fsync
    sync
    echo "==> Done! Boot from $WRITE_TARGET"

    # Create LUKS persistent partition (for persistent mode)
    echo ""
    echo "==> Creating encrypted persistence partition..."
    PART_SIZE="2G"
    parted "$WRITE_TARGET" mkpart primary ext4 -- -${PART_SIZE} -1s 2>/dev/null || true
    PART="${WRITE_TARGET}3"
    [[ -b "$PART" ]] || PART="${WRITE_TARGET}p3"
    if [[ -b "$PART" ]]; then
        cryptsetup luksFormat "$PART"
        cryptsetup luksOpen "$PART" shadowkey-persist
        mkfs.ext4 -L persistence /dev/mapper/shadowkey-persist
        mkdir -p /mnt/shadowkey-persist
        mount /dev/mapper/shadowkey-persist /mnt/shadowkey-persist
        echo "/ union" > /mnt/shadowkey-persist/persistence.conf
        umount /mnt/shadowkey-persist
        cryptsetup luksClose shadowkey-persist
        echo "==> Encrypted persistence partition ready"
    fi
fi

echo ""
echo "ShadowKey ISO: $OUTPUT"
echo "Write to USB:  dd if=$OUTPUT of=/dev/sdX bs=4M status=progress"
echo "Test in QEMU:  qemu-system-x86_64 -cdrom $OUTPUT -m 2G -enable-kvm"

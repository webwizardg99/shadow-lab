#!/bin/bash
# ShadowKey Boot Init
# Runs on first boot from USB. Detects environment, loads profile,
# starts all services, opens the web dashboard.
#
# Executed by: /etc/rc.local or systemd shadowkey-init.service
# Logs to:     /tmp/shadowkey.log and journald

set -euo pipefail
exec > >(tee -a /tmp/shadowkey.log) 2>&1

SHADOWKEY_DIR="/opt/shadowkey"
DASHBOARD_DIR="/opt/shadowlab"
RECON_RESULT="/tmp/sk_recon.json"
PROFILE_CONFIG="/tmp/sk_profile.json"
BOOT_MODE="${SHADOWKEY_BOOT_MODE:-stealth}"   # stealth | persistent
PROFILE_OVERRIDE="${SHADOWKEY_PROFILE:-}"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
ok()   { echo -e "${GRN}[✓]${RST} $*"; }
warn() { echo -e "${YLW}[!]${RST} $*"; }
err()  { echo -e "${RED}[✗]${RST} $*"; }
info() { echo -e "${CYN}[*]${RST} $*"; }

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo -e "${BLD}${CYN}"
cat << 'EOF'
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗  ██╗███████╗██╗   ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║█████╔╝ █████╗   ╚████╔╝
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔═██╗ ██╔══╝    ╚██╔╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██╗███████╗   ██║
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝
EOF
echo -e "${RST}"
echo -e "  ${BLD}ShadowKey v0.1  |  Mode: ${BOOT_MODE}${RST}"
echo -e "  100% freedom. 100% security. No trace.\n"
sleep 1

# ── Step 1: Network wait ──────────────────────────────────────────────────────
info "Waiting for network..."
for i in $(seq 1 15); do
    if ip route show default &>/dev/null; then
        ok "Network ready"
        break
    fi
    sleep 1
done

# Try DHCP if no network yet
if ! ip route show default &>/dev/null; then
    iface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
    if [[ -n "$iface" ]]; then
        warn "No route — attempting DHCP on $iface"
        dhclient "$iface" 2>/dev/null || dhcpcd "$iface" 2>/dev/null || true
        sleep 3
    fi
fi

# ── Step 2: Environment recon ─────────────────────────────────────────────────
info "Detecting environment..."
if python3 "$SHADOWKEY_DIR/shadowbridge_recon.py" > "$RECON_RESULT" 2>/dev/null; then
    MODE=$(python3 -c "import json,sys; d=json.load(open('$RECON_RESULT')); print(d.get('mode','home'))")
    SCORE=$(python3 -c "import json,sys; d=json.load(open('$RECON_RESULT')); print(d.get('corp_score',0))")
    ok "Environment detected: ${BLD}${MODE}${RST} (score: ${SCORE})"
else
    warn "Recon failed — defaulting to home profile"
    echo '{"mode":"home","corp_score":0}' > "$RECON_RESULT"
    MODE="home"
fi

# ── Step 3: Load profile ──────────────────────────────────────────────────────
info "Loading security profile..."
PROFILE_ARGS="--recon-json $RECON_RESULT"
[[ -n "$PROFILE_OVERRIDE" ]] && PROFILE_ARGS="--profile $PROFILE_OVERRIDE --no-recon"

python3 "$SHADOWKEY_DIR/shadowkey_profile.py" \
    $PROFILE_ARGS \
    --write-nft \
    > "$PROFILE_CONFIG"

PROFILE=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d['_meta']['profile'])")
ok "Profile loaded: ${BLD}${PROFILE}${RST}"

# ── Step 4: Apply firewall ────────────────────────────────────────────────────
info "Applying firewall rules..."
if command -v nft &>/dev/null && [[ -f /tmp/shadowkey_nft.conf ]]; then
    nft -f /tmp/shadowkey_nft.conf && ok "nftables rules applied" || warn "nftables apply failed"
else
    warn "nft not available — skipping firewall"
fi

# ── Step 5: Start ShadowBridge dashboard ─────────────────────────────────────
info "Starting ShadowBridge dashboard..."
cd "$DASHBOARD_DIR"

# Kill any previous instance
pkill -f "uvicorn main" 2>/dev/null || true
sleep 1

# Inject profile into dashboard env
export SHADOWBRIDGE_PROFILE="$PROFILE"
export SHADOWBRIDGE_RECON_JSON="$RECON_RESULT"

nohup python3 -m uvicorn main:app \
    --host 127.0.0.1 \
    --port 8888 \
    --workers 1 \
    > /tmp/shadowbridge.log 2>&1 &

DASH_PID=$!
echo $DASH_PID > /tmp/shadowbridge.pid

# Wait for dashboard to come up
for i in $(seq 1 15); do
    if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8888/login 2>/dev/null | grep -q "200\|302"; then
        ok "Dashboard ready at http://localhost:8888"
        break
    fi
    sleep 1
done

# ── Step 6: Start ShadowMesh ──────────────────────────────────────────────────
MESH_ENABLED=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d.get('shadowmesh',{}).get('enabled',False))")
TOR_ENABLED=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d.get('shadowmesh',{}).get('tor_bridge',False))")

if [[ "$MESH_ENABLED" == "True" ]]; then
    info "Starting ShadowMesh..."
    MESH_ARGS="--no-wg"   # no WireGuard kernel module in live env by default
    [[ "$TOR_ENABLED" == "False" ]] && MESH_ARGS="$MESH_ARGS --no-tor"
    nohup python3 "$SHADOWKEY_DIR/shadowmesh/shadowmesh_node.py" $MESH_ARGS \
        > /tmp/shadowmesh.log 2>&1 &
    ok "ShadowMesh started (mesh discovery active)"
fi

# ── Step 7: Start honeypot (work/corporate only) ──────────────────────────────
HONEYPOT_ENABLED=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d.get('honeypot',{}).get('enabled',False))")
if [[ "$HONEYPOT_ENABLED" == "True" ]]; then
    info "Deploying honeypot ($PROFILE mode)..."
    nohup python3 "$SHADOWKEY_DIR/shadowbridge_honeypot.py" "$PROFILE" \
        > /tmp/honeypot.log 2>&1 &
    ok "Honeypot active (fake SSH:2222, HTTP:8080)"
fi

# ── Step 8: Start Suricata IDS ────────────────────────────────────────────────
SURICATA_ENABLED=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d.get('suricata',{}).get('enabled',False))")
IFACE=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d.get('_meta',{}).get('interface',''))")

if [[ "$SURICATA_ENABLED" == "True" ]] && command -v suricata &>/dev/null && [[ -n "$IFACE" ]]; then
    info "Starting Suricata IDS on $IFACE..."
    suricata -D -i "$IFACE" -l /tmp/suricata/ \
        --set outputs.1.eve-log.enabled=yes 2>/dev/null && \
        ok "Suricata IDS running" || warn "Suricata failed to start"
fi

# ── Step 9: DNS over HTTPS (corporate mode) ──────────────────────────────────
DOH=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d.get('firewall',{}).get('dns_over_https',False))")
if [[ "$DOH" == "True" ]] && command -v dnscrypt-proxy &>/dev/null; then
    info "Enabling DNS over HTTPS..."
    dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml &
    ok "DNS over HTTPS active"
fi

# ── Step 10: Launch browser ───────────────────────────────────────────────────
HOMEPAGE=$(python3 -c "import json; d=json.load(open('$PROFILE_CONFIG')); print(d.get('browser_homepage','http://localhost:8888'))")

info "Opening dashboard in browser..."
sleep 2

# Try kiosk browsers in order
if command -v chromium &>/dev/null; then
    chromium --kiosk --no-sandbox --disable-infobars \
        --app="$HOMEPAGE" &>/dev/null &
elif command -v chromium-browser &>/dev/null; then
    chromium-browser --kiosk --no-sandbox --disable-infobars \
        --app="$HOMEPAGE" &>/dev/null &
elif command -v firefox &>/dev/null; then
    firefox --kiosk "$HOMEPAGE" &>/dev/null &
else
    warn "No browser found — open manually: $HOMEPAGE"
fi

# ── Final status ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "  ${GRN}ShadowKey is running${RST}"
echo -e "  Profile   : ${BLD}${PROFILE}${RST} (${MODE} env, score: ${SCORE})"
echo -e "  Dashboard : ${BLD}http://localhost:8888${RST}"
echo -e "  Mode      : ${BLD}${BOOT_MODE}${RST}"
[[ "$BOOT_MODE" == "stealth" ]] && echo -e "  ${YLW}Stealth: no data written to host disk${RST}"
echo -e "${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""

# Keep script alive so systemd doesn't kill us
wait

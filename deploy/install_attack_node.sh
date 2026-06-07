#!/bin/bash
# install_attack_node.sh — ShadowLab Attack Node Setup
#
# Felállítja az attack gépet:
#   1. /opt/github-tools külön partíció (opcionális, ha van szabad eszköz)
#   2. hexstrike-ai klónozása + AI függőségek
#   3. ShadowBridge agent telepítése
#   4. ShadowMesh telepítése
#   5. Ollama + AI modellek (nemotron, qwen2.5)
#
# Használat:
#   bash install_attack_node.sh <attack_ip> <agent_token> [--disk /dev/sdb]
#
# Példa:
#   bash install_attack_node.sh 192.168.1.77 sb_attack_token --disk /dev/sdb

set -euo pipefail

ATTACK_HOST="${1:?Használat: $0 <host> <token> [--disk /dev/sdX]}"
AGENT_TOKEN="${2:?Hiányzó agent token}"
EXTRA_DISK=""
DASHBOARD_URL="${DASHBOARD_URL:-http://100.75.31.41:8888}"
SSH_USER="${SSH_USER:-wizardg}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

GITHUB_TOOLS_DIR="/opt/github-tools"
SHADOWBRIDGE_DIR="/opt/shadowbridge"
SHADOWMESH_DIR="/opt/shadowmesh"

# Parse optional args
shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk) EXTRA_DISK="$2"; shift 2 ;;
        *) echo "Ismeretlen arg: $1"; exit 1 ;;
    esac
done

echo "══════════════════════════════════════════════════════"
echo "  ShadowLab Attack Node Installer"
echo "  Host    : $ATTACK_HOST ($SSH_USER)"
echo "  Dashboard: $DASHBOARD_URL"
echo "  Disk    : ${EXTRA_DISK:-nincs (könyvtár mód)}"
echo "══════════════════════════════════════════════════════"
echo ""

# ── Helper ────────────────────────────────────────────────────────────────────
ssh_run() {
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$ATTACK_HOST" "$@"
}

# ── Step 1: GitHub-tools partíció ─────────────────────────────────────────────
echo "[1/6] GitHub-tools partíció beállítása..."

if [[ -n "$EXTRA_DISK" ]]; then
    echo "      Formázás: $EXTRA_DISK → ext4, mount: $GITHUB_TOOLS_DIR"
    ssh_run "
        sudo parted -s '$EXTRA_DISK' mklabel gpt
        sudo parted -s '$EXTRA_DISK' mkpart primary ext4 0% 100%
        sudo mkfs.ext4 -L github-tools '${EXTRA_DISK}1' -F
        sudo mkdir -p '$GITHUB_TOOLS_DIR'
        echo '${EXTRA_DISK}1  $GITHUB_TOOLS_DIR  ext4  defaults,noatime  0  2' \
            | sudo tee -a /etc/fstab
        sudo mount '$GITHUB_TOOLS_DIR'
        sudo chown $SSH_USER:$SSH_USER '$GITHUB_TOOLS_DIR'
        echo 'Partíció kész: \$(df -h $GITHUB_TOOLS_DIR | tail -1)'
    "
    echo "      ✓ Partíció felcsatolva: $GITHUB_TOOLS_DIR"
else
    # Nincs extra disk — sima könyvtár, de külön alkönyvtár struktúrával
    ssh_run "
        sudo mkdir -p '$GITHUB_TOOLS_DIR'
        sudo chown $SSH_USER:$SSH_USER '$GITHUB_TOOLS_DIR'
        mkdir -p '$GITHUB_TOOLS_DIR'/{ai-tools,pentest,recon,exploit,wordlists}
    "
    echo "      ✓ Könyvtárstruktúra: $GITHUB_TOOLS_DIR"
fi

# ── Step 2: Alap csomagok ─────────────────────────────────────────────────────
echo "[2/6] Alap függőségek telepítése..."
ssh_run "
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        git python3 python3-pip python3-venv \
        nmap masscan curl wget jq \
        net-tools iputils-ping dnsutils \
        wireguard-tools tor \
        build-essential libssl-dev libffi-dev \
        tmux htop
"
echo "      ✓ Csomagok telepítve"

# ── Step 3: hexstrike-ai klónozása ────────────────────────────────────────────
echo "[3/6] hexstrike-ai telepítése → $GITHUB_TOOLS_DIR/hexstrike-ai ..."
ssh_run "
    cd '$GITHUB_TOOLS_DIR'
    if [[ -d hexstrike-ai ]]; then
        echo 'Már létezik — frissítés...'
        cd hexstrike-ai && git pull --ff-only && cd ..
    else
        git clone https://github.com/webwizardg99/hexstrike-ai.git
    fi

    # Python venv + deps
    cd hexstrike-ai
    python3 -m venv .venv
    source .venv/bin/activate

    # requirements.txt ha van
    [[ -f requirements.txt ]] && pip install -q -r requirements.txt

    # setup.py / pyproject.toml ha van
    [[ -f setup.py ]]         && pip install -q -e .
    [[ -f pyproject.toml ]]   && pip install -q -e .

    # AI/ML alap deps (ha a repo nem hozza magával)
    pip install -q --upgrade \
        anthropic \
        openai \
        requests \
        httpx \
        rich \
        typer \
        pydantic

    deactivate
    echo 'hexstrike-ai kész'
"
echo "      ✓ hexstrike-ai telepítve + venv aktív"

# ── Step 4: hexstrike-ai wrapper script ──────────────────────────────────────
echo "[3b] hexstrike-ai PATH wrapper..."
ssh_run "
    sudo tee /usr/local/bin/hexstrike > /dev/null << 'WEOF'
#!/bin/bash
# hexstrike-ai launcher
HEXSTRIKE_DIR='$GITHUB_TOOLS_DIR/hexstrike-ai'
source \"\$HEXSTRIKE_DIR/.venv/bin/activate\"
ANTHROPIC_API_KEY=\"\${ANTHROPIC_API_KEY:-}\" \\
SHADOWBRIDGE_URL=\"$DASHBOARD_URL\" \\
python3 \"\$HEXSTRIKE_DIR/\$(ls \"\$HEXSTRIKE_DIR\" | grep -E '^main|^cli|^hexstrike' | head -1)\" \"\$@\"
WEOF
    sudo chmod +x /usr/local/bin/hexstrike
"
echo "      ✓ hexstrike parancs: /usr/local/bin/hexstrike"

# ── Step 5: Ollama + AI modellek ──────────────────────────────────────────────
echo "[4/6] Ollama telepítése + AI modellek..."
ssh_run "
    # Telepítés ha nincs
    if ! command -v ollama &>/dev/null; then
        curl -fsSL https://ollama.ai/install.sh | sh
        sleep 3
    fi

    # Háttérben indul
    systemctl enable --now ollama 2>/dev/null || nohup ollama serve &>/tmp/ollama.log &
    sleep 5

    # Attack node modelljei
    echo 'Modellek pull-olása (ez eltarthat egy ideig)...'
    ollama pull nemotron-mini         2>/dev/null || true
    ollama pull qwen2.5:3b            2>/dev/null || true
    ollama pull qwen2.5-coder:7b      2>/dev/null || true

    ollama list
"
echo "      ✓ Ollama + modellek kész"

# ── Step 6: ShadowBridge agent ────────────────────────────────────────────────
echo "[5/6] ShadowBridge agent telepítése..."
ssh_run "
    sudo mkdir -p '$SHADOWBRIDGE_DIR'
    sudo chown $SSH_USER:$SSH_USER '$SHADOWBRIDGE_DIR'
"
scp "$REPO_DIR/shadowbridge_agent.py" \
    "$REPO_DIR/shadowbridge_recon.py" \
    "$SSH_USER@$ATTACK_HOST:$SHADOWBRIDGE_DIR/"

ssh_run "
    cat > '$SHADOWBRIDGE_DIR/.env' << 'ENVEOF'
SHADOWBRIDGE_URL=$DASHBOARD_URL
SHADOWBRIDGE_TOKEN=$AGENT_TOKEN
SHADOWBRIDGE_MACHINE=attack
OLLAMA_URL=http://localhost:11434
POLL_INTERVAL=5
ENVEOF
    chmod 600 '$SHADOWBRIDGE_DIR/.env'

    sudo tee /etc/systemd/system/shadowbridge-agent.service > /dev/null << 'SVCEOF'
[Unit]
Description=ShadowBridge AI Agent (Attack Node)
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
User=$SSH_USER
WorkingDirectory=$SHADOWBRIDGE_DIR
EnvironmentFile=$SHADOWBRIDGE_DIR/.env
ExecStart=/usr/bin/python3 $SHADOWBRIDGE_DIR/shadowbridge_agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now shadowbridge-agent
"
echo "      ✓ ShadowBridge agent fut"

# ── Step 7: ShadowMesh ────────────────────────────────────────────────────────
echo "[6/6] ShadowMesh telepítése..."
ssh_run "sudo mkdir -p '$SHADOWMESH_DIR'"
scp "$REPO_DIR/shadowmesh/shadowmesh_node.py" \
    "$REPO_DIR/shadowmesh/shadowmesh_tor.py"  \
    "$REPO_DIR/shadowmesh/shadowmesh_cli.py"  \
    "$SSH_USER@$ATTACK_HOST:$SHADOWMESH_DIR/"

ssh_run "
    sudo tee /etc/systemd/system/shadowmesh.service > /dev/null << 'MESHSVC'
[Unit]
Description=ShadowMesh Overlay Node (Attack)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SHADOWMESH_DIR
ExecStart=/usr/bin/python3 $SHADOWMESH_DIR/shadowmesh_node.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
MESHSVC
    sudo ln -sf '$SHADOWMESH_DIR/shadowmesh_cli.py' /usr/local/bin/shadowmesh 2>/dev/null || true
    sudo chmod +x '$SHADOWMESH_DIR/shadowmesh_cli.py'
    sudo systemctl daemon-reload
    sudo systemctl enable --now shadowmesh
    sleep 2
    systemctl is-active shadowmesh && echo 'ShadowMesh: aktív' || echo 'ShadowMesh: elindult (check: journalctl -u shadowmesh)'
"
echo "      ✓ ShadowMesh fut"

# ── Összefoglaló ──────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  Attack Node telepítés kész!"
echo ""
echo "  hexstrike-ai : $GITHUB_TOOLS_DIR/hexstrike-ai"
echo "  Parancs      : hexstrike [args]"
echo "  Agent        : systemctl status shadowbridge-agent"
echo "  Mesh         : shadowmesh status"
echo "  Modellek     : ollama list"
echo ""
echo "  GitHub tools könyvtárstruktúra:"
echo "    $GITHUB_TOOLS_DIR/"
echo "    ├── hexstrike-ai/      ← AI hacktools"
echo "    ├── ai-tools/          ← egyéb AI eszközök"
echo "    ├── pentest/           ← pentest frameworkök"
echo "    ├── recon/             ← felderítési eszközök"
echo "    ├── exploit/           ← exploit gyűjtemény"
echo "    └── wordlists/         ← szótárak, listák"
echo ""
echo "  Logok:"
echo "    journalctl -u shadowbridge-agent -f"
echo "    journalctl -u shadowmesh -f"
echo "══════════════════════════════════════════════════════"

#!/bin/bash
# install_attack_node.sh — ShadowLab Attack Node Setup
#
# NOX DASH exkluzív — NEM ShadowBridge, NEM publikus API.
# Az attack node kizárólag a NOX Dashboard-dal kommunikál.
#
# Felállítja:
#   1. /opt/github-tools partíció (opcionális, ha van szabad eszköz)
#   2. hexstrike-ai klónozása + AI függőségek
#   3. ShadowMesh (mesh kapcsolat)
#   4. Ollama + AI modellek
#   5. NOX DASH attack-agent (NEM shadowbridge-agent)
#
# Használat:
#   bash install_attack_node.sh <attack_ip> <nox_token> [--disk /dev/sdb]
#
# Példa:
#   bash install_attack_node.sh 192.168.1.77 nox_attack_token --disk /dev/sdb

set -euo pipefail

ATTACK_HOST="${1:?Használat: $0 <host> <nox_token> [--disk /dev/sdX]}"
NOX_TOKEN="${2:?Hiányzó NOX token}"
EXTRA_DISK=""
NOX_DASH_URL="${NOX_DASH_URL:-http://100.75.31.41:8888}"
SSH_USER="${SSH_USER:-wizardg}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

GITHUB_TOOLS_DIR="/opt/github-tools"
SHADOWMESH_DIR="/opt/shadowmesh"
ATTACK_AGENT_DIR="/opt/nox-attack"

# Parse optional args
shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk) EXTRA_DISK="$2"; shift 2 ;;
        *) echo "Ismeretlen arg: $1"; exit 1 ;;
    esac
done

echo "══════════════════════════════════════════════════════"
echo "  ShadowLab Attack Node — NOX DASH Exkluzív"
echo "  Host     : $ATTACK_HOST ($SSH_USER)"
echo "  NOX Dash : $NOX_DASH_URL"
echo "  Disk     : ${EXTRA_DISK:-nincs (könyvtár mód)}"
echo "  ⚠  ShadowBridge: KIZÁRVA (NOX only)"
echo "══════════════════════════════════════════════════════"
echo ""

ssh_run() {
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$ATTACK_HOST" "$@"
}

# ── Step 1: GitHub-tools partíció ─────────────────────────────────────────────
echo "[1/5] GitHub-tools partíció..."

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
        sudo chown '$SSH_USER:$SSH_USER' '$GITHUB_TOOLS_DIR'
    "
    echo "      ✓ Külön partíció: $GITHUB_TOOLS_DIR"
else
    ssh_run "
        sudo mkdir -p '$GITHUB_TOOLS_DIR'/{hexstrike-ai,ai-tools,pentest,recon,exploit,wordlists}
        sudo chown -R '$SSH_USER:$SSH_USER' '$GITHUB_TOOLS_DIR'
    "
    echo "      ✓ Könyvtárstruktúra: $GITHUB_TOOLS_DIR"
fi

# ── Step 2: Alap csomagok ─────────────────────────────────────────────────────
echo "[2/5] Függőségek..."
ssh_run "
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        git python3 python3-pip python3-venv \
        nmap masscan curl wget jq \
        net-tools iputils-ping dnsutils \
        wireguard-tools tor \
        build-essential libssl-dev libffi-dev \
        tmux htop 2>&1 | tail -3
"
echo "      ✓ Csomagok kész"

# ── Step 3: hexstrike-ai ──────────────────────────────────────────────────────
echo "[3/5] hexstrike-ai telepítése..."
ssh_run "
    DEST='$GITHUB_TOOLS_DIR/hexstrike-ai'
    if [[ -d \"\$DEST\" ]]; then
        git -C \"\$DEST\" pull --ff-only
    else
        git clone https://github.com/webwizardg99/hexstrike-ai.git \"\$DEST\"
    fi

    cd \"\$DEST\"
    python3 -m venv .venv
    source .venv/bin/activate
    [[ -f requirements.txt ]]  && pip install -q -r requirements.txt || true
    [[ -f setup.py ]]          && pip install -q -e . || true
    [[ -f pyproject.toml ]]    && pip install -q -e . || true
    pip install -q anthropic openai requests httpx rich typer pydantic || true
    deactivate

    # Globális wrapper
    sudo tee /usr/local/bin/hexstrike > /dev/null << 'WEOF'
#!/bin/bash
DIR=\"$GITHUB_TOOLS_DIR/hexstrike-ai\"
source \"\$DIR/.venv/bin/activate\"
ENTRY=\$(ls \"\$DIR\" | grep -E '^main|^cli|^hexstrike|^__main__' | head -1)
python3 \"\$DIR/\$ENTRY\" \"\$@\"
WEOF
    sudo chmod +x /usr/local/bin/hexstrike
    echo 'hexstrike-ai kész'
"
echo "      ✓ hexstrike-ai → /usr/local/bin/hexstrike"

# ── Step 4: Ollama + modellek ─────────────────────────────────────────────────
echo "[4/5] Ollama + AI modellek..."
ssh_run "
    if ! command -v ollama &>/dev/null; then
        curl -fsSL https://ollama.ai/install.sh | sh
        sleep 3
    fi
    systemctl enable --now ollama 2>/dev/null || nohup ollama serve &>/tmp/ollama.log &
    sleep 5
    ollama pull nemotron-mini      2>/dev/null || true
    ollama pull qwen2.5:3b         2>/dev/null || true
    ollama pull qwen2.5-coder:7b   2>/dev/null || true
    ollama list
"
echo "      ✓ Ollama kész"

# ── Step 5: NOX Attack Agent (NEM ShadowBridge) ───────────────────────────────
echo "[5/5] NOX Attack Agent telepítése..."
ssh_run "sudo mkdir -p '$ATTACK_AGENT_DIR' && sudo chown '$SSH_USER:$SSH_USER' '$ATTACK_AGENT_DIR'"

scp "$REPO_DIR/deploy/nox_attack_agent.py" "$SSH_USER@$ATTACK_HOST:$ATTACK_AGENT_DIR/" 2>/dev/null || \
ssh_run "cat > '$ATTACK_AGENT_DIR/nox_attack_agent.py'" < "$REPO_DIR/deploy/nox_attack_agent.py" 2>/dev/null || true

ssh_run "
    cat > '$ATTACK_AGENT_DIR/.env' << 'ENVEOF'
NOX_DASH_URL=$NOX_DASH_URL
NOX_ATTACK_TOKEN=$NOX_TOKEN
GITHUB_TOOLS_DIR=$GITHUB_TOOLS_DIR
OLLAMA_URL=http://localhost:11434
ATTACK_MACHINE=attack
ENVEOF
    chmod 600 '$ATTACK_AGENT_DIR/.env'

    sudo tee /etc/systemd/system/nox-attack-agent.service > /dev/null << 'SVCEOF'
[Unit]
Description=NOX Dashboard Attack Agent (Exclusive)
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
User=$SSH_USER
WorkingDirectory=$ATTACK_AGENT_DIR
EnvironmentFile=$ATTACK_AGENT_DIR/.env
ExecStart=/usr/bin/python3 $ATTACK_AGENT_DIR/nox_attack_agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
    sudo systemctl daemon-reload
    sudo systemctl enable nox-attack-agent
"
echo "      ✓ NOX Attack Agent konfigurálva"

# ── ShadowMesh (mesh-re igen, ShadowBridge-re nem) ────────────────────────────
echo "[ + ] ShadowMesh..."
ssh_run "sudo mkdir -p '$SHADOWMESH_DIR'"
scp "$REPO_DIR/shadowmesh/shadowmesh_node.py" \
    "$REPO_DIR/shadowmesh/shadowmesh_tor.py"  \
    "$REPO_DIR/shadowmesh/shadowmesh_cli.py"  \
    "$SSH_USER@$ATTACK_HOST:$SHADOWMESH_DIR/"
ssh_run "
    sudo tee /etc/systemd/system/shadowmesh.service > /dev/null << 'MESHSVC'
[Unit]
Description=ShadowMesh Overlay Node
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
"
echo "      ✓ ShadowMesh fut"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  Attack Node kész — NOX DASH exkluzív"
echo ""
echo "  hexstrike-ai : $GITHUB_TOOLS_DIR/hexstrike-ai"
echo "  Parancs      : hexstrike [args]"
echo "  NOX Agent    : systemctl status nox-attack-agent"
echo "  Mesh         : shadowmesh status"
echo "  ⚡ ShadowBridge: NEM telepítve (szándékosan)"
echo ""
echo "  A NOX Dashboardon az Attack panel:"
echo "  http://$NOX_DASH_URL/attack"
echo "══════════════════════════════════════════════════════"

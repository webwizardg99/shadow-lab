#!/bin/bash
# ShadowBridge Agent Installer
# Usage: bash install_agent.sh <target_host> <machine_name> <agent_token>
# Example: bash install_agent.sh 192.168.1.50 monitoring mytoken123
# Requires: SSH access to target (key-based or password)

set -euo pipefail

TARGET_HOST="${1:?Usage: $0 <host> <machine_name> <token>}"
MACHINE_NAME="${2:?Usage: $0 <host> <machine_name> <token>}"
AGENT_TOKEN="${3:?Usage: $0 <host> <machine_name> <token>}"
DASHBOARD_URL="${4:-http://100.75.31.41:8888}"
SSH_USER="${SSH_USER:-wizardg}"
INSTALL_DIR="/opt/shadowbridge"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC="$SCRIPT_DIR/../shadowbridge_agent.py"

echo "=== ShadowBridge Agent Installer ==="
echo "Target:   $TARGET_HOST ($MACHINE_NAME)"
echo "Dashboard: $DASHBOARD_URL"
echo ""

# 1. Create install directory on target
echo "[1/5] Creating $INSTALL_DIR on $TARGET_HOST..."
ssh "$SSH_USER@$TARGET_HOST" "sudo mkdir -p $INSTALL_DIR && sudo chown $SSH_USER:$SSH_USER $INSTALL_DIR"

# 2. Copy agent script
echo "[2/5] Copying agent script..."
scp "$AGENT_SRC" "$SSH_USER@$TARGET_HOST:$INSTALL_DIR/shadowbridge_agent.py"

# 3. Write env config
echo "[3/5] Writing configuration..."
ssh "$SSH_USER@$TARGET_HOST" "cat > $INSTALL_DIR/.env << 'ENVEOF'
SHADOWBRIDGE_URL=$DASHBOARD_URL
SHADOWBRIDGE_TOKEN=$AGENT_TOKEN
SHADOWBRIDGE_MACHINE=$MACHINE_NAME
OLLAMA_URL=http://localhost:11434
POLL_INTERVAL=5
ENVEOF
chmod 600 $INSTALL_DIR/.env"

# 4. Install systemd service
echo "[4/5] Installing systemd service..."
ssh "$SSH_USER@$TARGET_HOST" "sudo tee /etc/systemd/system/shadowbridge-agent.service > /dev/null << 'SVCEOF'
[Unit]
Description=ShadowBridge AI Agent
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
User=$SSH_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/shadowbridge_agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
sudo systemctl daemon-reload
sudo systemctl enable shadowbridge-agent
sudo systemctl restart shadowbridge-agent"

# 5. Verify
echo "[5/5] Verifying..."
sleep 3
STATUS=$(ssh "$SSH_USER@$TARGET_HOST" "systemctl is-active shadowbridge-agent 2>/dev/null || echo failed")

if [ "$STATUS" = "active" ]; then
    echo ""
    echo "✅ Agent running on $MACHINE_NAME ($TARGET_HOST)"
    echo "   Check logs: ssh $SSH_USER@$TARGET_HOST 'journalctl -u shadowbridge-agent -f'"
else
    echo ""
    echo "⚠️  Agent status: $STATUS"
    echo "   Check: ssh $SSH_USER@$TARGET_HOST 'journalctl -u shadowbridge-agent -n 20'"
fi

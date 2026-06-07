#!/bin/bash
# install_shadowmesh.sh — deploy ShadowMesh node on a remote host via SSH
# Usage: bash install_shadowmesh.sh <host> [--no-tor] [--no-wg]
set -euo pipefail

HOST="${1:?Usage: $0 <host> [--no-tor] [--no-wg]}"
EXTRA_ARGS="${@:2}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_DIR="/opt/shadowmesh"
SERVICE="/etc/systemd/system/shadowmesh.service"

echo "==> Deploying ShadowMesh to $HOST"

ssh "$HOST" "mkdir -p $REMOTE_DIR"

scp "$REPO_DIR/shadowmesh/shadowmesh_node.py" \
    "$REPO_DIR/shadowmesh/shadowmesh_tor.py"  \
    "$REPO_DIR/shadowmesh/shadowmesh_cli.py"  \
    "$HOST:$REMOTE_DIR/"

# Write systemd service with optional extra args
ssh "$HOST" "cat > $SERVICE" <<EOF
[Unit]
Description=ShadowMesh Overlay Network Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$REMOTE_DIR
ExecStart=/usr/bin/python3 $REMOTE_DIR/shadowmesh_node.py $EXTRA_ARGS
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

ssh "$HOST" "
  ln -sf $REMOTE_DIR/shadowmesh_cli.py /usr/local/bin/shadowmesh 2>/dev/null || true
  chmod +x $REMOTE_DIR/shadowmesh_cli.py
  systemctl daemon-reload
  systemctl enable --now shadowmesh
  sleep 2
  systemctl status shadowmesh --no-pager
"

echo "==> Done. Check status: ssh $HOST shadowmesh status"

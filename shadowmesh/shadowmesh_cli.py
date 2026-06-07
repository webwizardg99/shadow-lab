#!/usr/bin/env python3
"""
shadowmesh — CLI tool for managing and inspecting a ShadowMesh node.

Usage:
  shadowmesh status          Show this node's status and peer list
  shadowmesh peers           List all known peers
  shadowmesh ping <node_id>  Send a gossip ping to a specific peer
  shadowmesh tor             Show Tor bridge status
  shadowmesh keygen          Generate a new WireGuard keypair (prints to stdout)
  shadowmesh start           Start the ShadowMesh daemon in the foreground
  shadowmesh version         Print version info

Environment variables override defaults (same as shadowmesh_node.py):
  SHADOWMESH_STATE    Path to state.json  (default /etc/shadowmesh/state.json)
  SHADOWMESH_WG_KEY   Path to wg.key      (default /etc/shadowmesh/wg.key)
  SHADOWMESH_ID       Path to node_id     (default /etc/shadowmesh/node_id)
  SHADOWMESH_TOR_DIR  Path to tor dir     (default /etc/shadowmesh/tor)
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

STATUS_URL = os.environ.get("SHADOWMESH_STATUS_URL", "http://127.0.0.1:51822/status")
VERSION    = "0.1.0"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_status() -> dict:
    try:
        with urllib.request.urlopen(STATUS_URL, timeout=3) as r:
            return json.loads(r.read())
    except urllib.error.URLError:
        return {"error": "ShadowMesh daemon not running (cannot reach status API)"}
    except Exception as e:
        return {"error": str(e)}


def _fmt_time(ts: float) -> str:
    if not ts:
        return "never"
    diff = time.time() - ts
    if diff < 60:
        return f"{int(diff)}s ago"
    if diff < 3600:
        return f"{int(diff/60)}m ago"
    return f"{int(diff/3600)}h ago"


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _ok(t):   return _color(t, "32")
def _warn(t): return _color(t, "33")
def _bad(t):  return _color(t, "31")
def _bold(t): return _color(t, "1")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_status(args):
    data = _get_status()
    if "error" in data:
        print(_bad(f"ERROR: {data['error']}"))
        return 1

    node = data.get("node", {})
    print(_bold("ShadowMesh Node Status"))
    print(f"  Node ID      : {node.get('node_id', '?')}")
    print(f"  Hostname     : {node.get('hostname', socket.gethostname())}")
    print(f"  Overlay IP   : {_ok(node.get('overlay_ip', '?'))}")
    print(f"  WireGuard    : {node.get('wg_pubkey', 'n/a')[:24]}…")
    print(f"  Tor .onion   : {node.get('onion', _warn('not configured'))}")
    print(f"  Peers        : {len(data.get('peers', {}))}")

    tor = data.get("tor", {})
    if tor:
        tor_ready = tor.get("ready", False)
        tor_label = _ok("ready") if tor_ready else _warn("not ready")
        print(f"  Tor bridge   : {tor_label} — {tor.get('onion', 'n/a')}")

    return 0


def cmd_peers(args):
    data = _get_status()
    if "error" in data:
        print(_bad(f"ERROR: {data['error']}"))
        return 1

    peers = data.get("peers", {})
    if not peers:
        print(_warn("No peers known yet."))
        return 0

    print(_bold(f"{'NODE ID':>16}  {'HOSTNAME':<18}  {'OVERLAY IP':<14}  {'LAST SEEN':<12}  ENDPOINTS"))
    print("─" * 90)
    now = time.time()
    for nid, p in peers.items():
        last = _fmt_time(p.get("last_seen", 0))
        age  = now - p.get("last_seen", now)
        seen_label = _ok(last) if age < 60 else (_warn(last) if age < 300 else _bad(last))
        eps = ", ".join(p.get("endpoints", []))
        print(
            f"  {nid[:14]:>14}  {p.get('hostname','?'):<18}  "
            f"{_ok(p.get('overlay_ip','?')):<14}  {seen_label:<20}  {eps}"
        )
    return 0


def cmd_ping(args):
    node_id = args.node_id
    data = _get_status()
    if "error" in data:
        print(_bad(f"ERROR: {data['error']}"))
        return 1

    peers = data.get("peers", {})
    # Support partial match
    match = next((p for nid, p in peers.items() if nid.startswith(node_id)), None)
    if not match:
        print(_bad(f"Unknown peer: {node_id}"))
        print(f"Known peers: {', '.join(peers.keys())}")
        return 1

    # Best-effort: try first LAN endpoint
    endpoints = match.get("endpoints", [])
    if not endpoints:
        print(_warn("Peer has no endpoints"))
        return 1

    ep = endpoints[0]
    if ep.startswith("tor:"):
        print(_warn(f"Peer only reachable via Tor: {ep}"))
        return 0

    host, _, port_str = ep.rpartition(":")
    port = int(port_str)
    import socket as _sock
    s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
    t0 = time.monotonic()
    s.sendto(b'{"type":"ping"}', (host, port))
    s.settimeout(2.0)
    try:
        reply, _ = s.recvfrom(256)
        rtt = (time.monotonic() - t0) * 1000
        print(_ok(f"Pong from {ep}: {rtt:.1f} ms"))
    except TimeoutError:
        print(_warn(f"No response from {ep} within 2s"))
    finally:
        s.close()
    return 0


def cmd_tor(args):
    data = _get_status()
    if "error" in data:
        print(_bad(f"ERROR: {data['error']}"))
        return 1

    tor = data.get("tor")
    if not tor:
        print(_warn("Tor bridge info not available from daemon."))
        return 0

    print(_bold("ShadowMesh Tor Bridge"))
    ready = tor.get("ready", False)
    print(f"  Status       : {_ok('ready') if ready else _warn('not ready')}")
    print(f"  .onion       : {tor.get('onion') or _warn('not yet assigned')}")
    print(f"  SOCKS5       : 127.0.0.1:{tor.get('socks_port', 9150)}")
    print(f"  Control port : 127.0.0.1:{tor.get('control_port', 9151)}")
    print(f"  HS port      : {tor.get('hs_port', 51821)}")
    return 0


def cmd_keygen(args):
    try:
        priv = subprocess.check_output(["wg", "genkey"], text=True).strip()
        pub  = subprocess.run(
            ["wg", "pubkey"], input=priv, capture_output=True, text=True
        ).stdout.strip()
        print(f"PRIVATE_KEY={priv}")
        print(f"PUBLIC_KEY={pub}")
    except FileNotFoundError:
        print(_bad("wg (wireguard-tools) not found. Install with: apt install wireguard-tools"))
        return 1
    return 0


def cmd_start(args):
    """Start the ShadowMesh node in foreground."""
    here = Path(__file__).parent
    node_script = here / "shadowmesh_node.py"
    if not node_script.exists():
        print(_bad(f"Not found: {node_script}"))
        return 1

    cmd = [sys.executable, str(node_script)]
    if args.no_wg:
        cmd.append("--no-wg")
    if args.no_tor:
        cmd.append("--no-tor")

    print(f"Starting ShadowMesh: {' '.join(cmd)}")
    try:
        os.execv(sys.executable, cmd)  # replace current process
    except OSError as e:
        print(_bad(f"exec failed: {e}"))
        return 1


def cmd_version(args):
    print(f"shadowmesh {VERSION}")
    return 0


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shadowmesh",
        description="ShadowMesh CLI — manage your mesh node",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("status",  help="Show node status and summary")
    sub.add_parser("peers",   help="List all known peers")
    sub.add_parser("tor",     help="Show Tor bridge status")
    sub.add_parser("keygen",  help="Generate a WireGuard keypair")
    sub.add_parser("version", help="Print version")

    ping_p = sub.add_parser("ping", help="Ping a peer by node_id prefix")
    ping_p.add_argument("node_id", help="Node ID (or prefix) to ping")

    start_p = sub.add_parser("start", help="Start the ShadowMesh daemon")
    start_p.add_argument("--no-wg",  action="store_true", help="Skip WireGuard setup")
    start_p.add_argument("--no-tor", action="store_true", help="Disable Tor bridge")

    return p


COMMANDS = {
    "status":  cmd_status,
    "peers":   cmd_peers,
    "ping":    cmd_ping,
    "tor":     cmd_tor,
    "keygen":  cmd_keygen,
    "start":   cmd_start,
    "version": cmd_version,
}


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    fn = COMMANDS.get(args.command)
    if not fn:
        print(_bad(f"Unknown command: {args.command}"))
        return 1
    return fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())

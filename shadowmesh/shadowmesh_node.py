#!/usr/bin/env python3
"""
ShadowMesh Node — Layer 1 & 2
UDP multicast discovery + WireGuard tunnel management + Gossip protocol

No central server. No internet required for LAN peers.
Peers find each other via multicast, exchange WireGuard pubkeys,
then gossip their peer tables to the rest of the mesh.
"""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger("shadowmesh.node")

# ── Constants ─────────────────────────────────────────────────────────────────
MULTICAST_GROUP  = "239.77.77.77"
MULTICAST_PORT   = 51820
GOSSIP_PORT      = 51821
WG_INTERFACE     = "shadowmesh0"
STATE_FILE       = Path(os.environ.get("SHADOWMESH_STATE", "/etc/shadowmesh/state.json"))
WG_PRIVKEY_FILE  = Path(os.environ.get("SHADOWMESH_WG_KEY", "/etc/shadowmesh/wg.key"))
NODE_ID_FILE     = Path(os.environ.get("SHADOWMESH_ID", "/etc/shadowmesh/node_id"))
MESH_SUBNET      = "10.77.0.0/16"   # ShadowMesh overlay address space
GOSSIP_INTERVAL  = 30               # seconds between gossip broadcasts
PEER_TTL         = 300              # seconds before a peer is considered stale


# ── Peer record ───────────────────────────────────────────────────────────────

@dataclass
class Peer:
    node_id:    str
    hostname:   str
    wg_pubkey:  str
    overlay_ip: str          # 10.77.x.x
    endpoints:  list         # ["192.168.1.5:51820", "tor:abc123.onion:51820"]
    last_seen:  float = field(default_factory=time.time)
    version:    int   = 0    # increments on each update — gossip uses this

    def is_stale(self) -> bool:
        return time.time() - self.last_seen > PEER_TTL

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Peer":
        return Peer(**{k: v for k, v in d.items() if k in Peer.__dataclass_fields__})


# ── WireGuard helpers ─────────────────────────────────────────────────────────

def wg_genkey() -> tuple[str, str]:
    """Generate WireGuard private/public key pair. Returns (privkey, pubkey)."""
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pubkey  = subprocess.check_output(
        ["wg", "pubkey"], input=privkey.encode()
    ).decode().strip()
    return privkey, pubkey


def wg_get_pubkey(privkey: str) -> str:
    return subprocess.check_output(
        ["wg", "pubkey"], input=privkey.encode()
    ).decode().strip()


def _run(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def wg_setup_interface(privkey: str, overlay_ip: str):
    """Create or reconfigure the WireGuard interface."""
    # Remove if exists
    _run(["ip", "link", "del", WG_INTERFACE], check=False)
    _run(["ip", "link", "add", WG_INTERFACE, "type", "wireguard"])
    _run(["ip", "address", "add", f"{overlay_ip}/16", "dev", WG_INTERFACE])

    tmp_key = f"/tmp/sm_wg_{os.getpid()}.key"
    Path(tmp_key).write_text(privkey)
    os.chmod(tmp_key, 0o600)
    try:
        _run(["wg", "set", WG_INTERFACE, "private-key", tmp_key,
              "listen-port", str(MULTICAST_PORT)])
    finally:
        os.unlink(tmp_key)

    _run(["ip", "link", "set", WG_INTERFACE, "up"])
    log.info(f"WireGuard interface {WG_INTERFACE} up at {overlay_ip}")


def wg_add_peer(pubkey: str, endpoint: str, allowed_ip: str):
    _run(["wg", "set", WG_INTERFACE,
          "peer", pubkey,
          "endpoint", endpoint,
          "allowed-ips", f"{allowed_ip}/32",
          "persistent-keepalive", "25"])


def wg_remove_peer(pubkey: str):
    _run(["wg", "set", WG_INTERFACE, "peer", pubkey, "--remove"], check=False)


# ── Overlay IP assignment ─────────────────────────────────────────────────────

def _node_overlay_ip(node_id: str) -> str:
    """Deterministically assign 10.77.x.x from node_id hash."""
    h = hashlib.sha256(node_id.encode()).digest()
    return f"10.77.{h[0]}.{h[1]}"


# ── Discovery (UDP multicast) ─────────────────────────────────────────────────

def _make_announce(node_id: str, hostname: str, pubkey: str,
                   overlay_ip: str, endpoints: list, version: int) -> bytes:
    msg = json.dumps({
        "t":   "announce",
        "id":  node_id,
        "h":   hostname,
        "pk":  pubkey,
        "ov":  overlay_ip,
        "ep":  endpoints,
        "ver": version,
        "ts":  int(time.time()),
    }).encode()
    return msg


def _parse_announce(data: bytes) -> Optional[dict]:
    try:
        msg = json.loads(data.decode())
        if msg.get("t") == "announce":
            return msg
    except Exception:
        pass
    return None


# ── Gossip (TCP) ──────────────────────────────────────────────────────────────

def _make_gossip_payload(peers: Dict[str, Peer]) -> bytes:
    return json.dumps({
        "t": "gossip",
        "peers": [p.to_dict() for p in peers.values() if not p.is_stale()],
    }).encode()


# ── Main Node class ───────────────────────────────────────────────────────────

class ShadowMeshNode:
    def __init__(self, enable_tor: bool = True):
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

        # Node identity
        if NODE_ID_FILE.exists():
            self.node_id = NODE_ID_FILE.read_text().strip()
        else:
            self.node_id = secrets.token_hex(8)
            NODE_ID_FILE.write_text(self.node_id)

        # WireGuard keys
        if WG_PRIVKEY_FILE.exists():
            self.wg_privkey = WG_PRIVKEY_FILE.read_text().strip()
            self.wg_pubkey  = wg_get_pubkey(self.wg_privkey)
        else:
            self.wg_privkey, self.wg_pubkey = wg_genkey()
            WG_PRIVKEY_FILE.write_text(self.wg_privkey)
            os.chmod(WG_PRIVKEY_FILE, 0o600)

        self.hostname   = socket.gethostname()
        self.overlay_ip = _node_overlay_ip(self.node_id)
        self.endpoints: list = []   # populated at runtime
        self.peers: Dict[str, Peer] = {}
        self.version = 0
        self._tor_bridge = None
        self._enable_tor = enable_tor

        self._load_state()
        log.info(f"Node {self.node_id[:8]} | overlay {self.overlay_ip} | pubkey {self.wg_pubkey[:16]}...")

    def _load_state(self):
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text())
                self.version = data.get("version", 0)
                for p in data.get("peers", []):
                    peer = Peer.from_dict(p)
                    if not peer.is_stale():
                        self.peers[peer.node_id] = peer
                log.info(f"Loaded {len(self.peers)} peers from state")
            except Exception as e:
                log.warning(f"State load error: {e}")

    def _save_state(self):
        try:
            STATE_FILE.write_text(json.dumps({
                "node_id":    self.node_id,
                "version":    self.version,
                "overlay_ip": self.overlay_ip,
                "peers": [p.to_dict() for p in self.peers.values()],
            }, indent=2))
        except Exception as e:
            log.warning(f"State save error: {e}")

    def _get_local_endpoints(self) -> list:
        endpoints = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            endpoints.append(f"{local_ip}:{MULTICAST_PORT}")
        except Exception:
            pass
        # Append .onion endpoint if Tor bridge is ready
        if self._tor_bridge and self._tor_bridge.onion_address:
            endpoints.append(f"tor:{self._tor_bridge.onion_address}:{GOSSIP_PORT}")
        return endpoints

    def _update_wg_peers(self):
        for peer in self.peers.values():
            if peer.is_stale():
                wg_remove_peer(peer.wg_pubkey)
                continue
            # Use first non-overlay endpoint
            endpoint = next(
                (ep for ep in peer.endpoints if not ep.startswith("tor:")), None
            )
            if endpoint:
                try:
                    wg_add_peer(peer.wg_pubkey, endpoint, peer.overlay_ip)
                except Exception as e:
                    log.debug(f"wg add peer {peer.node_id[:8]} failed: {e}")

    def _merge_peers(self, incoming: list) -> int:
        merged = 0
        for pd in incoming:
            nid = pd.get("node_id")
            if not nid or nid == self.node_id:
                continue
            existing = self.peers.get(nid)
            if not existing or pd.get("version", 0) > existing.version:
                self.peers[nid] = Peer.from_dict(pd)
                merged += 1
        return merged

    # ── Discovery sender ──────────────────────────────────────────────────────

    async def _multicast_announce(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        while True:
            self.endpoints = self._get_local_endpoints()
            msg = _make_announce(
                self.node_id, self.hostname, self.wg_pubkey,
                self.overlay_ip, self.endpoints, self.version,
            )
            try:
                await loop.run_in_executor(
                    None, lambda: sock.sendto(msg, (MULTICAST_GROUP, MULTICAST_PORT))
                )
                log.debug(f"Announced to multicast group")
            except Exception as e:
                log.debug(f"Multicast send error: {e}")
            await asyncio.sleep(15)

    # ── Discovery listener ────────────────────────────────────────────────────

    async def _multicast_listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MULTICAST_PORT))
        mreq = struct.pack("4sL", socket.inet_aton(MULTICAST_GROUP),
                           socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        log.info(f"Listening on multicast {MULTICAST_GROUP}:{MULTICAST_PORT}")
        while True:
            try:
                data, addr = await loop.run_in_executor(None, lambda: sock.recvfrom(4096))
                msg = _parse_announce(data)
                if msg and msg["id"] != self.node_id:
                    nid = msg["id"]
                    existing = self.peers.get(nid)
                    if not existing or msg["ver"] > existing.version:
                        self.peers[nid] = Peer(
                            node_id=nid, hostname=msg["h"],
                            wg_pubkey=msg["pk"], overlay_ip=msg["ov"],
                            endpoints=msg["ep"], version=msg["ver"],
                        )
                        log.info(f"Discovered peer {msg['h']} ({nid[:8]}) at {addr[0]}")
                        self._update_wg_peers()
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except Exception as e:
                log.debug(f"Multicast recv error: {e}")
                await asyncio.sleep(1)

    # ── Gossip server ─────────────────────────────────────────────────────────

    async def _gossip_serve(self, reader, writer):
        src = writer.get_extra_info("peername")
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=10)
            msg = json.loads(data.decode())
            if msg.get("t") == "gossip":
                merged = self._merge_peers(msg.get("peers", []))
                if merged:
                    log.info(f"Gossip from {src[0]}: merged {merged} new peers")
                    self._update_wg_peers()
                    self._save_state()
                resp = _make_gossip_payload(self.peers)
                writer.write(resp)
                await writer.drain()
        except Exception as e:
            log.debug(f"Gossip serve error from {src}: {e}")
        finally:
            writer.close()

    async def _gossip_broadcast(self):
        """Periodically push our peer table to all known peers."""
        await asyncio.sleep(20)
        while True:
            payload = _make_gossip_payload(self.peers)
            for peer in list(self.peers.values()):
                if peer.is_stale():
                    continue
                endpoint = next(
                    (ep for ep in peer.endpoints if not ep.startswith("tor:")), None
                )
                if not endpoint:
                    continue
                host, _, port = endpoint.rpartition(":")
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, GOSSIP_PORT), timeout=5
                    )
                    writer.write(payload)
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.read(65536), timeout=8)
                    rmsg = json.loads(resp.decode())
                    if rmsg.get("t") == "gossip":
                        merged = self._merge_peers(rmsg.get("peers", []))
                        if merged:
                            log.info(f"Gossip reply from {peer.hostname}: +{merged} peers")
                    writer.close()
                except Exception:
                    # Direct TCP failed — try Tor .onion fallback
                    tor_ep = next(
                        (ep for ep in peer.endpoints if ep.startswith("tor:")), None
                    )
                    if tor_ep and self._tor_bridge and self._tor_bridge.is_ready:
                        _, onion, _ = tor_ep.split(":", 2)
                        try:
                            payload_dict = json.loads(payload.decode())
                            rmsg = await self._tor_bridge.send_gossip_via_tor(
                                onion, payload_dict
                            )
                            if rmsg.get("t") == "gossip":
                                merged = self._merge_peers(rmsg.get("peers", []))
                                if merged:
                                    log.info(f"Tor gossip from {peer.hostname}: +{merged} peers")
                        except Exception as te:
                            log.debug(f"Tor fallback for {peer.hostname} failed: {te}")
            self._save_state()
            await asyncio.sleep(GOSSIP_INTERVAL)

    # ── Status API (local HTTP) ───────────────────────────────────────────────

    async def _status_serve(self, reader, writer):
        try:
            await reader.read(1024)
            tor_info = None
            if self._tor_bridge:
                from shadowmesh_tor import tor_status
                tor_info = tor_status(self._tor_bridge)
            status = {
                "node": {
                    "node_id":    self.node_id,
                    "hostname":   self.hostname,
                    "overlay_ip": self.overlay_ip,
                    "wg_pubkey":  self.wg_pubkey,
                    "endpoints":  self.endpoints,
                    "onion": (
                        self._tor_bridge.onion_address
                        if self._tor_bridge else None
                    ),
                },
                "peers": {
                    p.node_id: p.to_dict()
                    for p in self.peers.values()
                    if not p.is_stale()
                },
                "peer_count": len(self.peers),
                "tor": tor_info,
                "uptime": int(time.time()),
            }
            body = json.dumps(status, indent=2).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    # ── Main run ──────────────────────────────────────────────────────────────

    async def run(self, no_wg: bool = False):
        if not no_wg:
            try:
                wg_setup_interface(self.wg_privkey, self.overlay_ip)
                self._update_wg_peers()
            except Exception as e:
                log.warning(f"WireGuard setup failed (running without tunnel): {e}")

        # Start Tor bridge in background thread (blocking bootstrap)
        if self._enable_tor:
            try:
                from shadowmesh_tor import TorBridge, TorRelayServer
                self._tor_bridge = TorBridge(gossip_port=GOSSIP_PORT)
                loop = asyncio.get_event_loop()
                ok = await loop.run_in_executor(None, self._tor_bridge.start)
                if ok:
                    log.info(f"Tor bridge active: {self._tor_bridge.onion_address}")
                else:
                    log.warning("Tor bridge not available — continuing without it")
                    self._tor_bridge = None
            except ImportError:
                log.warning("shadowmesh_tor not found — Tor bridge disabled")

        gossip_server = await asyncio.start_server(
            self._gossip_serve, "0.0.0.0", GOSSIP_PORT
        )
        status_server = await asyncio.start_server(
            self._status_serve, "127.0.0.1", 51822
        )
        log.info(f"ShadowMesh node running | gossip:{GOSSIP_PORT} | status:51822")

        await asyncio.gather(
            self._multicast_announce(),
            self._multicast_listen(),
            self._gossip_broadcast(),
            gossip_server.serve_forever(),
            status_server.serve_forever(),
        )


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    no_wg  = "--no-wg"  in sys.argv
    no_tor = "--no-tor" in sys.argv
    node = ShadowMeshNode(enable_tor=not no_tor)
    asyncio.run(node.run(no_wg=no_wg))

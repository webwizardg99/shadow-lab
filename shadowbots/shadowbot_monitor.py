#!/usr/bin/env python3
"""
ShadowBot Monitor — Network & Mesh Topology Watcher
Tracks ShadowMesh peer state, detects topology changes, latency anomalies,
new devices on LAN, and reports suspicious behaviour.
"""
import json
import os
import socket
import subprocess
import time
import urllib.request
from collections import deque

from shadowbot_base import ShadowBotBase

MESH_STATUS_URL = os.environ.get("SHADOWMESH_STATUS_URL", "http://127.0.0.1:51822/status")
SCAN_INTERVAL   = 60     # seconds between full LAN scans
LATENCY_SAMPLES = 10     # rolling window for latency baseline
LATENCY_SPIKE   = 3.0    # multiplier above baseline triggers alert


class MonitorBot(ShadowBotBase):
    NAME            = "monitor"
    PREFERRED_MODEL = "lfm2.5:latest"
    TASK_TYPES      = ["network_analysis", "mesh_status", "scan"]
    SYSTEM_PROMPT   = """You are ShadowBot Monitor — a network operations specialist.
You analyse mesh topology, detect anomalies in network behaviour,
and identify suspicious new devices. Be precise and data-driven.
Flag deviations from baseline. Use network engineering terminology."""

    def __init__(self, token: str = ""):
        super().__init__(token)
        self._known_peers: dict = self.memory.get("known_peers", {})
        self._known_lan_hosts: set = set(self.memory.get("known_lan_hosts", []))
        self._latency_history: dict = {}   # node_id → deque of RTTs
        self._last_scan = 0.0

    # ── Autonomous cycle ──────────────────────────────────────────────────────

    def autonomous_cycle(self):
        self._check_mesh()
        self._check_lan_scan()

    def _check_mesh(self):
        try:
            with urllib.request.urlopen(MESH_STATUS_URL, timeout=3) as r:
                status = json.loads(r.read())
        except Exception:
            return

        peers = status.get("peers", {})

        # Detect new peers
        for nid, peer in peers.items():
            if nid not in self._known_peers:
                self.log.info(f"New mesh peer: {peer.get('hostname')} ({nid[:8]})")
                self.alert(
                    f"New ShadowMesh peer joined: {peer.get('hostname')} "
                    f"@ {peer.get('overlay_ip')}",
                    severity="info", alert_type="mesh.peer.joined",
                    data={"node_id": nid, "peer": peer},
                )
                self.memory.log_event("peer_join", peer)

        # Detect lost peers
        for nid in list(self._known_peers):
            if nid not in peers:
                lost = self._known_peers[nid]
                self.log.warning(f"Mesh peer lost: {lost.get('hostname')} ({nid[:8]})")
                self.alert(
                    f"ShadowMesh peer lost: {lost.get('hostname')} — "
                    f"last seen {int(time.time() - lost.get('last_seen', time.time()))}s ago",
                    severity="medium", alert_type="mesh.peer.lost",
                    data={"node_id": nid, "peer": lost},
                )
                self.memory.log_event("peer_loss", lost)

        self._known_peers = dict(peers)
        self.memory.set("known_peers", self._known_peers)

        # Detect Tor bridge going down
        tor = status.get("tor", {})
        if tor and not tor.get("ready") and self.memory.get("tor_was_ready"):
            self.alert("Tor bridge went offline", severity="medium",
                       alert_type="tor.offline")
        if tor:
            self.memory.set("tor_was_ready", tor.get("ready", False))

    def _check_lan_scan(self):
        if time.time() - self._last_scan < SCAN_INTERVAL:
            return
        self._last_scan = time.time()

        hosts = self._arp_scan()
        new_hosts = hosts - self._known_lan_hosts

        if new_hosts and self._known_lan_hosts:
            # Not first run — genuinely new devices
            for host in new_hosts:
                self.log.warning(f"New LAN device: {host}")
                self.alert(
                    f"Unknown device appeared on LAN: {host}",
                    severity="medium", alert_type="lan.new_device",
                    data={"ip": host},
                )
                self.memory.log_event("new_lan_device", {"ip": host, "ts": time.time()})

        # AI analysis if many new devices
        if len(new_hosts) >= 5:
            prompt = (
                f"Detected {len(new_hosts)} new devices on LAN: {list(new_hosts)}\n"
                f"Known baseline has {len(self._known_lan_hosts)} devices.\n"
                "Is this normal (e.g. office arrival) or suspicious (scanning/intrusion)?"
            )
            analysis = self.think(prompt)
            self.alert(analysis[:400], severity="high",
                       alert_type="bot.monitor.lan_surge",
                       data={"new_hosts": list(new_hosts)})

        self._known_lan_hosts = hosts
        self.memory.set("known_lan_hosts", list(hosts))

    def _arp_scan(self) -> set:
        hosts = set()
        try:
            # Try nmap fast ping scan
            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--open", "192.168.0.0/24"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    ip = parts[-1].strip("()")
                    if ip:
                        hosts.add(ip)
        except Exception:
            # Fallback: read ARP cache
            try:
                arp_out = subprocess.check_output(["arp", "-n"], text=True, timeout=5)
                for line in arp_out.splitlines()[1:]:
                    parts = line.split()
                    if parts and parts[0] != "Address":
                        hosts.add(parts[0])
            except Exception:
                pass
        return hosts

    # ── Task handler ──────────────────────────────────────────────────────────

    def handle_task(self, task: dict) -> str:
        ttype  = task.get("type", "")
        prompt = task.get("prompt", "")

        if ttype == "mesh_status":
            peers = self._known_peers
            summary = json.dumps({
                "peer_count": len(peers),
                "peers": {
                    nid[:8]: {
                        "hostname": p.get("hostname"),
                        "overlay":  p.get("overlay_ip"),
                        "last_seen": int(time.time() - p.get("last_seen", time.time())),
                    }
                    for nid, p in peers.items()
                }
            }, indent=2)
            return self.think(f"Current mesh topology:\n{summary}\n\nAnalyze: {prompt}")

        if ttype == "scan":
            hosts = self._arp_scan()
            return self.think(
                f"LAN scan found {len(hosts)} hosts: {list(hosts)}\n"
                f"Known baseline: {len(self._known_lan_hosts)}\n"
                f"Query: {prompt}"
            )

        return self.think(prompt)


if __name__ == "__main__":
    import logging, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    token = sys.argv[1] if len(sys.argv) > 1 else ""
    MonitorBot(token).run()

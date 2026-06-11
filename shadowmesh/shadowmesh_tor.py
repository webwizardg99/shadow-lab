#!/usr/bin/env python3
"""
ShadowMesh Tor Bridge — Layer 3
Provides .onion hidden service endpoints for ShadowMesh peers,
enabling encrypted mesh communication when direct WireGuard paths fail
or when anonymized routing is required.

Features:
  - Tor hidden service exposing the local ShadowMesh gossip port
  - SOCKS5 proxy for outbound .onion peer connections
  - Automatic .onion address integration into peer announcements
  - Bridge relay mode: forward mesh traffic through Tor for remote peers
  - Store-and-forward: buffer messages when Tor circuit is not yet ready

Usage:
  from shadowmesh_tor import TorBridge
  bridge = TorBridge()
  bridge.start()
  onion = bridge.onion_address   # "abc123...xyz.onion"
"""
import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("shadowmesh.tor")

# ── Config ────────────────────────────────────────────────────────────────────
TOR_DATA_DIR     = Path(os.environ.get("SHADOWMESH_TOR_DIR", "/etc/shadowmesh/tor"))
SOCKS_PORT       = int(os.environ.get("SHADOWMESH_SOCKS_PORT", "9150"))
CONTROL_PORT     = int(os.environ.get("SHADOWMESH_CTRL_PORT", "9151"))
HIDDEN_SVC_PORT  = int(os.environ.get("SHADOWMESH_TOR_HSP", "51821"))  # maps to local gossip
TOR_READY_TIMEOUT = 60   # seconds to wait for Tor bootstrap
CIRCUIT_RETRY    = 3


class TorBridge:
    """
    Manages a Tor process providing a .onion hidden service for this ShadowMesh node.

    The hidden service exposes the local gossip port (51821) so remote peers
    can reach this node even when behind NAT or when direct IP contact is unwanted.

    Outbound .onion connections are made via SOCKS5 on localhost:SOCKS_PORT.
    """

    def __init__(self, gossip_port: int = 51821):
        self.gossip_port = gossip_port
        self._tor_proc: Optional[subprocess.Popen] = None
        self._ready = threading.Event()
        self._shutdown = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self.onion_address: Optional[str] = None
        TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Tor config generation ─────────────────────────────────────────────────

    def _write_torrc(self) -> Path:
        hs_dir = TOR_DATA_DIR / "hidden_service"
        hs_dir.mkdir(parents=True, exist_ok=True)
        torrc_path = TOR_DATA_DIR / "torrc"
        torrc_path.write_text(
            f"DataDirectory {TOR_DATA_DIR}\n"
            f"SocksPort 127.0.0.1:{SOCKS_PORT}\n"
            f"ControlPort 127.0.0.1:{CONTROL_PORT}\n"
            f"CookieAuthentication 1\n"
            f"HiddenServiceDir {hs_dir}\n"
            f"HiddenServicePort {HIDDEN_SVC_PORT} 127.0.0.1:{self.gossip_port}\n"
            f"Log notice stdout\n"
        )
        return torrc_path

    def _read_onion_address(self) -> Optional[str]:
        hostname_file = TOR_DATA_DIR / "hidden_service" / "hostname"
        if hostname_file.exists():
            return hostname_file.read_text().strip()
        return None

    # ── Process lifecycle ─────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start Tor and wait for bootstrap. Returns True on success."""
        if not shutil.which("tor"):
            log.warning("tor binary not found — TorBridge disabled")
            return False

        torrc = self._write_torrc()
        log.info(f"Starting Tor with config {torrc}")
        try:
            self._tor_proc = subprocess.Popen(
                ["tor", "-f", str(torrc)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as e:
            log.error(f"Failed to start tor: {e}")
            return False

        self._monitor_thread = threading.Thread(
            target=self._monitor_tor, daemon=True, name="tor-monitor"
        )
        self._monitor_thread.start()

        log.info(f"Waiting up to {TOR_READY_TIMEOUT}s for Tor bootstrap…")
        if not self._ready.wait(timeout=TOR_READY_TIMEOUT):
            log.error("Tor did not bootstrap in time")
            self.stop()
            return False

        self.onion_address = self._read_onion_address()
        if self.onion_address:
            log.info(f"Hidden service ready: {self.onion_address}")
        else:
            log.warning("Could not read .onion hostname file")

        return True

    def stop(self):
        """Terminate the Tor process."""
        self._shutdown.set()
        if self._tor_proc and self._tor_proc.poll() is None:
            log.info("Stopping Tor process")
            self._tor_proc.terminate()
            try:
                self._tor_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._tor_proc.kill()

    def _monitor_tor(self):
        """Read Tor stdout, detect bootstrap completion, log output."""
        if not self._tor_proc or not self._tor_proc.stdout:
            return
        for line in self._tor_proc.stdout:
            line = line.rstrip()
            if line:
                log.debug(f"[tor] {line}")
            if "Bootstrapped 100%" in line:
                log.info("Tor bootstrap complete (100%)")
                self._ready.set()
            if self._shutdown.is_set():
                break

    @property
    def is_ready(self) -> bool:
        return self._ready.is_set()

    # ── Outbound .onion connection via SOCKS5 ─────────────────────────────────

    def open_socks5_connection(self, onion_host: str, port: int, timeout: float = 30.0):
        """
        Open a raw socket connection to <onion_host>:<port> via local SOCKS5 proxy.
        Returns a connected socket or raises ConnectionError.
        """
        if not self.is_ready:
            raise ConnectionError("Tor not ready")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(("127.0.0.1", SOCKS_PORT))
        except OSError as e:
            sock.close()
            raise ConnectionError(f"Cannot connect to SOCKS5 proxy: {e}") from e

        # SOCKS5 handshake — no auth
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if resp != b"\x05\x00":
            sock.close()
            raise ConnectionError(f"SOCKS5 auth negotiation failed: {resp!r}")

        # SOCKS5 CONNECT with DOMAINNAME address type
        host_bytes = onion_host.encode()
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + port.to_bytes(2, "big")
        )
        sock.sendall(request)
        reply = sock.recv(10)
        if len(reply) < 2 or reply[1] != 0x00:
            sock.close()
            code = reply[1] if len(reply) > 1 else -1
            raise ConnectionError(f"SOCKS5 CONNECT failed with code {code}")

        return sock

    # ── Async wrapper ─────────────────────────────────────────────────────────

    async def async_connect(
        self, onion_host: str, port: int, timeout: float = 30.0
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Async version: opens a SOCKS5-proxied TCP stream to an .onion address.
        Returns (reader, writer) for asyncio stream I/O.
        """
        loop = asyncio.get_running_loop()
        raw_sock = await loop.run_in_executor(
            None, lambda: self.open_socks5_connection(onion_host, port, timeout)
        )
        raw_sock.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=raw_sock)
        return reader, writer

    # ── Gossip-over-Tor relay ─────────────────────────────────────────────────

    async def send_gossip_via_tor(self, onion_host: str, payload: dict) -> dict:
        """
        Send a gossip payload to a remote peer's .onion address.
        Returns the peer's response dict, or {"error": "..."} on failure.
        """
        for attempt in range(CIRCUIT_RETRY):
            try:
                reader, writer = await self.async_connect(
                    onion_host, HIDDEN_SVC_PORT, timeout=30.0
                )
                data = json.dumps(payload).encode()
                writer.write(len(data).to_bytes(4, "big") + data)
                await writer.drain()

                size_bytes = await asyncio.wait_for(reader.read(4), timeout=20.0)
                if len(size_bytes) < 4:
                    raise ConnectionError("Incomplete length prefix")
                size = int.from_bytes(size_bytes, "big")
                raw = await asyncio.wait_for(reader.read(size), timeout=20.0)
                writer.close()
                return json.loads(raw)

            except Exception as e:
                log.warning(f"Tor gossip attempt {attempt+1}/{CIRCUIT_RETRY} failed: {e}")
                if attempt < CIRCUIT_RETRY - 1:
                    await asyncio.sleep(2 ** attempt)

        return {"error": f"all {CIRCUIT_RETRY} Tor gossip attempts failed"}


# ── Bridge relay server ───────────────────────────────────────────────────────

class TorRelayServer:
    """
    Listens on the gossip port and routes incoming Tor-proxied connections
    into the local ShadowMesh gossip handler.  This is what the hidden service
    points at — it unwraps the onion layer and feeds messages into the mesh.
    """

    def __init__(self, handle_gossip_fn, port: int = 51821):
        self.handle_gossip_fn = handle_gossip_fn
        self.port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, "127.0.0.1", self.port
        )
        log.info(f"TorRelayServer listening on 127.0.0.1:{self.port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        peer = writer.get_extra_info("peername")
        try:
            size_bytes = await asyncio.wait_for(reader.read(4), timeout=10.0)
            if len(size_bytes) < 4:
                return
            size = int.from_bytes(size_bytes, "big")
            if size > 1_000_000:  # 1 MB sanity limit
                log.warning(f"Oversized gossip payload from {peer}: {size} bytes")
                return
            raw = await asyncio.wait_for(reader.read(size), timeout=15.0)
            payload = json.loads(raw)

            response = await self.handle_gossip_fn(payload)
            resp_data = json.dumps(response).encode()
            writer.write(len(resp_data).to_bytes(4, "big") + resp_data)
            await writer.drain()
        except Exception as e:
            log.debug(f"Relay client {peer} error: {e}")
        finally:
            writer.close()


# ── Status helper ─────────────────────────────────────────────────────────────

def tor_status(bridge: TorBridge) -> dict:
    return {
        "enabled":      bridge._tor_proc is not None,
        "ready":        bridge.is_ready,
        "onion":        bridge.onion_address,
        "socks_port":   SOCKS_PORT,
        "control_port": CONTROL_PORT,
        "hs_port":      HIDDEN_SVC_PORT,
    }


# ── CLI / smoke test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print("ShadowMesh TorBridge — smoke test")
    bridge = TorBridge()
    ok = bridge.start()
    if not ok:
        print("Tor not available or failed to bootstrap. Is tor installed?")
        sys.exit(1)

    print(f"  .onion address : {bridge.onion_address}")
    print(f"  SOCKS5 proxy   : 127.0.0.1:{SOCKS_PORT}")
    print(f"  Control port   : 127.0.0.1:{CONTROL_PORT}")
    print(json.dumps(tor_status(bridge), indent=2))

    print("\nPress Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        bridge.stop()
        print("Stopped.")

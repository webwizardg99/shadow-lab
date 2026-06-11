#!/usr/bin/env python3
"""
ShadowBridge Honeypot
Fake SSH + HTTP services that log and report intrusion attempts.
Home mode: basic SSH trap on port 2222
Corporate mode: SSH + fake SMB banner + fake RDP banner
"""
import asyncio
import json
import logging
import os
import socket
import time
import urllib.request

log = logging.getLogger("shadowbridge-honeypot")

DASHBOARD_URL = os.environ.get("SHADOWBRIDGE_URL", "http://100.75.31.41:8888")
AGENT_TOKEN   = os.environ.get("SHADOWBRIDGE_TOKEN", "")
MACHINE_ID    = os.environ.get("SHADOWBRIDGE_MACHINE", socket.gethostname())

# ── Report helper ─────────────────────────────────────────────────────────────

def _report(event_type: str, src_ip: str, src_port: int,
            service: str, data: dict = None):
    payload = json.dumps({
        "type":    f"honeypot.{event_type}",
        "machine": MACHINE_ID,
        "message": f"Honeypot hit on {service} from {src_ip}:{src_port}",
        "severity": "high",
        "data": {"src_ip": src_ip, "src_port": src_port, "service": service,
                 **(data or {})},
    }).encode()
    req = urllib.request.Request(
        f"{DASHBOARD_URL}/api/sb/alert",
        data=payload,
        headers={"Content-Type": "application/json",
                 "X-Agent-Token": AGENT_TOKEN},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass
    log.warning(f"[HONEYPOT] {service} hit from {src_ip}:{src_port} | {data}")


# ── Fake SSH ──────────────────────────────────────────────────────────────────

FAKE_SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"


async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    src = writer.get_extra_info("peername")
    src_ip, src_port = (src[0], src[1]) if src else ("?", 0)
    try:
        writer.write(FAKE_SSH_BANNER)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=10)
        decoded = data.decode(errors="replace").strip()
        _report("connect", src_ip, src_port, "ssh",
                {"client_banner": decoded[:120]})
    except Exception:
        _report("connect", src_ip, src_port, "ssh", {})
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── Fake HTTP (admin panel lure) ───────────────────────────────────────────────

FAKE_HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Server: Apache/2.4.52 (Ubuntu)\r\n"
    b"Connection: close\r\n\r\n"
    b"<html><head><title>Admin Login</title></head>"
    b"<body><h2>Administration Panel</h2>"
    b"<form method='post'>"
    b"Username: <input name='user'><br>"
    b"Password: <input type='password' name='pass'><br>"
    b"<input type='submit' value='Login'></form></body></html>"
)


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    src = writer.get_extra_info("peername")
    src_ip, src_port = (src[0], src[1]) if src else ("?", 0)
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=10)
        first_line = data.decode(errors="replace").split("\n")[0].strip()
        writer.write(FAKE_HTTP_RESPONSE)
        await writer.drain()
        _report("connect", src_ip, src_port, "http-admin",
                {"request": first_line[:120]})
    except Exception:
        _report("connect", src_ip, src_port, "http-admin", {})
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── Fake SMB banner (corporate mode) ─────────────────────────────────────────

FAKE_SMB_BANNER = (
    b"\x00\x00\x00\x54"          # NetBIOS session header
    b"\xffSMB"                    # SMB magic
    b"\x72"                       # command: negotiate
    b"\x00" * 84
)


async def handle_smb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    src = writer.get_extra_info("peername")
    src_ip, src_port = (src[0], src[1]) if src else ("?", 0)
    try:
        await asyncio.wait_for(reader.read(256), timeout=8)
        writer.write(FAKE_SMB_BANNER)
        await writer.drain()
        _report("connect", src_ip, src_port, "smb", {})
    except Exception:
        _report("connect", src_ip, src_port, "smb", {})
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── Launcher ──────────────────────────────────────────────────────────────────

async def start_honeypots(mode: str = "home"):
    servers = []

    ssh_server = await asyncio.start_server(handle_ssh, "0.0.0.0", 2222)
    servers.append(ssh_server)
    log.info("Honeypot SSH listening on :2222")

    http_server = await asyncio.start_server(handle_http, "0.0.0.0", 8080)
    servers.append(http_server)
    log.info("Honeypot HTTP listening on :8080")

    if mode in ("corporate", "hybrid"):
        smb_server = await asyncio.start_server(handle_smb, "0.0.0.0", 4450)
        servers.append(smb_server)
        log.info("Honeypot SMB (fake) listening on :4450")

    log.info(f"All honeypots active — mode: {mode.upper()}")
    async with asyncio.TaskGroup() as tg:
        for srv in servers:
            tg.create_task(srv.serve_forever())


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    mode = sys.argv[1] if len(sys.argv) > 1 else "home"
    log.info(f"Starting ShadowBridge Honeypot in {mode.upper()} mode")
    asyncio.run(start_honeypots(mode))

#!/usr/bin/env python3
"""Shadow Lab Agent — streams live stats to your Shadow Lab dashboard."""

import argparse
import asyncio
import json
import os
import socket
import sys
import time

try:
    import psutil
except ImportError:
    sys.exit("Missing dependency: pip install psutil")

try:
    import websockets
except ImportError:
    sys.exit("Missing dependency: pip install websockets")


_prev_net = None
_prev_time = None


def collect() -> dict:
    global _prev_net, _prev_time

    # CPU / RAM / Disk
    vm   = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net  = psutil.net_io_counters()
    now  = time.time()

    # Network speed (bytes/s)
    net_rate = {"up": 0.0, "down": 0.0}
    if _prev_net is not None and _prev_time is not None:
        dt = now - _prev_time
        if dt > 0:
            net_rate = {
                "up":   max(0, (net.bytes_sent - _prev_net.bytes_sent) / dt),
                "down": max(0, (net.bytes_recv - _prev_net.bytes_recv) / dt),
            }
    _prev_net  = net
    _prev_time = now

    # Temperatures
    temps: dict = {}
    try:
        for k, v in psutil.sensors_temperatures().items():
            temps[k] = [{"label": s.label or k, "current": round(s.current, 1)} for s in v]
    except Exception:
        pass

    # GPU (nvidia-smi)
    gpu = None
    try:
        import subprocess
        out = subprocess.check_output(
            ["nvidia-smi",
             "--query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total",
             "--format=csv,noheader,nounits"],
            text=True, stderr=subprocess.DEVNULL, timeout=3
        ).strip()
        p = [x.strip() for x in out.split(",")]
        gpu = {"util": int(p[0]), "temp": int(p[1]),
               "mem_used": int(p[2]), "mem_total": int(p[3])}
    except Exception:
        pass

    return {
        "cpu":      psutil.cpu_percent(interval=0.3),
        "ram":      {"percent": vm.percent, "used": vm.used,  "total": vm.total},
        "disk":     {"percent": disk.percent, "used": disk.used, "total": disk.total},
        "net":      {"sent": net.bytes_sent, "recv": net.bytes_recv},
        "net_rate": net_rate,
        "temps":    temps,
        "gpu":      gpu,
        "load":     list(os.getloadavg()),
        "hostname": socket.gethostname(),
        "uptime":   int(time.time() - psutil.boot_time()),
    }


async def run(server: str, token: str, interval: float):
    # Normalise server URL: http(s) → ws(s)
    server = server.rstrip("/")
    if server.startswith("http://"):
        server = "ws://" + server[7:]
    elif server.startswith("https://"):
        server = "wss://" + server[8:]

    url     = f"{server}/ws/agent/{token}"
    backoff = 5

    print(f"Shadow Lab Agent")
    print(f"  Server : {server}")
    print(f"  Token  : {token[:8]}…")
    print(f"  Interval: {interval}s")
    print()

    while True:
        try:
            async with websockets.connect(url, ping_interval=20, open_timeout=10) as ws:
                print("Connected ✓  (Ctrl-C to stop)")
                backoff = 5
                while True:
                    stats = collect()
                    await ws.send(json.dumps(stats))
                    await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped.")
            return
        except Exception as e:
            print(f"Disconnected ({e}) — reconnecting in {backoff}s…")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)


def main():
    parser = argparse.ArgumentParser(
        description="Shadow Lab Agent — streams live stats to your dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent.py --server ws://shadowlab.example.com --token YOUR_TOKEN
  python3 agent.py --server http://localhost:8889 --token YOUR_TOKEN

Environment variables:
  SHADOWLAB_SERVER   Shadow Lab server URL
  SHADOWLAB_TOKEN    Agent token
        """,
    )
    parser.add_argument(
        "--server", "-s",
        default=os.getenv("SHADOWLAB_SERVER", "ws://localhost:8889"),
        help="Shadow Lab server URL (default: ws://localhost:8889)",
    )
    parser.add_argument(
        "--token", "-t",
        default=os.getenv("SHADOWLAB_TOKEN"),
        help="Agent token from the Shadow Lab dashboard",
    )
    parser.add_argument(
        "--interval", "-i",
        type=float, default=2.0,
        help="Stats push interval in seconds (default: 2)",
    )
    args = parser.parse_args()

    if not args.token:
        parser.error("--token is required (or set SHADOWLAB_TOKEN env var)\n"
                     "Get a token from: Shadow Lab → ⚙ Manage → 🔑 Token")

    asyncio.run(run(args.server, args.token, args.interval))


if __name__ == "__main__":
    main()

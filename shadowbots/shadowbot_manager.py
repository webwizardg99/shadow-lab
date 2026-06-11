#!/usr/bin/env python3
"""
ShadowBot Manager — Bot Swarm Launcher & Supervisor
Starts all bots as threads, monitors health, restarts crashed bots.

Usage:
  python3 shadowbot_manager.py              # start all bots
  python3 shadowbot_manager.py sentinel     # start only sentinel
  python3 shadowbot_manager.py --list       # show registered bots
  python3 shadowbot_manager.py --status     # show running status

API (local HTTP on port 51823):
  GET /status   → JSON status of all bots
  GET /sitrep   → Sentinel's latest situation report
  POST /restart/<bot_name>  → restart a specific bot
"""
import json
import logging
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger("shadowbot.manager")

# ── Bot registry ──────────────────────────────────────────────────────────────

BOT_CLASSES = {}

def _load_bots():
    here = Path(__file__).parent
    sys.path.insert(0, str(here))
    try:
        from shadowbot_security import SecurityBot
        from shadowbot_monitor  import MonitorBot
        from shadowbot_sentinel import SentinelBot
        BOT_CLASSES["security"] = SecurityBot
        BOT_CLASSES["monitor"]  = MonitorBot
        BOT_CLASSES["sentinel"] = SentinelBot
    except ImportError as e:
        log.warning(f"Could not import bot: {e}")


# ── Manager ───────────────────────────────────────────────────────────────────

class BotManager:
    def __init__(self, token: str = ""):
        self.token = token
        self._bots: Dict[str, object]           = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._start_times: Dict[str, float]     = {}
        self._crash_counts: Dict[str, int]      = {}
        self._sentinel: Optional[object]         = None

    def start_bot(self, name: str):
        cls = BOT_CLASSES.get(name)
        if not cls:
            log.error(f"Unknown bot: {name}")
            return
        if name in self._threads and self._threads[name].is_alive():
            log.warning(f"{name} already running")
            return

        bot = cls(token=self.token)
        self._bots[name] = bot
        if name == "sentinel":
            self._sentinel = bot

        def _run_with_restart():
            while True:
                try:
                    self._start_times[name] = time.time()
                    bot.run()
                except Exception as e:
                    log.error(f"Bot {name} crashed: {e}")
                self._crash_counts[name] = self._crash_counts.get(name, 0) + 1
                if self._crash_counts[name] > 10:
                    log.critical(f"Bot {name} crashed 10 times — giving up")
                    break
                delay = min(60, 5 * self._crash_counts[name])
                log.info(f"Restarting {name} in {delay}s...")
                time.sleep(delay)

        t = threading.Thread(target=_run_with_restart, name=f"bot-{name}", daemon=True)
        t.start()
        self._threads[name] = t
        log.info(f"Started {name}")

    def start_all(self, names: list = None):
        targets = names or list(BOT_CLASSES.keys())
        # Start worker bots first, Sentinel last (it reads their memory)
        order = [n for n in targets if n != "sentinel"] + \
                ([n for n in targets if n == "sentinel"])
        for name in order:
            self.start_bot(name)
            time.sleep(1)   # stagger starts

    def stop_all(self):
        for bot in self._bots.values():
            try:
                bot.stop()
            except Exception:
                pass

    def status(self) -> dict:
        result = {}
        for name, t in self._threads.items():
            bot = self._bots.get(name)
            result[name] = {
                "running":     t.is_alive(),
                "uptime":      int(time.time() - self._start_times.get(name, time.time())),
                "crashes":     self._crash_counts.get(name, 0),
                "model":       getattr(bot, "PREFERRED_MODEL", "?"),
                "prefer_claude": getattr(bot, "PREFER_CLAUDE", False),
            }
        return result

    def get_sitrep(self) -> dict:
        if self._sentinel:
            return self._sentinel.get_sitrep()
        return {"text": "Sentinel not running", "ts": 0}

    def get_threat_model(self) -> dict:
        if self._sentinel:
            return self._sentinel.get_threat_model()
        return {}

    def wait(self):
        try:
            while True:
                # Log health every 5 min
                for name, t in self._threads.items():
                    if not t.is_alive():
                        log.warning(f"Thread for {name} died")
                time.sleep(300)
        except KeyboardInterrupt:
            log.info("Shutting down bot swarm")
            self.stop_all()


# ── Local status API ──────────────────────────────────────────────────────────

class _StatusHandler(BaseHTTPRequestHandler):
    manager: BotManager = None

    def log_message(self, fmt, *args):
        pass   # silence access log

    def do_GET(self):
        if self.path == "/status":
            body = json.dumps(self.manager.status(), indent=2).encode()
        elif self.path == "/sitrep":
            body = json.dumps(self.manager.get_sitrep(), indent=2).encode()
        elif self.path == "/threats":
            body = json.dumps(self.manager.get_threat_model(), indent=2).encode()
        else:
            self.send_response(404); self.end_headers(); return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.startswith("/restart/"):
            name = self.path.split("/")[-1]
            self.manager.start_bot(name)
            body = json.dumps({"restarted": name}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()


def _start_api_server(manager: BotManager, port: int = 51823):
    _StatusHandler.manager = manager
    server = HTTPServer(("127.0.0.1", port), _StatusHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True, name="bot-api")
    t.start()
    log.info(f"Bot manager API: http://127.0.0.1:{port}/status")


# ── Systemd service writer ─────────────────────────────────────────────────────

def write_systemd_service(path: str = "/etc/systemd/system/shadowbots.service"):
    svc = f"""[Unit]
Description=ShadowBot Swarm
After=network.target shadowbridge-agent.service
Wants=network.target

[Service]
Type=simple
User=wizardg
WorkingDirectory=/opt/shadowbridge
EnvironmentFile=/opt/shadowbridge/.env
ExecStart=/usr/bin/python3 /opt/shadowbridge/shadowbot_manager.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    Path(path).write_text(svc)
    print(f"Service written to {path}")
    print("Enable with: sudo systemctl daemon-reload && sudo systemctl enable --now shadowbots")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    _load_bots()

    parser = argparse.ArgumentParser(description="ShadowBot Manager")
    parser.add_argument("bots", nargs="*", help="Bot names to start (default: all)")
    parser.add_argument("--list",            action="store_true", help="List bots")
    parser.add_argument("--status",          action="store_true", help="Show running status")
    parser.add_argument("--sitrep",          action="store_true", help="Show latest sitrep")
    parser.add_argument("--write-service",   action="store_true", help="Write systemd service")
    parser.add_argument("--no-api",          action="store_true", help="Disable status API")
    parser.add_argument("--token",           default=os.environ.get("SHADOWBRIDGE_TOKEN",""),
                        help="Agent token")
    args = parser.parse_args()

    if args.list:
        print("Registered bots:")
        for name, cls in BOT_CLASSES.items():
            print(f"  {name:<12} model={cls.PREFERRED_MODEL}")
        return

    if args.write_service:
        write_systemd_service()
        return

    if args.status:
        try:
            with urllib.request.urlopen("http://127.0.0.1:51823/status", timeout=3) as r:
                data = json.loads(r.read())
            print(json.dumps(data, indent=2))
        except Exception:
            print("Bot manager not running (port 51823 unreachable)")
        return

    if args.sitrep:
        try:
            with urllib.request.urlopen("http://127.0.0.1:51823/sitrep", timeout=3) as r:
                data = json.loads(r.read())
            print(data.get("text", "No sitrep available"))
        except Exception:
            print("Sentinel not running")
        return

    # ── Start bot swarm ───────────────────────────────────────────────────────
    manager = BotManager(token=args.token)

    if not args.no_api:
        _start_api_server(manager)

    targets = args.bots if args.bots else None
    log.info(f"Starting ShadowBot swarm: {targets or 'all'}")
    manager.start_all(targets)
    manager.wait()


if __name__ == "__main__":
    main()

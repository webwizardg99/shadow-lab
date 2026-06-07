#!/usr/bin/env python3
"""
ShadowBot Base Class
All bots inherit from ShadowBotBase which handles:
  - ShadowBridge task queue polling
  - Alert reporting to dashboard
  - Persistent memory (SQLite)
  - Ollama / Claude API model calls
  - Lifecycle (start/stop/heartbeat)
"""
import asyncio
import json
import logging
import os
import sqlite3
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

log = logging.getLogger("shadowbot")

DASHBOARD_URL = os.environ.get("SHADOWBRIDGE_URL", "http://100.75.31.41:8888")
OLLAMA_URL    = os.environ.get("OLLAMA_URL", "http://localhost:11434")
CLAUDE_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MEMORY_DB     = Path(os.environ.get("SHADOWBOT_MEMORY", "/opt/shadowbridge/bot_memory.db"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))


# ── Memory store ──────────────────────────────────────────────────────────────

class BotMemory:
    """Persistent key-value + event log per bot."""

    def __init__(self, bot_name: str):
        MEMORY_DB.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(MEMORY_DB), check_same_thread=False)
        self.bot = bot_name
        self._init()

    def _init(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS bot_kv (
                bot TEXT, key TEXT, value TEXT, updated_at REAL,
                PRIMARY KEY (bot, key)
            );
            CREATE TABLE IF NOT EXISTS bot_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot TEXT, event_type TEXT, data TEXT, ts REAL
            );
            CREATE INDEX IF NOT EXISTS idx_bot_events ON bot_events(bot, ts);
        """)
        self.db.commit()

    def set(self, key: str, value):
        self.db.execute(
            "INSERT OR REPLACE INTO bot_kv VALUES (?,?,?,?)",
            (self.bot, key, json.dumps(value), time.time())
        )
        self.db.commit()

    def get(self, key: str, default=None):
        row = self.db.execute(
            "SELECT value FROM bot_kv WHERE bot=? AND key=?", (self.bot, key)
        ).fetchone()
        return json.loads(row[0]) if row else default

    def log_event(self, event_type: str, data: dict):
        self.db.execute(
            "INSERT INTO bot_events (bot, event_type, data, ts) VALUES (?,?,?,?)",
            (self.bot, event_type, json.dumps(data), time.time())
        )
        self.db.commit()

    def recent_events(self, event_type: str = None, limit: int = 20) -> list:
        if event_type:
            rows = self.db.execute(
                "SELECT event_type, data, ts FROM bot_events "
                "WHERE bot=? AND event_type=? ORDER BY ts DESC LIMIT ?",
                (self.bot, event_type, limit)
            ).fetchall()
        else:
            rows = self.db.execute(
                "SELECT event_type, data, ts FROM bot_events "
                "WHERE bot=? ORDER BY ts DESC LIMIT ?",
                (self.bot, limit)
            ).fetchall()
        return [{"type": r[0], "data": json.loads(r[1]), "ts": r[2]} for r in rows]

    def all_bot_events(self, limit: int = 50) -> list:
        """Read events from ALL bots — for the Sentinel's cross-bot awareness."""
        rows = self.db.execute(
            "SELECT bot, event_type, data, ts FROM bot_events "
            "ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"bot": r[0], "type": r[1], "data": json.loads(r[2]), "ts": r[3]} for r in rows]


# ── LLM interface ─────────────────────────────────────────────────────────────

def _ollama_generate(model: str, prompt: str, system: str = "") -> str:
    payload = json.dumps({
        "model": model, "prompt": prompt,
        "system": system, "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate", data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read()).get("response", "")


def _claude_generate(prompt: str, system: str = "", model: str = "claude-sonnet-4-6") -> str:
    if not CLAUDE_API_KEY:
        raise RuntimeError("No ANTHROPIC_API_KEY set")
    payload = json.dumps({
        "model": model,
        "max_tokens": 4096,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": CLAUDE_API_KEY,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.loads(r.read())
    return data["content"][0]["text"]


def llm_call(prompt: str, system: str = "", prefer_claude: bool = False,
             fallback_model: str = "llama3.1:8b") -> str:
    """Call best available LLM. Claude API first if prefer_claude and key set."""
    if prefer_claude and CLAUDE_API_KEY:
        try:
            return _claude_generate(prompt, system)
        except Exception as e:
            log.warning(f"Claude API failed: {e} — falling back to Ollama")
    return _ollama_generate(fallback_model, prompt, system)


# ── Dashboard API ─────────────────────────────────────────────────────────────

def _api(method: str, path: str, body: dict = None, token: str = "") -> dict:
    url = f"{DASHBOARD_URL}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Agent-Token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


# ── Base Bot ──────────────────────────────────────────────────────────────────

class ShadowBotBase(ABC):
    """
    Abstract base for all ShadowBots.

    Subclasses implement:
      - NAME: str              — unique bot identifier
      - SYSTEM_PROMPT: str     — LLM persona/role definition
      - TASK_TYPES: list[str]  — task types this bot handles
      - handle_task(task)      — process a single task dict
      - autonomous_cycle()     — proactive work between tasks (optional)
    """

    NAME:          str = "base"
    SYSTEM_PROMPT: str = "You are a ShadowBot assistant."
    TASK_TYPES:    list = []
    PREFERRED_MODEL: str = "llama3.1:8b"
    PREFER_CLAUDE: bool = False
    HEARTBEAT_INTERVAL: int = 60   # seconds

    def __init__(self, token: str = ""):
        self.token = token or os.environ.get("SHADOWBRIDGE_TOKEN", "")
        self.memory = BotMemory(self.NAME)
        self.log = logging.getLogger(f"shadowbot.{self.NAME}")
        self._running = False
        self._last_heartbeat = 0.0

    # ── LLM shortcut ──────────────────────────────────────────────────────────

    def think(self, prompt: str, system: str = "") -> str:
        return llm_call(
            prompt,
            system or self.SYSTEM_PROMPT,
            prefer_claude=self.PREFER_CLAUDE,
            fallback_model=self.PREFERRED_MODEL,
        )

    # ── Dashboard helpers ─────────────────────────────────────────────────────

    def alert(self, message: str, severity: str = "info",
              alert_type: str = None, data: dict = None):
        _api("POST", "/api/sb/alert", {
            "type":     alert_type or f"bot.{self.NAME}",
            "severity": severity,
            "machine":  self.NAME,
            "message":  message,
            "data":     data or {},
        }, token=self.token)
        self.memory.log_event("alert", {"msg": message, "sev": severity})

    def create_task(self, task_type: str, prompt: str,
                    target: str = "server", system: str = "") -> str:
        resp = _api("POST", "/api/ai/task", {
            "type": task_type, "prompt": prompt,
            "target": target, "system": system,
        }, token=self.token)
        return resp.get("id", "")

    def get_alerts(self, unacked_only: bool = True) -> list:
        resp = _api("GET", "/api/sb/alerts", token=self.token)
        alerts = resp if isinstance(resp, list) else resp.get("alerts", [])
        if unacked_only:
            alerts = [a for a in alerts if not a.get("acked")]
        return alerts

    def get_recon(self, machine: str = "server") -> dict:
        return _api("GET", f"/api/sb/recon/{machine}", token=self.token)

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _send_heartbeat(self):
        now = time.time()
        if now - self._last_heartbeat < self.HEARTBEAT_INTERVAL:
            return
        _api("POST", "/api/sb/alert", {
            "type": "bot.heartbeat", "severity": "info",
            "machine": self.NAME,
            "message": f"{self.NAME} alive",
            "data": {"uptime": int(now - self.memory.get("start_ts", now))},
        }, token=self.token)
        self._last_heartbeat = now

    # ── Abstract interface ────────────────────────────────────────────────────

    @abstractmethod
    def handle_task(self, task: dict) -> str:
        """Process a task from the queue. Return result string."""

    def autonomous_cycle(self):
        """Called between task polls. Override for proactive behaviour."""

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        self._running = True
        self.memory.set("start_ts", time.time())
        self.log.info(f"{self.NAME} starting (model: {self.PREFERRED_MODEL})")
        self.alert(f"{self.NAME} online", severity="info",
                   alert_type="bot.online")

        while self._running:
            try:
                self._send_heartbeat()
                self.autonomous_cycle()
                self._poll_task()
                time.sleep(POLL_INTERVAL)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.log.error(f"Loop error: {e}")
                time.sleep(POLL_INTERVAL)

        self.log.info(f"{self.NAME} stopped")

    def _poll_task(self):
        resp = _api("GET", f"/api/ai/task/next?machine={self.NAME}",
                    token=self.token)
        task = resp if isinstance(resp, dict) else {}
        if not task.get("id") or task.get("type") not in self.TASK_TYPES:
            return

        tid = task["id"]
        self.log.info(f"Task {tid} [{task.get('type')}]: {task.get('prompt','')[:60]}...")
        _api("PATCH", f"/api/ai/task/{tid}",
             {"status": "running", "machine": self.NAME}, token=self.token)

        try:
            start = time.time()
            result = self.handle_task(task)
            elapsed = round(time.time() - start, 1)
            _api("PATCH", f"/api/ai/task/{tid}", {
                "status": "done", "result": result,
                "model": self.PREFERRED_MODEL, "elapsed": elapsed,
            }, token=self.token)
            self.log.info(f"Task {tid} done in {elapsed}s")
        except Exception as e:
            _api("PATCH", f"/api/ai/task/{tid}",
                 {"status": "error", "result": str(e)}, token=self.token)
            self.log.error(f"Task {tid} failed: {e}")

    def stop(self):
        self._running = False

#!/usr/bin/env python3
"""
NOX Dashboard Attack Agent — Exclusive to NOX DASH
NOT a ShadowBridge component.

Polls NOX Dashboard for attack tasks, executes them via local tools
(hexstrike-ai, Ollama models, nmap/masscan, etc.), and reports results back.

Env vars (from /opt/nox-attack/.env):
  NOX_DASH_URL        — e.g. http://100.75.31.41:8888
  NOX_ATTACK_TOKEN    — authentication token
  GITHUB_TOOLS_DIR    — /opt/github-tools
  OLLAMA_URL          — http://localhost:11434
  ATTACK_MACHINE      — node label (default: attack)
"""
import asyncio
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("nox-attack-agent")

# ── Config ─────────────────────────────────────────────────────────────────────
NOX_DASH_URL     = os.environ["NOX_DASH_URL"].rstrip("/")
NOX_ATTACK_TOKEN = os.environ["NOX_ATTACK_TOKEN"]
GITHUB_TOOLS_DIR = Path(os.environ.get("GITHUB_TOOLS_DIR", "/opt/github-tools"))
OLLAMA_URL       = os.environ.get("OLLAMA_URL", "http://localhost:11434")
ATTACK_MACHINE   = os.environ.get("ATTACK_MACHINE", "attack")

POLL_INTERVAL    = int(os.environ.get("NOX_POLL_INTERVAL", "10"))
HEARTBEAT_EVERY  = int(os.environ.get("NOX_HEARTBEAT_EVERY", "60"))
MAX_OUTPUT_BYTES = 64 * 1024   # 64 KB — truncate large command output

HEADERS = {
    "Authorization": f"Bearer {NOX_ATTACK_TOKEN}",
    "Content-Type":  "application/json",
    "X-Node":        ATTACK_MACHINE,
}

# ── Helpers ────────────────────────────────────────────────────────────────────

def _truncate(text: str, limit: int = MAX_OUTPUT_BYTES) -> str:
    if len(text) > limit:
        return text[:limit] + f"\n… [truncated — {len(text)} bytes total]"
    return text


def _allowed_command(cmd: str) -> bool:
    """
    Allowlist check: only permit known-safe tool prefixes.
    Blocks shell metacharacters to prevent RCE via injected payloads.
    """
    ALLOWED_PREFIXES = (
        "hexstrike", "nmap", "masscan", "curl", "wget",
        "ollama", "python3", "ping", "dig", "nslookup",
        "shadowmesh", "whois", "traceroute",
    )
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return False
    if not parts:
        return False
    binary = Path(parts[0]).name
    return binary in ALLOWED_PREFIXES


async def run_command(cmd: str, timeout: int = 120) -> dict:
    """Run a shell command and return stdout/stderr/returncode."""
    if not _allowed_command(cmd):
        return {"error": f"Command not in allowlist: {cmd!r}", "returncode": -1}

    log.info(f"Running: {cmd}")
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"error": f"Command timed out after {timeout}s", "returncode": -1}

        return {
            "stdout":     _truncate(stdout.decode(errors="replace")),
            "stderr":     _truncate(stderr.decode(errors="replace")),
            "returncode": proc.returncode,
        }
    except Exception as e:
        return {"error": str(e), "returncode": -1}


# ── Inventory helpers ──────────────────────────────────────────────────────────

def _installed_tools() -> list[dict]:
    tools = []
    registry = GITHUB_TOOLS_DIR / ".registry.json"
    if registry.exists():
        try:
            data = json.loads(registry.read_text())
            tools = data.get("tools", [])
        except Exception:
            pass
    return tools


async def _ollama_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        return []


async def build_status() -> dict:
    return {
        "node":          ATTACK_MACHINE,
        "timestamp":     int(time.time()),
        "tools":         _installed_tools(),
        "ollama_models": await _ollama_models(),
        "ollama_url":    OLLAMA_URL,
        "github_tools_dir": str(GITHUB_TOOLS_DIR),
    }


# ── NOX DASH communication ─────────────────────────────────────────────────────

async def heartbeat(client: httpx.AsyncClient) -> None:
    status = await build_status()
    try:
        r = await client.post(
            f"{NOX_DASH_URL}/api/attack/heartbeat",
            json=status,
            headers=HEADERS,
            timeout=10,
        )
        if r.status_code == 200:
            log.debug("Heartbeat OK")
        else:
            log.warning(f"Heartbeat {r.status_code}: {r.text[:200]}")
    except Exception as e:
        log.warning(f"Heartbeat failed: {e}")


async def poll_tasks(client: httpx.AsyncClient) -> list[dict]:
    try:
        r = await client.get(
            f"{NOX_DASH_URL}/api/attack/tasks",
            params={"node": ATTACK_MACHINE, "status": "pending"},
            headers=HEADERS,
            timeout=10,
        )
        if r.status_code == 200:
            return r.json().get("tasks", [])
        log.debug(f"Poll tasks {r.status_code}")
        return []
    except Exception as e:
        log.debug(f"Poll failed: {e}")
        return []


async def report_result(
    client: httpx.AsyncClient, task_id: str, result: dict
) -> None:
    try:
        r = await client.post(
            f"{NOX_DASH_URL}/api/attack/tasks/{task_id}/result",
            json={"node": ATTACK_MACHINE, "result": result},
            headers=HEADERS,
            timeout=10,
        )
        if r.status_code not in (200, 201):
            log.warning(f"Result report {r.status_code}: {r.text[:200]}")
    except Exception as e:
        log.warning(f"Result report failed: {e}")


# ── Task dispatch ──────────────────────────────────────────────────────────────

async def handle_task(client: httpx.AsyncClient, task: dict) -> None:
    task_id   = task.get("id", "?")
    task_type = task.get("type", "")
    payload   = task.get("payload", {})

    log.info(f"Task {task_id} type={task_type}")

    if task_type == "run_command":
        cmd     = payload.get("command", "")
        timeout = int(payload.get("timeout", 120))
        result  = await run_command(cmd, timeout)

    elif task_type == "ollama_query":
        model  = payload.get("model", "nemotron-mini")
        prompt = payload.get("prompt", "")
        result = await ollama_query(model, prompt)

    elif task_type == "hexstrike":
        args   = payload.get("args", "")
        result = await run_command(f"hexstrike {args}", timeout=180)

    elif task_type == "nmap_scan":
        target  = payload.get("target", "")
        options = payload.get("options", "-sV -T4")
        if not target:
            result = {"error": "No target specified"}
        else:
            result = await run_command(f"nmap {options} {shlex.quote(target)}", timeout=300)

    elif task_type == "status":
        result = await build_status()

    else:
        result = {"error": f"Unknown task type: {task_type!r}"}

    await report_result(client, task_id, result)


async def ollama_query(model: str, prompt: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            r.raise_for_status()
            data = r.json()
            return {
                "model":    model,
                "response": _truncate(data.get("response", "")),
                "done":     data.get("done", False),
            }
    except Exception as e:
        return {"error": str(e)}


# ── Main loop ──────────────────────────────────────────────────────────────────

async def main() -> None:
    log.info(f"NOX Attack Agent starting — node={ATTACK_MACHINE}")
    log.info(f"NOX Dashboard: {NOX_DASH_URL}")
    log.info(f"GitHub tools:  {GITHUB_TOOLS_DIR}")

    last_heartbeat = 0.0

    async with httpx.AsyncClient() as client:
        while True:
            now = time.time()

            if now - last_heartbeat >= HEARTBEAT_EVERY:
                await heartbeat(client)
                last_heartbeat = now

            tasks = await poll_tasks(client)
            for task in tasks:
                asyncio.create_task(handle_task(client, task))

            await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped.")
    except KeyError as e:
        log.error(f"Missing required env var: {e}")
        sys.exit(1)

#!/usr/bin/env python3
"""
ShadowBridge AI Agent Daemon
Runs on each node, polls the task queue, executes via local Ollama, returns results.
"""
import json
import os
import sys
import time
import socket
import logging
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("shadowbridge-agent")

# ── Config (override via env) ─────────────────────────────────────────────────
DASHBOARD_URL  = os.environ.get("SHADOWBRIDGE_URL", "http://100.75.31.41:8888")
AGENT_TOKEN    = os.environ.get("SHADOWBRIDGE_TOKEN", "")
OLLAMA_URL     = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MACHINE_ID     = os.environ.get("SHADOWBRIDGE_MACHINE", socket.gethostname())
POLL_INTERVAL  = int(os.environ.get("POLL_INTERVAL", "5"))

# ── Model preference per machine (fallback chain) ─────────────────────────────
MODEL_PREFERENCES = {
    "server":     ["qwen2.5-coder:latest", "llama3.1:8b", "webwizardg99/wizz:latest"],
    "assistant":  ["qwen2.5:3b"],
    "monitoring": ["lfm2.5:latest"],
    "attack":     ["nemotron-3-ultra:cloud", "qwen2.5:3b"],
}

TASK_TYPE_MODEL = {
    "code":      "qwen2.5-coder:latest",
    "reasoning": "lfm2.5:latest",
    "security":  "nemotron-3-ultra:cloud",
    "fast":      "qwen2.5:3b",
    "general":   "llama3.1:8b",
}


def _ollama_models() -> list:
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as r:
            return [m["name"] for m in json.loads(r.read())["models"]]
    except Exception:
        return []


def _pick_model(task_type: str) -> str:
    available = _ollama_models()
    preferred = TASK_TYPE_MODEL.get(task_type)
    if preferred and preferred in available:
        return preferred
    hostname = socket.gethostname()
    for m in MODEL_PREFERENCES.get(hostname, []):
        if m in available:
            return m
    return available[0] if available else ""


def _ollama_generate(model: str, prompt: str, system: str = "") -> str:
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "system": system or "You are ShadowBridge, an expert cybersecurity and full-stack engineer.",
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read()).get("response", "")


def _api(method: str, path: str, body: dict = None) -> dict:
    url = f"{DASHBOARD_URL}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Token": AGENT_TOKEN,
        "X-Machine-ID": MACHINE_ID,
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def poll_and_execute():
    log.info(f"ShadowBridge Agent starting on {MACHINE_ID}")
    available = _ollama_models()
    log.info(f"Available models: {available}")
    if not available:
        log.error("No Ollama models found — is Ollama running?")
        sys.exit(1)

    while True:
        try:
            task = _api("GET", f"/api/ai/task/next?machine={MACHINE_ID}")
            if "error" in task or not task.get("id"):
                time.sleep(POLL_INTERVAL)
                continue

            tid  = task["id"]
            ttype = task.get("type", "general")
            prompt = task.get("prompt", "")
            system = task.get("system", "")

            log.info(f"Task {tid} [{ttype}]: {prompt[:80]}...")
            _api("PATCH", f"/api/ai/task/{tid}", {"status": "running", "machine": MACHINE_ID})

            model = _pick_model(ttype)
            log.info(f"Using model: {model}")

            start = time.time()
            result = _ollama_generate(model, prompt, system)
            elapsed = round(time.time() - start, 1)

            _api("PATCH", f"/api/ai/task/{tid}", {
                "status": "done",
                "result": result,
                "model": model,
                "elapsed": elapsed,
            })
            log.info(f"Task {tid} done in {elapsed}s")

        except KeyboardInterrupt:
            log.info("Shutting down.")
            break
        except Exception as e:
            log.error(f"Poll error: {e}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    poll_and_execute()

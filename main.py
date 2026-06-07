import asyncio
import base64
import collections
import io
import json
import os
import re
import shlex
import socket
import stat
import time
import uuid
import urllib.request
import urllib.error
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

import paramiko
import psutil
import subprocess
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form, Body, UploadFile, File
import tempfile
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

import database as db
from shadowbridge_telegram import TelegramDispatcher, send_alert as tg_send_alert

# ── Config ───────────────────────────────────────────────────────────────────
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")
with open(CONFIG_FILE) as f:
    _cfg = json.load(f)

PORT: int               = _cfg.get("port", 8889)
ALERT_THRESHOLDS        = _cfg.get("alerts", {"cpu": 85, "ram": 90, "disk": 90, "temp": 80})
NETWORK_SUBNET: str     = _cfg.get("network_subnet", "192.168.1.0/24")

COOKIE_NAME = "shadowlab_session"

# ── Stats script ─────────────────────────────────────────────────────────────
STATS_SCRIPT = b"""
import psutil, json, subprocess, os, socket, time
temps = {}
try:
    for k, v in psutil.sensors_temperatures().items():
        temps[k] = [{"label": s.label or k, "current": round(s.current, 1)} for s in v]
except Exception:
    pass
gpu = None
try:
    out = subprocess.check_output(
        ["nvidia-smi","--query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total",
         "--format=csv,noheader,nounits"], text=True, stderr=subprocess.DEVNULL).strip()
    p = [x.strip() for x in out.split(",")]
    gpu = {"util": int(p[0]), "temp": int(p[1]), "mem_used": int(p[2]), "mem_total": int(p[3])}
except Exception:
    pass
vm   = psutil.virtual_memory()
disk = psutil.disk_usage("/")
net  = psutil.net_io_counters()
print(json.dumps({
    "cpu":      psutil.cpu_percent(interval=0.5),
    "ram":      {"percent": vm.percent, "used": vm.used, "total": vm.total},
    "disk":     {"percent": disk.percent, "used": disk.used, "total": disk.total},
    "net":      {"sent": net.bytes_sent, "recv": net.bytes_recv},
    "temps":    temps,
    "gpu":      gpu,
    "load":     list(os.getloadavg()),
    "hostname": socket.gethostname(),
    "uptime":   int(time.time() - psutil.boot_time()),
}))
"""

# ── Auth helpers ─────────────────────────────────────────────────────────────

def _get_user(request: Request) -> Optional[Dict]:
    token = request.cookies.get(COOKIE_NAME)
    return db.get_user_by_session(token) if token else None


def _require_pro(user: Optional[Dict]) -> Optional[JSONResponse]:
    if not user or not db.is_pro(user):
        return JSONResponse({"error": "Pro előfizetés szükséges"}, status_code=403)
    return None


# ── Machine adapter ───────────────────────────────────────────────────────────

def _adapt(m: Dict) -> Dict:
    return {
        "id":       m["id"],
        "label":    m["label"],
        "host":     m["host"],
        "user":     m.get("ssh_user", ""),
        "password": m.get("ssh_pass", ""),
        "mac":      m.get("mac", ""),
        "local":    bool(m.get("is_local", 0)),
    }


def _get_machine(machine_id: str, user_id: int) -> Optional[Dict]:
    for m in db.get_machines(user_id):
        if str(m["id"]) == str(machine_id):
            return _adapt(m)
    return None


def _machines_dict(user_id: int) -> Dict[str, Dict]:
    return {str(m["id"]): _adapt(m) for m in db.get_machines(user_id)}


# ── State ─────────────────────────────────────────────────────────────────────
latest_stats: Dict[str, Any] = {}
connected_clients: Dict[WebSocket, int] = {}  # ws -> user_id
_prev_net: Dict[str, Dict] = {}
_prev_time: Dict[str, float] = {}
agent_connected: Set[str] = set()            # machine IDs with active agent WS

# ── Network Watcher ───────────────────────────────────────────────────────────
KNOWN_DEVICES_FILE = os.path.join(os.path.dirname(__file__), "known_devices.json")
device_alerts: collections.deque = collections.deque(maxlen=50)


def _load_known_devices() -> Dict:
    try:
        with open(KNOWN_DEVICES_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_known_devices(devices: Dict) -> None:
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=2)


def _mac_vendor(mac: str) -> str:
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    for path in ("/usr/share/arp-scan/ieee-oui.txt", "/usr/share/nmap/nmap-mac-prefixes"):
        try:
            with open(path) as f:
                for line in f:
                    if line.upper().startswith(oui):
                        return line.split(None, 1)[1].strip()[:50]
        except Exception:
            pass
    return "Unknown"


def _assess_risk(nmap_output: str) -> str:
    high_risk   = {"22", "23", "21", "3389", "5900", "4444", "6666", "1337", "31337"}
    medium_risk = {"80", "443", "8080", "8443", "8888", "7070", "9090"}
    open_ports  = set(re.findall(r'(\d+)/tcp\s+open', nmap_output))
    if open_ports & high_risk:
        return "high"
    if open_ports & medium_risk or len(open_ports) > 3:
        return "medium"
    if open_ports:
        return "low"
    return "low"


async def _quick_device_scan(ip: str):
    try:
        proc = await asyncio.create_subprocess_exec(
            "/usr/bin/nmap", "-F", "-T4", "--open", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = out.decode(errors="replace")
        risk   = _assess_risk(output)
        relevant = [l for l in output.splitlines()
                    if any(k in l for k in ("open", "PORT", "MAC Address", "Host is", "OS:"))]
        return "\n".join(relevant) or "No open ports", risk
    except Exception as e:
        return f"Scan error: {e}", "unknown"


async def _network_watcher_loop():
    known = _load_known_devices()
    await asyncio.sleep(15)
    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "/usr/bin/nmap", "-sn", "-T4", "--host-timeout", "5s", NETWORK_SUBNET,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=35)
            proc2 = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc2.communicate()
            current: Dict[str, str] = {}
            for line in out.decode().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "lladdr":
                    ip  = parts[0]
                    mac = parts[4].upper()
                    if ip.startswith("192.168."):
                        current[mac] = ip
            for mac, ip in current.items():
                if mac not in known:
                    vendor   = _mac_vendor(mac)
                    scan_out, risk = await _quick_device_scan(ip)
                    alert = {
                        "id": uuid.uuid4().hex[:8], "ts": int(time.time()),
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "scan": scan_out, "risk": risk,
                    }
                    device_alerts.append(alert)
                    known[mac] = {"ip": ip, "vendor": vendor,
                                  "first_seen": alert["ts"], "approved": False}
                    _save_known_devices(known)
                    for ws in list(connected_clients):
                        try:
                            await ws.send_json({"_new_device": alert})
                        except Exception:
                            connected_clients.pop(ws, None)
                elif known[mac].get("ip") != ip:
                    known[mac]["ip"] = ip
                    _save_known_devices(known)
        except Exception:
            pass
        await asyncio.sleep(60)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_alerts(stats: Dict) -> list:
    alerts = []
    if stats.get("cpu", 0) >= ALERT_THRESHOLDS.get("cpu", 85):
        alerts.append(f"CPU {stats['cpu']:.0f}%")
    if stats.get("ram", {}).get("percent", 0) >= ALERT_THRESHOLDS.get("ram", 90):
        alerts.append(f"RAM {stats['ram']['percent']:.0f}%")
    if stats.get("disk", {}).get("percent", 0) >= ALERT_THRESHOLDS.get("disk", 90):
        alerts.append(f"DISK {stats['disk']['percent']:.0f}%")
    for readings in stats.get("temps", {}).values():
        for r in readings:
            if r.get("current", 0) >= ALERT_THRESHOLDS.get("temp", 80):
                alerts.append(f"TEMP {r['current']}°C")
                break
    return alerts


def _net_rates(machine_key: str, stats: Dict) -> Dict:
    now = time.time()
    net = stats.get("net", {})
    if machine_key in _prev_net:
        dt = now - _prev_time[machine_key]
        if dt > 0:
            prev = _prev_net[machine_key]
            stats["net_rate"] = {
                "sent": max(0, (net["sent"] - prev["sent"]) / dt),
                "recv": max(0, (net["recv"] - prev["recv"]) / dt),
            }
    _prev_net[machine_key] = net
    _prev_time[machine_key] = now
    return stats


def _local_stats() -> Dict:
    temps: Dict = {}
    try:
        for k, v in psutil.sensors_temperatures().items():
            temps[k] = [{"label": s.label or k, "current": round(s.current, 1)} for s in v]
    except Exception:
        pass
    gpu = None
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=utilization.gpu,temperature.gpu,memory.used,memory.total",
             "--format=csv,noheader,nounits"], text=True, stderr=subprocess.DEVNULL).strip()
        p = [x.strip() for x in out.split(",")]
        gpu = {"util": int(p[0]), "temp": int(p[1]), "mem_used": int(p[2]), "mem_total": int(p[3])}
    except Exception:
        pass
    vm   = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net  = psutil.net_io_counters()
    return {
        "cpu":      psutil.cpu_percent(interval=0.5),
        "ram":      {"percent": vm.percent, "used": vm.used, "total": vm.total},
        "disk":     {"percent": disk.percent, "used": disk.used, "total": disk.total},
        "net":      {"sent": net.bytes_sent, "recv": net.bytes_recv},
        "temps":    temps,
        "gpu":      gpu,
        "load":     list(os.getloadavg()),
        "hostname": socket.gethostname(),
        "uptime":   int(time.time() - psutil.boot_time()),
    }


def _remote_stats(machine: Dict) -> Optional[Dict]:
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(machine["host"], username=machine["user"],
                    password=machine["password"], timeout=5, banner_timeout=5,
                    look_for_keys=False, allow_agent=False)
        stdin, stdout, _ = ssh.exec_command("python3 -", timeout=12)
        stdin.write(STATS_SCRIPT)
        stdin.channel.shutdown_write()
        output = stdout.read().decode()
        ssh.close()
        return json.loads(output)
    except Exception:
        return None


# ── Background collector ───────────────────────────────────────────────────────
async def _collect_loop():
    loop = asyncio.get_event_loop()
    while True:
        all_machines = db.get_all_machines()
        all_stats: Dict[str, Any] = {}

        for machine in all_machines:
            m   = _adapt(machine)
            key = str(m["id"])
            if key in agent_connected:
                continue  # agent is pushing live data directly
            if m.get("local"):
                raw = await loop.run_in_executor(None, _local_stats)
            else:
                raw = await loop.run_in_executor(None, _remote_stats, m)

            if raw:
                raw = _net_rates(key, raw)
                raw["online"] = True
                raw["alerts"] = _check_alerts(raw)
            else:
                raw = {"online": False, "alerts": []}
            all_stats[key] = raw

        latest_stats.clear()
        latest_stats.update(all_stats)

        for ws, user_id in list(connected_clients.items()):
            try:
                user_machine_ids = {str(m["id"]) for m in db.get_machines(user_id)}
                user_stats = {k: v for k, v in all_stats.items() if k in user_machine_ids}
                await ws.send_json(user_stats)
            except Exception:
                connected_clients.pop(ws, None)

        await asyncio.sleep(3)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    db.init_shadowbridge_tables()
    task1 = asyncio.create_task(_collect_loop())
    task2 = asyncio.create_task(_network_watcher_loop())
    _tg_dispatcher = TelegramDispatcher(
        get_config_fn=db.get_telegram_config,
        list_alerts_fn=lambda: db.list_alerts(unacked_only=True),
        ack_fn=db.ack_alert,
    )
    _tg_dispatcher.start()
    yield
    task1.cancel()
    task2.cancel()


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="Shadow Lab", lifespan=lifespan)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _get_user(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
async def login(request: Request, username: str = Form(), password: str = Form()):
    user = db.authenticate(username, password)
    if not user:
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Hibás felhasználónév vagy jelszó"})
    token = db.create_session(user["id"])
    resp  = RedirectResponse("/", status_code=302)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax")
    return resp


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if _get_user(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "register.html", {"error": None})


@app.post("/register")
async def register(request: Request,
                   email: str     = Form(),
                   username: str  = Form(),
                   password: str  = Form(),
                   password2: str = Form()):
    if password != password2:
        return templates.TemplateResponse(request, "register.html",
                                          {"error": "A két jelszó nem egyezik"})
    if len(password) < 8:
        return templates.TemplateResponse(request, "register.html",
                                          {"error": "A jelszó legalább 8 karakter legyen"})
    user = db.register_user(email, username, password)
    if not user:
        return templates.TemplateResponse(request, "register.html",
                                          {"error": "Ez az email vagy felhasználónév már foglalt"})
    token = db.create_session(user["id"])
    resp  = RedirectResponse("/", status_code=302)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax")
    return resp


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        db.delete_session(token)
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = _get_user(request)
    if not user:
        return templates.TemplateResponse(request, "landing.html", {})
    machines = _machines_dict(user["id"])
    return templates.TemplateResponse(request, "index.html", {
        "machines": machines,
        "user":     user,
        "is_pro":   db.is_pro(user),
    })


# ── Machine management ────────────────────────────────────────────────────────

@app.get("/api/machines")
async def list_machines(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    machines = db.get_machines(user["id"])
    return {"machines": [{**_adapt(m), "id": m["id"]} for m in machines]}


@app.post("/api/machines")
async def add_machine_endpoint(request: Request, payload: Dict = Body(...)):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)

    limit = 10 if db.is_pro(user) else 3
    if len(db.get_machines(user["id"])) >= limit:
        return {"error": f"Elérted a géplimitet ({limit}).{' Upgrade szükséges.' if not db.is_pro(user) else ''}"}

    label    = payload.get("label", "").strip()
    host     = payload.get("host", "").strip()
    if not label or not host:
        return {"error": "Label és host megadása kötelező"}

    m = db.add_machine(user["id"], label, host,
                       payload.get("ssh_user", ""),
                       payload.get("ssh_pass", ""),
                       payload.get("mac", ""),
                       bool(payload.get("is_local", False)))
    return {"ok": True, "machine": _adapt(m)}


@app.delete("/api/machines/{machine_id}")
async def delete_machine_endpoint(request: Request, machine_id: int):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    db.delete_machine(user["id"], machine_id)
    return {"ok": True}


@app.patch("/api/machines/{machine_id}")
async def update_machine_endpoint(request: Request, machine_id: int, payload: Dict = Body(...)):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    db.update_machine(user["id"], machine_id, **payload)
    return {"ok": True}


# ── Stats WebSocket ───────────────────────────────────────────────────────────

@app.websocket("/ws/stats")
async def stats_ws(websocket: WebSocket):
    token = websocket.cookies.get(COOKIE_NAME)
    user  = db.get_user_by_session(token) if token else None
    if not user:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    connected_clients[websocket] = user["id"]
    user_machine_ids = {str(m["id"]) for m in db.get_machines(user["id"])}
    if latest_stats:
        await websocket.send_json({k: v for k, v in latest_stats.items()
                                   if k in user_machine_ids})
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        connected_clients.pop(websocket, None)


# ── Agent token generation ────────────────────────────────────────────────────

@app.post("/api/machines/{machine_id}/token")
async def generate_token(request: Request, machine_id: str):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if not _get_machine(machine_id, user["id"]):
        return JSONResponse({"error": "Nem található"}, status_code=404)
    token = db.generate_agent_token(user["id"], int(machine_id))
    return {"token": token}


# ── Agent WebSocket ───────────────────────────────────────────────────────────

@app.websocket("/ws/agent/{token}")
async def agent_ws(websocket: WebSocket, token: str):
    machine_row = db.get_machine_by_agent_token(token)
    if not machine_row:
        await websocket.close(code=4401)
        return
    machine_id = str(machine_row["id"])
    await websocket.accept()
    agent_connected.add(machine_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                raw = json.loads(data)
            except Exception:
                continue
            raw = _net_rates(machine_id, raw)
            raw["online"] = True
            raw["alerts"] = _check_alerts(raw)
            latest_stats[machine_id] = raw
            payload = {machine_id: raw}
            for ws, uid in list(connected_clients.items()):
                if any(str(m["id"]) == machine_id for m in db.get_machines(uid)):
                    try:
                        await ws.send_json(payload)
                    except Exception:
                        connected_clients.pop(ws, None)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        agent_connected.discard(machine_id)
        latest_stats[machine_id] = {"online": False, "alerts": []}
        offline_payload = {machine_id: {"online": False, "alerts": []}}
        for ws, uid in list(connected_clients.items()):
            if any(str(m["id"]) == machine_id for m in db.get_machines(uid)):
                try:
                    await ws.send_json(offline_payload)
                except Exception:
                    connected_clients.pop(ws, None)


# ── Network map ───────────────────────────────────────────────────────────────

@app.get("/api/network")
async def network_map(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)

    MACHINES = _machines_dict(user["id"])

    async def ping_host(host: str) -> float:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "2", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc.communicate()
            if proc.returncode == 0:
                m = re.search(r"time=(\d+\.?\d*)", out.decode())
                return float(m.group(1)) if m else 0.0
        except Exception:
            pass
        return -1.0

    tasks   = {mid: ping_host(m["host"]) for mid, m in MACHINES.items() if not m.get("local")}
    results = {mid: await coro for mid, coro in tasks.items()}

    nodes, edges = [], []
    nodes.append({"id": "gateway", "label": "Gateway\n.1", "group": "gateway"})
    local_mid = next((mid for mid, m in MACHINES.items() if m.get("local")), None)
    if local_mid:
        nodes.append({"id": "local", "label": MACHINES[local_mid]["label"],
                      "group": "local", "latency": 0})
        edges.append({"from": "local", "to": "gateway", "label": "LAN", "dashes": False})

    for mid, machine in MACHINES.items():
        if machine.get("local"):
            continue
        latency = results.get(mid, -1)
        online  = latency >= 0
        nodes.append({"id": mid, "label": f"{machine['label']}\n{machine['host']}",
                      "group": "online" if online else "offline",
                      "latency": round(latency, 1) if online else None})
        edges.append({"from": "gateway", "to": mid, "dashes": False,
                      "label": f"{latency:.1f}ms" if online else "offline"})

    return {"nodes": nodes, "edges": edges, "thresholds": ALERT_THRESHOLDS}


# ── PRO: Remote exec ──────────────────────────────────────────────────────────

@app.post("/api/exec")
async def exec_cmd(request: Request, payload: Dict = Body(...)):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine_id = payload.get("machine", "")
    command    = payload.get("command", "").strip()
    if not command:
        return {"error": "Üres parancs"}

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": f"Ismeretlen gép: {machine_id}"}

    loop = asyncio.get_event_loop()

    if machine.get("local"):
        try:
            proc = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return {"output": out.decode(errors="replace"), "machine": machine_id}
        except asyncio.TimeoutError:
            return {"error": "Timeout (60s)"}
        except Exception as e:
            return {"error": str(e)}

    def _ssh_exec():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(machine["host"], username=machine["user"],
                    password=machine["password"], timeout=10,
                    look_for_keys=False, allow_agent=False)
        _, stdout, stderr = ssh.exec_command(command, timeout=60)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        ssh.close()
        return out + (f"\n[stderr]:\n{err}" if err.strip() else "")

    try:
        result = await asyncio.wait_for(loop.run_in_executor(None, _ssh_exec), timeout=65)
        return {"output": result, "machine": machine_id}
    except asyncio.TimeoutError:
        return {"error": "Timeout (60s)"}
    except Exception as e:
        return {"error": str(e)}


# ── PRO: Screenshot ───────────────────────────────────────────────────────────

@app.get("/api/screenshot/{machine_id}")
async def screenshot(request: Request, machine_id: str):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}

    SCMD = (
        "DISPLAY=:0 scrot -q 65 /tmp/_sl_ss.png 2>/dev/null && echo scrot || "
        "DISPLAY=:0 import -window root -resize 1280x -quality 65 /tmp/_sl_ss.png 2>/dev/null && echo import || "
        "echo FAIL"
    )
    loop = asyncio.get_event_loop()

    if machine.get("local"):
        def _local_ss():
            subprocess.run(SCMD, shell=True, timeout=15)
            with open("/tmp/_sl_ss.png", "rb") as f:
                return f.read()
        try:
            data = await asyncio.wait_for(loop.run_in_executor(None, _local_ss), timeout=20)
            return {"image": "data:image/png;base64," + base64.b64encode(data).decode()}
        except Exception as e:
            return {"error": str(e)}

    def _remote_ss():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(machine["host"], username=machine["user"],
                    password=machine["password"], timeout=10,
                    look_for_keys=False, allow_agent=False)
        _, stdout, _ = ssh.exec_command(SCMD, timeout=20)
        result = stdout.read().decode().strip()
        if "FAIL" in result or result == "":
            ssh.close()
            raise RuntimeError("Screenshot failed")
        buf  = io.BytesIO()
        sftp = ssh.open_sftp()
        sftp.getfo("/tmp/_sl_ss.png", buf)
        sftp.close()
        ssh.close()
        return buf.getvalue()

    try:
        data = await asyncio.wait_for(loop.run_in_executor(None, _remote_ss), timeout=25)
        return {"image": "data:image/png;base64," + base64.b64encode(data).decode()}
    except asyncio.TimeoutError:
        return {"error": "Timeout (25s)"}
    except Exception as e:
        return {"error": str(e)}


# ── PRO: Processes ────────────────────────────────────────────────────────────

PROC_SCRIPT = b"""
import psutil, json, time
procs = []
plist = list(psutil.process_iter(['pid','name','username','status','cmdline','memory_percent']))
for p in plist:
    try: p.cpu_percent()
    except: pass
time.sleep(0.5)
for p in plist:
    try:
        cpu = p.cpu_percent()
        mem = p.memory_percent()
        cmd = ' '.join(p.cmdline()[:6]) if p.cmdline() else p.name()
        procs.append({'pid': p.pid, 'name': p.name(), 'user': p.username() or '?',
                      'cpu': round(cpu,1), 'mem': round(mem,2),
                      'status': p.status(), 'cmd': cmd[:120]})
    except: pass
procs.sort(key=lambda x: (-x['cpu'], -x['mem']))
print(json.dumps(procs[:40]))
"""


@app.get("/api/processes/{machine_id}")
async def get_processes(request: Request, machine_id: str):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}

    loop = asyncio.get_event_loop()

    if machine.get("local"):
        def _local_procs():
            procs, plist = [], list(psutil.process_iter(
                ['pid', 'name', 'username', 'status', 'cmdline', 'memory_percent']))
            for p in plist:
                try: p.cpu_percent()
                except: pass
            time.sleep(0.5)
            for p in plist:
                try:
                    cmd = ' '.join(p.cmdline()[:6]) if p.cmdline() else p.name()
                    procs.append({'pid': p.pid, 'name': p.name(),
                                  'user': p.username() or '?', 'cpu': round(p.cpu_percent(), 1),
                                  'mem': round(p.memory_percent(), 2), 'status': p.status(),
                                  'cmd': cmd[:120]})
                except: pass
            procs.sort(key=lambda x: (-x['cpu'], -x['mem']))
            return procs[:40]
        try:
            result = await asyncio.wait_for(loop.run_in_executor(None, _local_procs), timeout=15)
            return {"processes": result}
        except Exception as e:
            return {"error": str(e)}

    def _remote_procs():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(machine["host"], username=machine["user"],
                    password=machine["password"], timeout=10,
                    look_for_keys=False, allow_agent=False)
        stdin, stdout, _ = ssh.exec_command("python3 -", timeout=20)
        stdin.write(PROC_SCRIPT)
        stdin.channel.shutdown_write()
        out = stdout.read().decode()
        ssh.close()
        return json.loads(out)

    try:
        result = await asyncio.wait_for(loop.run_in_executor(None, _remote_procs), timeout=25)
        return {"processes": result}
    except asyncio.TimeoutError:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


# ── PRO: Kill process ─────────────────────────────────────────────────────────

@app.post("/api/kill")
async def kill_proc(request: Request, payload: Dict = Body(...)):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine_id = payload.get("machine")
    pid        = int(payload.get("pid", 0))
    force      = payload.get("force", False)
    if pid <= 1:
        return {"error": "Rendszerfolyamat nem állítható le"}

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}

    loop = asyncio.get_event_loop()

    if machine.get("local"):
        def _local_kill():
            p = psutil.Process(pid)
            name = p.name()
            p.kill() if force else p.terminate()
            return name
        try:
            name = await loop.run_in_executor(None, _local_kill)
            return {"ok": True, "msg": f"{'Force killed' if force else 'Terminated'}: {name} (PID {pid})"}
        except Exception as e:
            return {"error": str(e)}

    sig = "-9" if force else "-15"

    def _remote_kill():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(machine["host"], username=machine["user"],
                    password=machine["password"], timeout=8,
                    look_for_keys=False, allow_agent=False)
        _, stdout, _ = ssh.exec_command(f"kill {sig} {pid} 2>&1 && echo OK || echo FAIL")
        out = stdout.read().decode().strip()
        ssh.close()
        return out

    try:
        result = await asyncio.wait_for(loop.run_in_executor(None, _remote_kill), timeout=12)
        if "FAIL" in result or "No such" in result:
            return {"error": result}
        return {"ok": True, "msg": f"Leállítva PID {pid} ({'force' if force else 'graceful'})"}
    except Exception as e:
        return {"error": str(e)}


# ── PRO: Logs ─────────────────────────────────────────────────────────────────

@app.get("/api/logs/{machine_id}")
async def get_logs(request: Request, machine_id: str,
                   file: str = "/var/log/syslog", lines: int = 100):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    if file != "journalctl" and not file.startswith("/"):
        return {"error": "Érvénytelen útvonal"}

    lines = max(10, min(lines, 1000))
    cmd = (f"journalctl -n {lines} --no-pager --output=short-iso 2>/dev/null"
           if file == "journalctl"
           else f"tail -n {lines} {shlex.quote(file)} 2>&1")

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}

    loop = asyncio.get_event_loop()

    if machine.get("local"):
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return {"content": out.decode(errors="replace"), "file": file}
        except Exception as e:
            return {"error": str(e)}

    def _remote_log():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(machine["host"], username=machine["user"],
                    password=machine["password"], timeout=8,
                    look_for_keys=False, allow_agent=False)
        _, stdout, _ = ssh.exec_command(cmd, timeout=15)
        out = stdout.read().decode(errors="replace")
        ssh.close()
        return out

    try:
        content = await asyncio.wait_for(loop.run_in_executor(None, _remote_log), timeout=20)
        return {"content": content, "file": file}
    except asyncio.TimeoutError:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


# ── PRO: nmap scan WebSocket ──────────────────────────────────────────────────

SCAN_TYPES: Dict[str, list] = {
    "fast":       ["/usr/bin/nmap", "-F", "--open", "-T4"],
    "top1000":    ["/usr/bin/nmap", "--open", "-T4"],
    "service":    ["/usr/bin/nmap", "-sV", "--open", "-T4"],
    "os":         ["/usr/bin/nmap", "-O", "--open", "-T4"],
    "aggressive": ["/usr/bin/nmap", "-A", "--open", "-T4"],
    "full":       ["/usr/bin/nmap", "-p-", "--open", "-T4"],
    "ping":       ["/usr/bin/nmap", "-sn", "-T4"],
    "udp":        ["/usr/bin/nmap", "-sU", "--top-ports", "200", "--open", "-T4"],
    "vuln":       ["/usr/bin/nmap", "--script", "vuln", "-T4"],
    "subnet":     ["/usr/bin/nmap", "-sn", "-T4"],
}


@app.websocket("/ws/scan")
async def scan_ws(websocket: WebSocket):
    token = websocket.cookies.get(COOKIE_NAME)
    user  = db.get_user_by_session(token) if token else None
    if not user:
        await websocket.close(code=1008)
        return
    if not db.is_pro(user):
        await websocket.accept()
        await websocket.send_text("❌ Pro előfizetés szükséges\n")
        await websocket.close()
        return
    await websocket.accept()

    proc = None
    try:
        params    = await asyncio.wait_for(websocket.receive_json(), timeout=30)
        target    = params.get("target", "").strip()
        scan_type = params.get("type", "fast")

        if not target or not re.match(r'^[a-zA-Z0-9.\-_/: ]+$', target):
            await websocket.send_text("❌ Érvénytelen cél\n")
            return

        cmd = SCAN_TYPES.get(scan_type, SCAN_TYPES["fast"]) + [target]
        await websocket.send_text(f"[Shadow Lab] $ {' '.join(cmd)}\n\n")

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            await websocket.send_text(line.decode(errors="replace"))
        await proc.wait()
        rc = proc.returncode
        await websocket.send_text(f"\n[Shadow Lab] Done. (exit {rc})\n")
        await websocket.send_json({"done": True, "rc": rc})

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        try:
            await websocket.send_text("❌ Timeout\n")
        except Exception:
            pass
    except Exception as e:
        try:
            await websocket.send_text(f"❌ Hiba: {e}\n")
        except Exception:
            pass
    finally:
        if proc and proc.returncode is None:
            proc.kill()


# ── PRO: SSH terminal ─────────────────────────────────────────────────────────

@app.websocket("/ws/terminal/{machine_id}")
async def terminal_ws(websocket: WebSocket, machine_id: str):
    token = websocket.cookies.get(COOKIE_NAME)
    user  = db.get_user_by_session(token) if token else None
    if not user:
        await websocket.close(code=1008)
        return
    if not db.is_pro(user):
        await websocket.accept()
        await websocket.send_text("\r\n\x1b[31mPro előfizetés szükséges\x1b[0m\r\n")
        await websocket.close()
        return

    machine = _get_machine(machine_id, user["id"])
    if not machine or machine.get("local"):
        await websocket.accept()
        await websocket.close()
        return

    await websocket.accept()
    ssh     = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    channel = None
    try:
        ssh.connect(machine["host"], username=machine["user"],
                    password=machine["password"], timeout=10,
                    look_for_keys=False, allow_agent=False)
        channel = ssh.invoke_shell(term="xterm-256color", width=220, height=50)
        channel.setblocking(False)
        loop = asyncio.get_event_loop()

        async def ssh_to_ws():
            while True:
                try:
                    data = await loop.run_in_executor(
                        None, lambda: channel.recv(4096) if channel.recv_ready() else b"")
                    if data:
                        await websocket.send_bytes(data)
                    else:
                        await asyncio.sleep(0.02)
                    if channel.closed or channel.exit_status_ready():
                        break
                except Exception:
                    break

        async def ws_to_ssh():
            while True:
                try:
                    msg = await websocket.receive()
                    if "bytes" in msg:
                        channel.send(msg["bytes"])
                    elif "text" in msg:
                        data = json.loads(msg["text"])
                        if data.get("type") == "resize":
                            channel.resize_pty(width=data["cols"], height=data["rows"])
                except WebSocketDisconnect:
                    break
                except Exception:
                    break

        await asyncio.gather(ssh_to_ws(), ws_to_ssh())
    except Exception as e:
        try:
            await websocket.send_text(f"\r\n\x1b[31mKapcsolódási hiba: {e}\x1b[0m\r\n")
        except Exception:
            pass
    finally:
        if channel:
            channel.close()
        ssh.close()


# ── PRO: WoL ─────────────────────────────────────────────────────────────────

@app.post("/api/wol/{machine_id}")
async def wake_machine(request: Request, machine_id: str):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}
    mac = machine.get("mac", "")
    if not mac:
        return {"error": "Nincs MAC cím konfigurálva"}
    try:
        mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
        magic = b'\xff' * 6 + mac_bytes * 16
        import ipaddress
        net = ipaddress.IPv4Network(NETWORK_SUBNET, strict=False)
        broadcast = str(net.broadcast_address)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for port in (7, 9):
                for _ in range(3):
                    s.sendto(magic, (broadcast, port))
        return {"ok": True, "mac": mac, "broadcast": broadcast}
    except Exception as e:
        return {"error": str(e)}


# ── PRO: File manager ─────────────────────────────────────────────────────────

@app.get("/api/files/{machine_id}")
async def list_files(request: Request, machine_id: str, path: str = "/home"):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}

    if machine.get("local"):
        try:
            entries = []
            with os.scandir(path) as it:
                for e in sorted(it, key=lambda x: (not x.is_dir(), x.name.lower())):
                    try:
                        s = e.stat()
                        entries.append({"name": e.name, "path": e.path,
                                        "is_dir": e.is_dir(),
                                        "size": s.st_size if not e.is_dir() else 0,
                                        "mtime": int(s.st_mtime)})
                    except Exception:
                        pass
            return {"path": path, "entries": entries}
        except Exception as e:
            return {"error": str(e)}

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(machine["host"], username=machine["user"],
                       password=machine["password"], timeout=8)
        sftp = client.open_sftp()
        entries = []
        for attr in sorted(sftp.listdir_attr(path),
                           key=lambda x: (not stat.S_ISDIR(x.st_mode or 0), x.filename.lower())):
            entries.append({"name": attr.filename,
                            "path": path.rstrip("/") + "/" + attr.filename,
                            "is_dir": stat.S_ISDIR(attr.st_mode or 0),
                            "size": attr.st_size or 0,
                            "mtime": int(attr.st_mtime or 0)})
        sftp.close()
        client.close()
        return {"path": path, "entries": entries}
    except Exception as e:
        return {"error": str(e)}


# ── PRO: Services ─────────────────────────────────────────────────────────────

def _run_on_machine(machine: Dict, cmd: str, timeout: int = 15) -> Dict:
    if machine.get("local"):
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {"output": r.stdout + r.stderr, "ok": r.returncode == 0}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(machine["host"], username=machine["user"],
                       password=machine["password"], timeout=8)
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
        client.close()
        return {"output": out, "ok": True}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/services/{machine_id}")
async def list_services(request: Request, machine_id: str, all: str = "0"):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}

    state_filter = "" if all == "1" else "--state=active,failed"
    cmd = (f"systemctl list-units --type=service --no-pager --no-legend {state_filter} "
           f"| awk '{{print $1,$2,$3,$4}}' | head -80")
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, lambda: _run_on_machine(machine, cmd))
    if "error" in result:
        return result
    services = []
    for line in result["output"].strip().splitlines():
        parts = line.split(None, 3)
        if len(parts) >= 3 and parts[0].endswith(".service"):
            services.append({"name": parts[0].replace(".service", ""),
                             "load": parts[1], "active": parts[2],
                             "sub": parts[3].strip() if len(parts) > 3 else ""})
    return {"services": services}


@app.post("/api/service/{machine_id}")
async def control_service(request: Request, machine_id: str, payload: Dict = Body(...)):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    machine = _get_machine(machine_id, user["id"])
    if not machine:
        return {"error": "Ismeretlen gép"}

    name   = payload.get("name", "").strip().replace(".service", "")
    action = payload.get("action", "").strip()
    if not name or action not in ("start", "stop", "restart", "status"):
        return {"error": "Érvénytelen paraméterek"}

    pw  = machine.get("password", "")
    cmd = f"echo {shlex.quote(pw)} | sudo -S systemctl {action} {name}.service 2>&1; echo EXIT:$?"
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _run_on_machine(machine, cmd, 20))


# ── PRO: Ping matrix ──────────────────────────────────────────────────────────

@app.get("/api/ping-matrix")
async def ping_matrix_endpoint(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    if err := _require_pro(user):
        return err

    MACHINES = _machines_dict(user["id"])

    async def _ping(host: str) -> Optional[float]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "2", host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=4)
            m = re.search(r'time=([\d.]+)', out.decode())
            return float(m.group(1)) if m else None
        except Exception:
            return None

    results = {mid: await _ping(m["host"]) for mid, m in MACHINES.items()}
    return {"results": results, "machines": {mid: m["label"] for mid, m in MACHINES.items()}}


# ── Network watcher API ───────────────────────────────────────────────────────

@app.get("/api/device-alerts")
async def get_device_alerts(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    return {"alerts": list(device_alerts)}


@app.post("/api/device-alerts/clear")
async def clear_device_alerts(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    device_alerts.clear()
    return {"ok": True}


@app.get("/api/known-devices")
async def get_known_devices(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    return {"devices": _load_known_devices()}


@app.post("/api/device-rescan")
async def rescan_device(request: Request, payload: Dict = Body(...)):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    ip = payload.get("ip", "").strip()
    if not re.match(r'^[\d.]+$', ip):
        return {"error": "Érvénytelen IP"}
    scan_out, risk = await _quick_device_scan(ip)
    return {"scan": scan_out, "risk": risk}


# ── Account info ──────────────────────────────────────────────────────────────

@app.get("/api/account")
async def account_info(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    return {
        "username":      user["username"],
        "email":         user["email"],
        "tier":          user["tier"],
        "is_pro":        db.is_pro(user),
        "machine_count": len(db.get_machines(user["id"])),
        "machine_limit": 10 if db.is_pro(user) else 3,
    }


# ── ShadowBridge AI Orchestration ────────────────────────────────────────────

def _auth_agent_or_user(request: Request) -> bool:
    return bool(_get_user(request) or request.headers.get("X-Agent-Token"))


@app.post("/api/ai/task")
async def ai_task_create(request: Request, payload: Dict = Body(...)):
    if not _auth_agent_or_user(request):
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    tid  = uuid.uuid4().hex[:12]
    task = db.create_ai_task(
        tid,
        task_type=payload.get("type", "general"),
        prompt=payload.get("prompt", ""),
        system=payload.get("system", ""),
        target=payload.get("target", "any"),
    )
    return {"id": tid, "status": "pending"}


@app.get("/api/ai/task/next")
async def ai_task_next(request: Request, machine: str = "any"):
    if not request.headers.get("X-Agent-Token"):
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    task = db.next_ai_task(machine)
    return task or {}


@app.get("/api/ai/task/{tid}")
async def ai_task_get(request: Request, tid: str):
    if not _auth_agent_or_user(request):
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    task = db.get_ai_task(tid)
    return task or JSONResponse({"error": "Nem található"}, status_code=404)


@app.patch("/api/ai/task/{tid}")
async def ai_task_update(request: Request, tid: str, payload: Dict = Body(...)):
    if not request.headers.get("X-Agent-Token"):
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    ok = db.update_ai_task(tid, **payload)
    return {"ok": ok} if ok else JSONResponse({"error": "Nem található"}, status_code=404)


@app.get("/api/ai/tasks")
async def ai_task_list(request: Request):
    if not _auth_agent_or_user(request):
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    return {"tasks": db.list_ai_tasks(50)}


# ── ShadowBridge Alerts ───────────────────────────────────────────────────────

@app.post("/api/sb/alert")
async def sb_alert_create(request: Request, payload: Dict = Body(...)):
    if not _auth_agent_or_user(request):
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    alert = db.create_alert(
        alert_type=payload.get("type", "unknown"),
        message=payload.get("message", ""),
        severity=payload.get("severity", "info"),
        machine=payload.get("machine") or request.headers.get("X-Machine-ID"),
        data=payload.get("data"),
    )
    return {"ok": True, "id": alert["id"]}


@app.get("/api/sb/alerts")
async def sb_alert_list(request: Request, unacked: str = "0"):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    return {"alerts": db.list_alerts(100, unacked_only=(unacked == "1"))}


@app.post("/api/sb/alerts/{alert_id}/ack")
async def sb_alert_ack(request: Request, alert_id: str):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    db.ack_alert(alert_id)
    return {"ok": True}


# ── ShadowBridge Recon ────────────────────────────────────────────────────────

@app.post("/api/sb/recon")
async def sb_recon_save(request: Request, payload: Dict = Body(...)):
    if not _auth_agent_or_user(request):
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    machine = payload.get("machine") or request.headers.get("X-Machine-ID", "unknown")
    db.save_recon(
        machine=machine,
        mode=payload.get("mode", "home"),
        score=payload.get("corp_score", 0),
        subnet=payload.get("subnet", ""),
        host_count=payload.get("host_count", 0),
        evidence=payload.get("evidence", []),
        raw=payload,
    )
    return {"ok": True}


@app.get("/api/sb/recon/{machine}")
async def sb_recon_get(request: Request, machine: str):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    result = db.latest_recon(machine)
    return result or {"mode": "unknown", "score": 0}


# ── ShadowBridge Telegram Config ─────────────────────────────────────────────

@app.get("/api/sb/telegram")
async def sb_telegram_get(request: Request):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    cfg = db.get_telegram_config()
    return {"enabled": bool(cfg.get("enabled")), "chat_id": cfg.get("chat_id", ""),
            "configured": bool(cfg.get("token"))}


@app.post("/api/sb/telegram")
async def sb_telegram_set(request: Request, payload: Dict = Body(...)):
    user = _get_user(request)
    if not user:
        return JSONResponse({"error": "Jogosulatlan"}, status_code=401)
    token   = payload.get("token", "").strip()
    chat_id = payload.get("chat_id", "").strip()
    enabled = bool(payload.get("enabled", True))
    if not token or not chat_id:
        return {"error": "token és chat_id kötelező"}
    db.set_telegram_config(token, chat_id, enabled)
    db.create_alert("telegram.configured", "Telegram alerting configured",
                    severity="info")
    return {"ok": True}

# ◈ Shadow Lab

Multi-tenant infrastructure monitoring dashboard — SaaS-ready, built with FastAPI + SQLite + WebSockets.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688) ![License](https://img.shields.io/badge/license-MIT-purple)

---

## Features

### Free tier
- Live CPU, RAM, Disk, Network stats (WebSocket, real-time)
- Temperature sensors (CPU cores, GPU, WiFi)
- Historical chart (CPU/RAM)
- Up to 3 machines per account
- Network map & device alerts

### Pro tier *(coming soon)*
- SSH terminal (xterm.js)
- Nmap scanner
- Process manager & kill
- File browser
- Wake-on-LAN
- Service control (systemctl)
- Up to 10 machines

---

## Stack

| Layer | Tech |
|---|---|
| Backend | FastAPI + uvicorn |
| Database | SQLite (multi-tenant) |
| Auth | bcrypt + session cookies |
| Frontend | Vanilla JS + Bootstrap 5 + Chart.js |
| Stats | psutil (local) / Paramiko SSH (remote) / Agent WS |
| Real-time | WebSockets |

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/webwizardg99/shadow-lab.git
cd shadow-lab

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp config.json.example config.json   # edit port, alert thresholds, subnet

# 4. Run
python3 -m uvicorn main:app --host 0.0.0.0 --port 8889
```

Open `http://localhost:8889` — register a free account and add your first machine.

---

## Configuration

`config.json` (not committed — create from example):

```json
{
    "port": 8889,
    "alerts": {
        "cpu":  85,
        "ram":  90,
        "disk": 90,
        "temp": 80
    },
    "network_subnet": "192.168.1.0/24"
}
```

---

## Adding machines

**Local machine** — check *"This is the local machine"* when adding. Stats are collected directly via `psutil`.

**Remote machine (SSH)** — provide the IP/hostname and SSH credentials. Shadow Lab connects over SSH and runs a lightweight stats script remotely.

**Remote machine (Agent)** — recommended for machines behind NAT or firewalls. The agent connects *outbound* to Shadow Lab, no inbound ports required.

---

## Agent

The agent is a standalone Python script that runs on any monitored machine and streams stats to Shadow Lab over a persistent WebSocket.

```
Your machine  ──── WebSocket (outbound) ────▶  Shadow Lab server
   agent.py                                       /ws/agent/{token}
```

### Setup

**1. Generate a token** — in the dashboard, open ⚙ Manage, click **🔑 Token** next to a machine. Copy the ready-made command.

**2. Install dependencies on the monitored machine:**

```bash
pip install psutil websockets
```

**3. Run the agent:**

```bash
python3 agent.py --server ws://your-shadowlab-host:8889 --token YOUR_TOKEN
```

Or with environment variables:

```bash
export SHADOWLAB_SERVER=ws://your-shadowlab-host:8889
export SHADOWLAB_TOKEN=YOUR_TOKEN
python3 agent.py
```

The agent reconnects automatically with exponential backoff if the connection drops. The dashboard shows ONLINE/OFFLINE in real time.

### Run as a systemd service

```ini
# /etc/systemd/system/shadowlab-agent.service
[Unit]
Description=Shadow Lab Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/shadowlab/agent.py
Environment=SHADOWLAB_SERVER=ws://your-shadowlab-host:8889
Environment=SHADOWLAB_TOKEN=YOUR_TOKEN
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now shadowlab-agent
```

---

## Security

- Passwords hashed with **bcrypt** (12 rounds, per-hash salt)
- Session tokens: `secrets.token_hex(32)`
- All shell arguments sanitised with `shlex.quote`
- Machine ownership enforced on every API endpoint
- `shadowlab.db` and `config.json` excluded from version control

---

## Project structure

```
shadow-lab/
├── main.py               # FastAPI app, routes, WebSocket broadcast
├── database.py           # SQLite helpers (users, machines, sessions, agent tokens)
├── agent.py              # Standalone agent — runs on monitored machines
├── config.json           # Local config (gitignored)
├── config.json.example   # Config template
├── requirements.txt      # Python dependencies
├── templates/
│   ├── index.html        # Dashboard (Jinja2)
│   ├── login.html
│   └── register.html
└── start.sh              # Convenience launcher
```

---

## License

MIT

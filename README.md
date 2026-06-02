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
| Stats | psutil (local) / Paramiko SSH (remote) |
| Real-time | WebSockets |

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/webwizardg99/shadow-lab.git
cd shadow-lab

# 2. Install dependencies
pip install fastapi uvicorn paramiko psutil bcrypt jinja2 python-multipart

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

**Remote machine** — provide the IP/hostname and SSH credentials. Shadow Lab connects over SSH and runs a lightweight stats script remotely.

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
├── main.py          # FastAPI app, routes, WebSocket broadcast
├── database.py      # SQLite helpers (users, machines, sessions)
├── config.json      # Local config (gitignored)
├── templates/
│   ├── index.html   # Dashboard (Jinja2)
│   ├── login.html
│   └── register.html
└── start.sh         # Convenience launcher
```

---

## License

MIT

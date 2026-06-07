# ShadowBridge — Reggeli Deploy Checklist

## 1. NOX Dashboard frissítése (5 perc)

```bash
cd /home/wizardg/lab-dashboard

# Backup és frissítés
cp main.py main.py.bak
# Másold át a cloud repóból a következő fájlokat:
#   main.py, database.py, shadowbridge_agent.py,
#   shadowbridge_recon.py, shadowbridge_telegram.py, shadowbridge_honeypot.py

# Restart
pkill -f "uvicorn main" ; sleep 1
nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8888 --reload > /tmp/nox.log 2>&1 &
sleep 3 && curl -s http://localhost:8888/login | head -3
```

## 2. Agent telepítése minden gépre (10 perc)

### NOX-on (server) — agent lokálisan:
```bash
mkdir -p /opt/shadowbridge
cp /home/wizardg/lab-dashboard/shadowbridge_agent.py /opt/shadowbridge/
cp /home/wizardg/lab-dashboard/shadowbridge_recon.py /opt/shadowbridge/

cat > /opt/shadowbridge/.env << 'EOF'
SHADOWBRIDGE_URL=http://100.75.31.41:8888
SHADOWBRIDGE_TOKEN=sb_nox_token_CHANGE_ME
SHADOWBRIDGE_MACHINE=server
OLLAMA_URL=http://localhost:11434
POLL_INTERVAL=5
EOF

sudo cp /home/wizardg/lab-dashboard/deploy/shadowbridge-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shadowbridge-agent
journalctl -u shadowbridge-agent -f
```

### assistant gépre:
```bash
bash /home/wizardg/lab-dashboard/deploy/install_agent.sh \
  <assistant_IP> assistant sb_assistant_token_CHANGE_ME
```

### monitoring gépre:
```bash
bash /home/wizardg/lab-dashboard/deploy/install_agent.sh \
  <monitoring_IP> monitoring sb_monitoring_token_CHANGE_ME
```

### attack gépre:
```bash
bash /home/wizardg/lab-dashboard/deploy/install_agent.sh \
  <attack_IP> attack sb_attack_token_CHANGE_ME
```

## 3. Telegram alerting beállítása (2 perc)

```bash
# Teszteld a bot tokent:
python3 /home/wizardg/lab-dashboard/shadowbridge_telegram.py \
  <BOT_TOKEN> <CHAT_ID> "ShadowBridge test üzenet"

# Ha OK, konfiguráld a dashboardon:
curl -s -X POST http://localhost:8888/api/sb/telegram \
  -H "Content-Type: application/json" \
  -b "shadowlab_session=<SESSION_COOKIE>" \
  -d '{"token":"<BOT_TOKEN>","chat_id":"<CHAT_ID>","enabled":true}'
```

## 4. Első AI task teszt (1 perc)

```bash
# Task beküldése:
curl -s -X POST http://localhost:8888/api/ai/task \
  -H "X-Agent-Token: sb_nox_token_CHANGE_ME" \
  -H "Content-Type: application/json" \
  -d '{"type":"fast","prompt":"Írj egy egymondatos tesztet.","target":"server"}' | python3 -m json.tool

# Eredmény lekérdezése (a visszakapott id-vel):
curl -s http://localhost:8888/api/ai/tasks \
  -H "X-Agent-Token: sb_nox_token_CHANGE_ME" | python3 -m json.tool
```

## 5. Honeypot indítása (opcionális)

```bash
# Home módban (alapértelmezett):
nohup python3 /home/wizardg/lab-dashboard/shadowbridge_honeypot.py home \
  > /tmp/honeypot.log 2>&1 &

# Figyeli: port 2222 (fake SSH), 8080 (fake admin panel)
# Minden kapcsolatfelvétel alert-et generál a dashboardon
```

## 6. Ellenőrzések

```bash
# Dashboard él?
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/login

# Agent-ek online?
curl -s http://localhost:8888/api/sb/alerts \
  -H "X-Agent-Token: sb_nox_token_CHANGE_ME" | python3 -m json.tool

# Recon eredmény?
curl -s http://localhost:8888/api/sb/recon/server \
  -H "X-Agent-Token: sb_nox_token_CHANGE_ME" | python3 -m json.tool
```

## Architektúra összefoglaló

```
[Claude/Opus] → POST /api/ai/task
                      ↓
               Task Queue (SQLite)
                      ↓
    ┌─────────────────┼─────────────────┐
    ↓                 ↓                 ↓
[server/NOX]   [monitoring]        [attack]
qwen2.5-coder  lfm2.5             nemotron-cloud
llama3.1:8b    (reasoning)        qwen2.5:3b
wizz           log analysis       security
    ↓                 ↓                 ↓
    └─────────────────┼─────────────────┘
                      ↓
             PATCH /api/ai/task/{id}
                      ↓
              [Telegram Alert]
```

#!/usr/bin/env python3
"""
ShadowBridge Telegram Alerting
Sends incident notifications via Telegram Bot API. No extra dependencies.
"""
import json
import logging
import threading
import time
import urllib.request
import urllib.error
import urllib.parse

log = logging.getLogger("shadowbridge-telegram")

_send_lock = threading.Lock()
_rate_bucket: list = []   # timestamps of recent sends (rate-limit: 20/min)


def _tg_request(token: str, method: str, payload: dict) -> dict:
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        log.error(f"Telegram API error {e.code}: {body}")
        return {"ok": False, "error": body}
    except Exception as e:
        log.error(f"Telegram send error: {e}")
        return {"ok": False, "error": str(e)}


def _rate_ok() -> bool:
    now = time.time()
    with _send_lock:
        _rate_bucket[:] = [t for t in _rate_bucket if now - t < 60]
        if len(_rate_bucket) >= 18:
            return False
        _rate_bucket.append(now)
    return True


SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "ℹ️",
}


def send_alert(token: str, chat_id: str, alert_type: str, message: str,
               severity: str = "info", machine: str = None, data: dict = None) -> bool:
    if not token or not chat_id:
        return False
    if not _rate_ok():
        log.warning("Telegram rate limit hit — alert dropped")
        return False

    emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    lines = [
        f"{emoji} *ShadowBridge Alert*",
        f"*Type:* `{alert_type}`",
        f"*Severity:* `{severity.upper()}`",
    ]
    if machine:
        lines.append(f"*Node:* `{machine}`")
    lines.append(f"*Message:* {message}")
    if data:
        for k, v in list(data.items())[:4]:
            lines.append(f"  • {k}: `{v}`")
    lines.append(f"_🕐 {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}_")

    result = _tg_request(token, "sendMessage", {
        "chat_id": chat_id,
        "text": "\n".join(lines),
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    })
    return result.get("ok", False)


def send_message(token: str, chat_id: str, text: str) -> bool:
    if not token or not chat_id:
        return False
    result = _tg_request(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    })
    return result.get("ok", False)


def verify_bot(token: str) -> dict:
    result = _tg_request(token, "getMe", {})
    if result.get("ok"):
        return result.get("result", {})
    return {}


# ── Background alert dispatcher ───────────────────────────────────────────────

class TelegramDispatcher(threading.Thread):
    """Watches the DB for unacked alerts and forwards them to Telegram."""

    def __init__(self, get_config_fn, list_alerts_fn, ack_fn):
        super().__init__(daemon=True, name="tg-dispatcher")
        self._get_cfg = get_config_fn
        self._list    = list_alerts_fn
        self._ack     = ack_fn

    def run(self):
        log.info("Telegram dispatcher started")
        while True:
            try:
                cfg = self._get_cfg()
                if cfg.get("enabled") and cfg.get("token") and cfg.get("chat_id"):
                    token   = cfg["token"]
                    chat_id = cfg["chat_id"]
                    pending = self._list(unacked_only=True)
                    for alert in pending:
                        ok = send_alert(
                            token, chat_id,
                            alert_type=alert["type"],
                            message=alert["message"],
                            severity=alert.get("severity", "info"),
                            machine=alert.get("machine"),
                            data=alert.get("data"),
                        )
                        if ok:
                            self._ack(alert["id"])
            except Exception as e:
                log.error(f"Dispatcher error: {e}")
            time.sleep(10)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: shadowbridge_telegram.py <BOT_TOKEN> <CHAT_ID> [message]")
        sys.exit(1)
    tok, cid = sys.argv[1], sys.argv[2]
    msg = sys.argv[3] if len(sys.argv) > 3 else "🟢 ShadowBridge Telegram test OK"
    bot = verify_bot(tok)
    if not bot:
        print("ERROR: Invalid bot token")
        sys.exit(1)
    print(f"Bot: @{bot.get('username')} ({bot.get('first_name')})")
    ok = send_message(tok, cid, msg)
    print("Sent:" if ok else "FAILED:", msg)

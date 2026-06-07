import sqlite3
import secrets
import os
import bcrypt
from typing import Optional, List, Dict

DB_PATH = os.path.join(os.path.dirname(__file__), "shadowlab.db")


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                email    TEXT    UNIQUE NOT NULL,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,
                tier     TEXT    NOT NULL DEFAULT 'free',
                created  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS machines (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                label       TEXT    NOT NULL,
                host        TEXT    NOT NULL,
                ssh_user    TEXT,
                ssh_pass    TEXT,
                mac         TEXT,
                is_local    INTEGER NOT NULL DEFAULT 0,
                agent_token TEXT    UNIQUE
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token    TEXT    PRIMARY KEY,
                user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
        """)
    # Migrate existing DBs that don't have agent_token yet
    try:
        with _conn() as c:
            c.execute("ALTER TABLE machines ADD COLUMN agent_token TEXT")
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_token ON machines(agent_token)")
    except Exception:
        pass


# ── Auth ──────────────────────────────────────────────────────────────────────

def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def register_user(email: str, username: str, password: str) -> Optional[Dict]:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
                (email.lower().strip(), username.strip(), _hash(password))
            )
            return get_user_by_email(email)
    except sqlite3.IntegrityError:
        return None


def authenticate(email_or_user: str, password: str) -> Optional[Dict]:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM users WHERE email=? OR username=?",
            (email_or_user.lower(), email_or_user)
        ).fetchone()
    if row and _verify(password, row["password"]):
        return dict(row)
    return None


def create_session(user_id: int) -> str:
    token = secrets.token_hex(32)
    with _conn() as c:
        c.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))
    return token


def get_user_by_session(token: str) -> Optional[Dict]:
    if not token:
        return None
    with _conn() as c:
        row = c.execute(
            "SELECT u.* FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=?",
            (token,)
        ).fetchone()
    return dict(row) if row else None


def delete_session(token: str):
    with _conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))


def get_user_by_email(email: str) -> Optional[Dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()
    return dict(row) if row else None


# ── Machines ─────────────────────────────────────────────────────────────────

def get_machines(user_id: int) -> List[Dict]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM machines WHERE user_id=?", (user_id,)).fetchall()
    return [dict(r) for r in rows]


def add_machine(user_id: int, label: str, host: str,
                ssh_user: str = "", ssh_pass: str = "",
                mac: str = "", is_local: bool = False) -> Dict:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO machines (user_id, label, host, ssh_user, ssh_pass, mac, is_local) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, label, host, ssh_user, ssh_pass, mac, int(is_local))
        )
        row = c.execute("SELECT * FROM machines WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def delete_machine(user_id: int, machine_id: int):
    with _conn() as c:
        c.execute("DELETE FROM machines WHERE id=? AND user_id=?", (machine_id, user_id))


def get_all_machines() -> List[Dict]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM machines").fetchall()
    return [dict(r) for r in rows]


def update_machine(user_id: int, machine_id: int, **kwargs):
    allowed = {"label", "host", "ssh_user", "ssh_pass", "mac"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    sets = ", ".join(f"{k}=?" for k in fields)
    with _conn() as c:
        c.execute(
            f"UPDATE machines SET {sets} WHERE id=? AND user_id=?",
            (*fields.values(), machine_id, user_id)
        )


# ── Agent tokens ─────────────────────────────────────────────────────────────

def generate_agent_token(user_id: int, machine_id: int) -> Optional[str]:
    token = secrets.token_urlsafe(32)
    with _conn() as c:
        rows = c.execute(
            "UPDATE machines SET agent_token=? WHERE id=? AND user_id=?",
            (token, machine_id, user_id)
        ).rowcount
    return token if rows > 0 else None


def get_machine_by_agent_token(token: str) -> Optional[Dict]:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM machines WHERE agent_token=?", (token,)
        ).fetchone()
    return dict(row) if row else None


# ── Tier helpers ─────────────────────────────────────────────────────────────

def is_pro(user: Dict) -> bool:
    return user.get("tier") in ("pro", "admin")


def set_tier(user_id: int, tier: str):
    with _conn() as c:
        c.execute("UPDATE users SET tier=? WHERE id=?", (tier, user_id))


# ── ShadowBridge extensions ───────────────────────────────────────────────────

def init_shadowbridge_tables():
    with _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS ai_tasks (
                id       TEXT    PRIMARY KEY,
                type     TEXT    NOT NULL DEFAULT 'general',
                prompt   TEXT    NOT NULL,
                system   TEXT    DEFAULT '',
                target   TEXT    DEFAULT 'any',
                status   TEXT    NOT NULL DEFAULT 'pending',
                result   TEXT,
                model    TEXT,
                machine  TEXT,
                elapsed  REAL,
                created  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                updated  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS sb_alerts (
                id        TEXT    PRIMARY KEY,
                type      TEXT    NOT NULL,
                severity  TEXT    NOT NULL DEFAULT 'info',
                machine   TEXT,
                message   TEXT    NOT NULL,
                data      TEXT,
                ack       INTEGER NOT NULL DEFAULT 0,
                created   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS recon_results (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                machine   TEXT    NOT NULL,
                mode      TEXT    NOT NULL,
                score     INTEGER NOT NULL,
                subnet    TEXT,
                host_count INTEGER,
                evidence  TEXT,
                raw       TEXT,
                created   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS telegram_config (
                id      INTEGER PRIMARY KEY DEFAULT 1,
                token   TEXT,
                chat_id TEXT,
                enabled INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO telegram_config (id) VALUES (1);
        """)


# ── AI Tasks (persistent) ─────────────────────────────────────────────────────

def create_ai_task(tid: str, task_type: str, prompt: str,
                   system: str = "", target: str = "any") -> Dict:
    with _conn() as c:
        c.execute(
            "INSERT INTO ai_tasks (id,type,prompt,system,target) VALUES (?,?,?,?,?)",
            (tid, task_type, prompt, system, target)
        )
    return get_ai_task(tid)


def get_ai_task(tid: str) -> Optional[Dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM ai_tasks WHERE id=?", (tid,)).fetchone()
    return dict(row) if row else None


def update_ai_task(tid: str, **kwargs) -> bool:
    allowed = {"status", "result", "model", "machine", "elapsed"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    fields["updated"] = int(__import__("time").time())
    sets = ", ".join(f"{k}=?" for k in fields)
    with _conn() as c:
        rows = c.execute(
            f"UPDATE ai_tasks SET {sets} WHERE id=?",
            (*fields.values(), tid)
        ).rowcount
    return rows > 0


def list_ai_tasks(limit: int = 50) -> List[Dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM ai_tasks ORDER BY created DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def next_ai_task(machine: str = "any") -> Optional[Dict]:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM ai_tasks WHERE status='pending' AND (target='any' OR target=?) "
            "ORDER BY created ASC LIMIT 1", (machine,)
        ).fetchone()
    return dict(row) if row else None


# ── Alerts ────────────────────────────────────────────────────────────────────

def create_alert(alert_type: str, message: str, severity: str = "info",
                 machine: str = None, data: dict = None) -> Dict:
    import time, json
    tid = secrets.token_hex(6)
    with _conn() as c:
        c.execute(
            "INSERT INTO sb_alerts (id,type,severity,machine,message,data) VALUES (?,?,?,?,?,?)",
            (tid, alert_type, severity, machine, message,
             json.dumps(data) if data else None)
        )
    return {"id": tid, "type": alert_type, "severity": severity,
            "machine": machine, "message": message}


def list_alerts(limit: int = 100, unacked_only: bool = False) -> List[Dict]:
    import json
    q = "SELECT * FROM sb_alerts"
    if unacked_only:
        q += " WHERE ack=0"
    q += " ORDER BY created DESC LIMIT ?"
    with _conn() as c:
        rows = c.execute(q, (limit,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("data"):
            try:
                d["data"] = json.loads(d["data"])
            except Exception:
                pass
        result.append(d)
    return result


def ack_alert(alert_id: str):
    with _conn() as c:
        c.execute("UPDATE sb_alerts SET ack=1 WHERE id=?", (alert_id,))


# ── Recon results ─────────────────────────────────────────────────────────────

def save_recon(machine: str, mode: str, score: int, subnet: str,
               host_count: int, evidence: list, raw: dict):
    import json
    with _conn() as c:
        c.execute(
            "INSERT INTO recon_results (machine,mode,score,subnet,host_count,evidence,raw) "
            "VALUES (?,?,?,?,?,?,?)",
            (machine, mode, score, subnet, host_count,
             json.dumps(evidence), json.dumps(raw))
        )


def latest_recon(machine: str) -> Optional[Dict]:
    import json
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM recon_results WHERE machine=? ORDER BY created DESC LIMIT 1",
            (machine,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    for key in ("evidence", "raw"):
        try:
            d[key] = json.loads(d[key]) if d[key] else None
        except Exception:
            pass
    return d


# ── Telegram config ───────────────────────────────────────────────────────────

def get_telegram_config() -> Dict:
    with _conn() as c:
        row = c.execute("SELECT * FROM telegram_config WHERE id=1").fetchone()
    return dict(row) if row else {}


def set_telegram_config(token: str, chat_id: str, enabled: bool = True):
    with _conn() as c:
        c.execute(
            "UPDATE telegram_config SET token=?, chat_id=?, enabled=? WHERE id=1",
            (token, chat_id, int(enabled))
        )

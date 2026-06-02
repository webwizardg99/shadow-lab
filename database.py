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
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                label     TEXT    NOT NULL,
                host      TEXT    NOT NULL,
                ssh_user  TEXT,
                ssh_pass  TEXT,
                mac       TEXT,
                is_local  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token    TEXT    PRIMARY KEY,
                user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
        """)


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


# ── Tier helpers ─────────────────────────────────────────────────────────────

def is_pro(user: Dict) -> bool:
    return user.get("tier") in ("pro", "admin")


def set_tier(user_id: int, tier: str):
    with _conn() as c:
        c.execute("UPDATE users SET tier=? WHERE id=?", (tier, user_id))

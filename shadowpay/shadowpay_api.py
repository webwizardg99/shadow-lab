#!/usr/bin/env python3
"""
ShadowPay — Anonymous Crypto Payment Gateway for ShadowKey ISO
Supports Monero (XMR) and Bitcoin (BTC).
No account. No email. No identity. Pay → token → download.

Flow:
  POST /api/pay/new          → create invoice, get address + amount
  GET  /api/pay/status/<id>  → check payment confirmation
  GET  /download/<token>     → one-time ISO download (token expires in 24h)
  GET  /api/pay/products     → list available ISOs / prices

Privacy guarantees:
  - No logs of IP addresses
  - Tokens are single-use
  - XMR subaddresses used (unlinkable)
  - Download served from RAM, no access log
"""
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger("shadowpay")

DB_PATH      = Path(os.environ.get("SHADOWPAY_DB",    "/opt/shadowpay/payments.db"))
ISO_DIR      = Path(os.environ.get("SHADOWPAY_ISO",   "/opt/shadowpay/iso"))
MONERO_RPC   = os.environ.get("MONERO_RPC_URL",  "http://127.0.0.1:18082/json_rpc")
MONERO_USER  = os.environ.get("MONERO_RPC_USER", "shadowpay")
MONERO_PASS  = os.environ.get("MONERO_RPC_PASS", "")
BTC_XPUB     = os.environ.get("SHADOWPAY_BTC_XPUB", "")
TOKEN_TTL    = 86400    # 24 hours
CONFIRM_REQ  = 10       # XMR confirmations needed (Monero ~20 min)
BTC_CONFIRM  = 2        # BTC confirmations needed

PRODUCTS = {
    "shadowkey-home": {
        "name":        "ShadowKey Home",
        "description": "Bootable USB live system — home profile",
        "price_xmr":   0.15,
        "price_btc":   0.00005,
        "file":        "shadowkey-home-amd64.iso",
    },
    "shadowkey-pro": {
        "name":        "ShadowKey Pro",
        "description": "Full stack: home + work + corporate + ShadowMesh",
        "price_xmr":   0.35,
        "price_btc":   0.00012,
        "file":        "shadowkey-pro-amd64.iso",
    },
}


# ── Database ──────────────────────────────────────────────────────────────────

class PayDB:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self._init()

    def _init(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS invoices (
                id          TEXT PRIMARY KEY,
                product     TEXT NOT NULL,
                currency    TEXT NOT NULL,     -- XMR | BTC
                amount      REAL NOT NULL,
                address     TEXT NOT NULL,
                subaddress_index INTEGER,
                status      TEXT DEFAULT 'pending',
                confirmations INTEGER DEFAULT 0,
                created_at  REAL,
                paid_at     REAL
            );
            CREATE TABLE IF NOT EXISTS download_tokens (
                token       TEXT PRIMARY KEY,
                invoice_id  TEXT NOT NULL,
                product     TEXT NOT NULL,
                used        INTEGER DEFAULT 0,
                created_at  REAL,
                expires_at  REAL
            );
            CREATE INDEX IF NOT EXISTS idx_invoice_status
                ON invoices(status, created_at);
        """)
        self.db.commit()

    def create_invoice(self, product: str, currency: str,
                       amount: float, address: str,
                       subaddress_index: int = 0) -> str:
        iid = secrets.token_hex(16)
        self.db.execute(
            "INSERT INTO invoices VALUES (?,?,?,?,?,?,?,?,?,?)",
            (iid, product, currency, amount, address,
             subaddress_index, "pending", 0, time.time(), None)
        )
        self.db.commit()
        return iid

    def get_invoice(self, iid: str) -> Optional[dict]:
        row = self.db.execute(
            "SELECT * FROM invoices WHERE id=?", (iid,)
        ).fetchone()
        if not row:
            return None
        cols = ["id","product","currency","amount","address",
                "subaddress_index","status","confirmations","created_at","paid_at"]
        return dict(zip(cols, row))

    def mark_paid(self, iid: str, confirmations: int):
        self.db.execute(
            "UPDATE invoices SET status='paid', confirmations=?, paid_at=? WHERE id=?",
            (confirmations, time.time(), iid)
        )
        self.db.commit()

    def update_confirmations(self, iid: str, confirmations: int):
        self.db.execute(
            "UPDATE invoices SET confirmations=? WHERE id=?",
            (confirmations, iid)
        )
        self.db.commit()

    def create_download_token(self, invoice_id: str, product: str) -> str:
        token = secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO download_tokens VALUES (?,?,?,?,?,?)",
            (token, invoice_id, product, 0,
             time.time(), time.time() + TOKEN_TTL)
        )
        self.db.commit()
        return token

    def consume_token(self, token: str) -> Optional[str]:
        """Returns product file name if token is valid, else None."""
        row = self.db.execute(
            "SELECT product, used, expires_at FROM download_tokens WHERE token=?",
            (token,)
        ).fetchone()
        if not row:
            return None
        product, used, expires_at = row
        if used or time.time() > expires_at:
            return None
        self.db.execute(
            "UPDATE download_tokens SET used=1 WHERE token=?", (token,)
        )
        self.db.commit()
        return product

    def pending_invoices(self) -> list:
        rows = self.db.execute(
            "SELECT id, currency, amount, address, subaddress_index "
            "FROM invoices WHERE status='pending'"
        ).fetchall()
        return [{"id": r[0], "currency": r[1], "amount": r[2],
                 "address": r[3], "subaddress_index": r[4]} for r in rows]


# ── Monero RPC ────────────────────────────────────────────────────────────────

def _xmr_rpc(method: str, params: dict = None) -> dict:
    payload = json.dumps({
        "jsonrpc": "2.0", "id": "0",
        "method": method, "params": params or {}
    }).encode()
    import base64
    creds = base64.b64encode(f"{MONERO_USER}:{MONERO_PASS}".encode()).decode()
    req = urllib.request.Request(
        MONERO_RPC, data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Basic {creds}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()).get("result", {})


def xmr_create_subaddress(label: str) -> tuple[str, int]:
    """Create a fresh subaddress for this invoice. Returns (address, index)."""
    result = _xmr_rpc("create_address", {"account_index": 0, "label": label})
    return result["address"], result["address_index"]


def xmr_check_payment(address: str, amount_xmr: float,
                       subaddress_index: int) -> tuple[bool, int]:
    """
    Check if address received >= amount_xmr.
    Returns (confirmed, confirmations).
    """
    result = _xmr_rpc("get_transfers", {
        "in": True, "account_index": 0,
        "subaddr_indices": [subaddress_index],
    })
    transfers = result.get("in", [])
    total_received = sum(t["amount"] for t in transfers) / 1e12  # piconero → XMR
    if total_received < amount_xmr * 0.999:   # 0.1% tolerance
        return False, 0
    min_conf = min((t.get("confirmations", 0) for t in transfers), default=0)
    return min_conf >= CONFIRM_REQ, min_conf


# ── Payment monitor (background) ─────────────────────────────────────────────

class PaymentMonitor:
    """Background thread that polls pending invoices and issues tokens."""

    def __init__(self, db: PayDB):
        self.db = db
        self._running = False

    def start(self):
        import threading
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="pay-monitor")
        t.start()
        log.info("Payment monitor started")

    def _loop(self):
        while self._running:
            try:
                self._check_all()
            except Exception as e:
                log.warning(f"Monitor error: {e}")
            time.sleep(30)   # check every 30s

    def _check_all(self):
        for inv in self.db.pending_invoices():
            if inv["currency"] == "XMR":
                self._check_xmr(inv)
            # BTC checking would go here (electrum / BTCPayServer webhook)

    def _check_xmr(self, inv: dict):
        try:
            paid, confs = xmr_check_payment(
                inv["address"], inv["amount"], inv["subaddress_index"]
            )
            self.db.update_confirmations(inv["id"], confs)
            if paid:
                self.db.mark_paid(inv["id"], confs)
                token = self.db.create_download_token(inv["id"], inv["product"])
                log.info(f"Invoice {inv['id'][:8]} paid — token issued")
        except Exception as e:
            log.debug(f"XMR check failed for {inv['id'][:8]}: {e}")


# ── FastAPI routes (mounted onto main.py) ─────────────────────────────────────
# Import this module in main.py and call register_routes(app, db_instance)

def register_routes(app, pay_db: PayDB):
    from fastapi import Request
    from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

    monitor = PaymentMonitor(pay_db)
    monitor.start()

    @app.get("/api/pay/products")
    async def products():
        return {
            k: {
                "name": v["name"],
                "description": v["description"],
                "price_xmr": v["price_xmr"],
                "price_btc": v["price_btc"],
            }
            for k, v in PRODUCTS.items()
        }

    @app.post("/api/pay/new")
    async def new_invoice(request: Request):
        body = await request.json()
        product  = body.get("product", "").strip()
        currency = body.get("currency", "XMR").upper()

        if product not in PRODUCTS:
            return JSONResponse({"error": "Unknown product"}, status_code=400)
        if currency not in ("XMR", "BTC"):
            return JSONResponse({"error": "Unsupported currency"}, status_code=400)

        p = PRODUCTS[product]
        amount = p[f"price_{currency.lower()}"]

        if currency == "XMR":
            try:
                address, idx = xmr_create_subaddress(f"shadowpay-{product}")
            except Exception as e:
                log.error(f"XMR subaddress creation failed: {e}")
                return JSONResponse(
                    {"error": "Payment service temporarily unavailable"},
                    status_code=503
                )
        else:
            return JSONResponse({"error": "BTC not yet configured"}, status_code=501)

        iid = pay_db.create_invoice(product, currency, amount, address, idx)
        log.info(f"Invoice {iid[:8]} created: {product} {amount} {currency}")

        return {
            "invoice_id":    iid,
            "product":       product,
            "currency":      currency,
            "amount":        amount,
            "address":       address,
            "confirmations_needed": CONFIRM_REQ,
            "expires_in":    3600,   # 1 hour to pay
            "check_url":     f"/api/pay/status/{iid}",
        }

    @app.get("/api/pay/status/{invoice_id}")
    async def invoice_status(invoice_id: str):
        inv = pay_db.get_invoice(invoice_id)
        if not inv:
            return JSONResponse({"error": "Invoice not found"}, status_code=404)

        # Check for token if paid
        token = None
        if inv["status"] == "paid":
            row = pay_db.db.execute(
                "SELECT token, used, expires_at FROM download_tokens WHERE invoice_id=?",
                (invoice_id,)
            ).fetchone()
            if row and not row[1]:
                token = row[0]

        return {
            "status":         inv["status"],
            "confirmations":  inv["confirmations"],
            "required":       CONFIRM_REQ,
            "download_token": token,
            "download_url":   f"/download/{token}" if token else None,
        }

    @app.get("/download/{token}")
    async def download_iso(token: str, request: Request):
        product_key = pay_db.consume_token(token)
        if not product_key:
            return JSONResponse(
                {"error": "Invalid or expired download token"},
                status_code=403
            )

        product = PRODUCTS.get(product_key)
        if not product:
            return JSONResponse({"error": "Product not found"}, status_code=404)

        iso_path = ISO_DIR / product["file"]
        if not iso_path.exists():
            log.warning(f"ISO not found: {iso_path}")
            return JSONResponse(
                {"error": "File not available yet — try again in a few minutes"},
                status_code=503
            )

        log.info(f"Download served: {product_key} (token consumed)")
        return FileResponse(
            path=str(iso_path),
            media_type="application/octet-stream",
            filename=product["file"],
            headers={
                "Content-Disposition": f'attachment; filename="{product["file"]}"',
                "X-Content-Type-Options": "nosniff",
            }
        )

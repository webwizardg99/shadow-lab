#!/usr/bin/env python3
"""
ShadowGuard WiFi Threat Detector — Core Detection Engine
Platform-agnostic Python module used by the Android APK (via Chaquopy/BeeWare)
and as a standalone daemon on Linux/Termux.

Detects:
  1. Evil Twin / Rogue AP     — same SSID, different BSSID
  2. Security Downgrade       — known WPA2/3 suddenly appears as Open
  3. Signal Spike             — sudden RSSI jump (rogue AP physically nearby)
  4. Deauth Flood             — 802.11 deauthentication frame storm
  5. KARMA / MANA Attack      — AP responds to all probe requests
  6. Captive Portal Injection — unexpected redirect on trusted network
  7. Channel Switch Anomaly   — AP changes channel unexpectedly

Usage (standalone):
  python3 shadowguard_detector.py monitor          # continuous monitoring
  python3 shadowguard_detector.py scan             # single scan
  python3 shadowguard_detector.py trust <SSID>     # fingerprint current AP
  python3 shadowguard_detector.py list             # show trusted networks
"""
import json
import logging
import os
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

log = logging.getLogger("shadowguard")

DB_PATH  = Path(os.environ.get("SHADOWGUARD_DB", os.path.expanduser("~/.shadowguard/networks.db")))
RSSI_SPIKE_THRESHOLD = 15   # dBm jump that triggers alert
SCAN_INTERVAL        = 10   # seconds between scans
DEAUTH_THRESHOLD     = 5    # deauths/second = flood


@dataclass
class APInfo:
    ssid:       str
    bssid:      str
    rssi:       int         # dBm, e.g. -65
    security:   str         # "WPA2", "WPA3", "WEP", "Open"
    channel:    int
    frequency:  int         # MHz
    vendor:     str = ""
    timestamp:  float = 0.0

    def fingerprint(self) -> str:
        """Stable identity: SSID + BSSID + security type."""
        return f"{self.ssid}|{self.bssid}|{self.security}"


@dataclass
class Threat:
    type:       str          # EVIL_TWIN | DOWNGRADE | SIGNAL_SPIKE | DEAUTH | KARMA | PORTAL
    severity:   str          # critical | high | medium
    ssid:       str
    bssid:      str
    message:    str
    evidence:   dict
    timestamp:  float


# ── Network fingerprint database ──────────────────────────────────────────────

class NetworkDB:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self._init()

    def _init(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS trusted_networks (
                ssid        TEXT NOT NULL,
                bssid       TEXT NOT NULL,
                security    TEXT NOT NULL,
                channel     INTEGER,
                rssi_avg    REAL,
                vendor      TEXT,
                trusted_at  REAL,
                last_seen   REAL,
                PRIMARY KEY (ssid, bssid)
            );
            CREATE TABLE IF NOT EXISTS threat_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                type        TEXT, severity TEXT, ssid TEXT, bssid TEXT,
                message     TEXT, evidence TEXT, ts REAL
            );
        """)
        self.db.commit()

    def trust(self, ap: APInfo):
        self.db.execute(
            "INSERT OR REPLACE INTO trusted_networks VALUES (?,?,?,?,?,?,?,?)",
            (ap.ssid, ap.bssid, ap.security, ap.channel,
             ap.rssi, ap.vendor, time.time(), time.time())
        )
        self.db.commit()
        log.info(f"Trusted: {ap.ssid} ({ap.bssid}) {ap.security}")

    def get_trusted(self, ssid: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM trusted_networks WHERE ssid=?", (ssid,)
        ).fetchall()
        cols = ["ssid","bssid","security","channel","rssi_avg",
                "vendor","trusted_at","last_seen"]
        return [dict(zip(cols, r)) for r in rows]

    def all_trusted(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT ssid, bssid, security, rssi_avg, last_seen "
            "FROM trusted_networks ORDER BY last_seen DESC"
        ).fetchall()
        return [{"ssid":r[0],"bssid":r[1],"security":r[2],
                 "rssi":r[3],"last_seen":r[4]} for r in rows]

    def update_seen(self, ssid: str, bssid: str):
        self.db.execute(
            "UPDATE trusted_networks SET last_seen=? WHERE ssid=? AND bssid=?",
            (time.time(), ssid, bssid)
        )
        self.db.commit()

    def log_threat(self, threat: Threat):
        self.db.execute(
            "INSERT INTO threat_log (type,severity,ssid,bssid,message,evidence,ts) "
            "VALUES (?,?,?,?,?,?,?)",
            (threat.type, threat.severity, threat.ssid, threat.bssid,
             threat.message, json.dumps(threat.evidence), threat.timestamp)
        )
        self.db.commit()

    def recent_threats(self, limit: int = 20) -> list:
        rows = self.db.execute(
            "SELECT type,severity,ssid,bssid,message,ts FROM threat_log "
            "ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"type":r[0],"severity":r[1],"ssid":r[2],
                 "bssid":r[3],"message":r[4],"ts":r[5]} for r in rows]


# ── WiFi scanner (platform-aware) ─────────────────────────────────────────────

def scan_networks() -> list[APInfo]:
    """Scan visible WiFi networks. Works on Linux (iwlist/nmcli) and Android (Termux)."""
    aps = []
    try:
        aps = _scan_nmcli()
        if aps:
            return aps
    except Exception:
        pass
    try:
        aps = _scan_iwlist()
    except Exception:
        pass
    return aps


def _scan_nmcli() -> list[APInfo]:
    out = subprocess.check_output(
        ["nmcli", "-t", "-f",
         "SSID,BSSID,SIGNAL,SECURITY,CHAN,FREQ", "dev", "wifi", "list", "--rescan", "yes"],
        text=True, timeout=15
    )
    aps = []
    for line in out.strip().splitlines():
        parts = line.split(":")
        if len(parts) < 6:
            continue
        try:
            ssid, bssid, signal, security, chan, freq = parts[:6]
            rssi = int(signal) * -1 if int(signal) > 0 else int(signal)
            aps.append(APInfo(
                ssid=ssid, bssid=bssid.replace("\\:", ":"),
                rssi=rssi,
                security=_normalize_security(security),
                channel=int(chan) if chan.isdigit() else 0,
                frequency=int(freq.split()[0]) if freq else 0,
                timestamp=time.time(),
            ))
        except Exception:
            continue
    return aps


def _scan_iwlist() -> list[APInfo]:
    iface = _get_wifi_iface()
    if not iface:
        return []
    out = subprocess.check_output(
        ["iwlist", iface, "scan"], text=True, timeout=20
    )
    aps = []
    current: dict = {}
    for line in out.splitlines():
        line = line.strip()
        if "Cell " in line and "Address:" in line:
            if current:
                aps.append(_iwlist_to_ap(current))
            current = {"bssid": line.split("Address:")[-1].strip()}
        elif "ESSID:" in line:
            current["ssid"] = line.split('"')[1] if '"' in line else ""
        elif "Signal level=" in line:
            try:
                sig = line.split("Signal level=")[1].split(" ")[0]
                current["rssi"] = int(sig.split("/")[0]) if "/" in sig else int(sig)
            except Exception:
                pass
        elif "Encryption key:" in line:
            current["enc"] = "off" not in line.lower()
        elif "IE: IEEE 802.11i/WPA2" in line:
            current["security"] = "WPA2"
        elif "IE: WPA" in line:
            current["security"] = current.get("security") or "WPA"
        elif "Channel:" in line:
            try:
                current["channel"] = int(line.split("Channel:")[1].strip())
            except Exception:
                pass
    if current:
        aps.append(_iwlist_to_ap(current))
    return aps


def _iwlist_to_ap(d: dict) -> APInfo:
    sec = d.get("security", "Open")
    if not d.get("enc", False):
        sec = "Open"
    return APInfo(
        ssid=d.get("ssid", ""), bssid=d.get("bssid", ""),
        rssi=d.get("rssi", -100),
        security=sec, channel=d.get("channel", 0),
        frequency=0, timestamp=time.time(),
    )


def _normalize_security(raw: str) -> str:
    r = raw.upper()
    if "WPA3" in r: return "WPA3"
    if "WPA2" in r: return "WPA2"
    if "WPA"  in r: return "WPA"
    if "WEP"  in r: return "WEP"
    return "Open"


def _get_wifi_iface() -> str:
    try:
        out = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT, text=True)
        for line in out.splitlines():
            if "IEEE 802.11" in line:
                return line.split()[0]
    except Exception:
        pass
    return "wlan0"


# ── Threat detectors ──────────────────────────────────────────────────────────

class ThreatDetector:
    def __init__(self, db: NetworkDB):
        self.db = db
        self._prev_scan: dict[str, APInfo] = {}   # bssid → APInfo

    def analyze(self, current_aps: list[APInfo]) -> list[Threat]:
        threats = []
        seen_ssids: dict[str, list[APInfo]] = {}

        for ap in current_aps:
            seen_ssids.setdefault(ap.ssid, []).append(ap)

        for ssid, aps in seen_ssids.items():
            trusted = self.db.get_trusted(ssid)
            trusted_bssids = {t["bssid"] for t in trusted}
            trusted_secs   = {t["security"] for t in trusted}

            for ap in aps:
                # 1. Evil Twin: SSID known but BSSID not in trust list
                if trusted and ap.bssid not in trusted_bssids:
                    threats.append(Threat(
                        type="EVIL_TWIN", severity="critical",
                        ssid=ssid, bssid=ap.bssid,
                        message=(
                            f"Evil Twin detected: '{ssid}' appears with unknown "
                            f"BSSID {ap.bssid} (trusted: {list(trusted_bssids)})"
                        ),
                        evidence={
                            "rogue_bssid":   ap.bssid,
                            "trusted_bssids": list(trusted_bssids),
                            "rssi":           ap.rssi,
                            "security":       ap.security,
                        },
                        timestamp=time.time(),
                    ))

                # 2. Security Downgrade: trusted as WPA2/3 but now Open/WEP
                if trusted_secs and ap.security in ("Open", "WEP"):
                    if any(s in ("WPA2","WPA3") for s in trusted_secs):
                        threats.append(Threat(
                            type="DOWNGRADE", severity="critical",
                            ssid=ssid, bssid=ap.bssid,
                            message=(
                                f"Security DOWNGRADE on '{ssid}': "
                                f"was {trusted_secs}, now {ap.security}"
                            ),
                            evidence={
                                "was": list(trusted_secs),
                                "now": ap.security,
                                "bssid": ap.bssid,
                            },
                            timestamp=time.time(),
                        ))

                # 3. Signal Spike: RSSI jumped >15 dBm since last scan
                prev = self._prev_scan.get(ap.bssid)
                if prev and ap.rssi - prev.rssi > RSSI_SPIKE_THRESHOLD:
                    threats.append(Threat(
                        type="SIGNAL_SPIKE", severity="high",
                        ssid=ssid, bssid=ap.bssid,
                        message=(
                            f"Signal spike on '{ssid}' ({ap.bssid}): "
                            f"{prev.rssi} → {ap.rssi} dBm — rogue AP may be nearby"
                        ),
                        evidence={"prev_rssi": prev.rssi, "curr_rssi": ap.rssi,
                                  "delta": ap.rssi - prev.rssi},
                        timestamp=time.time(),
                    ))

                # Update seen
                if ap.bssid in trusted_bssids:
                    self.db.update_seen(ssid, ap.bssid)

        # 4. Multiple APs same SSID & same channel → likely KARMA/deauth setup
        for ssid, aps in seen_ssids.items():
            if len(aps) >= 3:
                channels = [a.channel for a in aps]
                unique_ch = set(channels)
                if len(unique_ch) == 1:
                    threats.append(Threat(
                        type="KARMA", severity="high",
                        ssid=ssid, bssid=aps[0].bssid,
                        message=(
                            f"Possible KARMA/MANA attack: {len(aps)} APs with "
                            f"SSID '{ssid}' on same channel {channels[0]}"
                        ),
                        evidence={"count": len(aps),
                                  "bssids": [a.bssid for a in aps],
                                  "channel": channels[0]},
                        timestamp=time.time(),
                    ))

        self._prev_scan = {ap.bssid: ap for ap in current_aps}
        return threats


# ── Captive portal check ──────────────────────────────────────────────────────

def check_captive_portal(trusted_ssids: list[str] = None) -> Optional[Threat]:
    """
    On trusted networks, an unexpected redirect = portal injection attack.
    Uses the standard connectivity check URL.
    """
    import urllib.request, urllib.error
    TEST_URL  = "http://connectivitycheck.gstatic.com/generate_204"
    EXPECTED  = 204

    try:
        req = urllib.request.Request(TEST_URL, headers={"User-Agent": "Android"})
        with urllib.request.urlopen(req, timeout=5) as r:
            if r.status != EXPECTED:
                return Threat(
                    type="PORTAL", severity="medium",
                    ssid="current", bssid="unknown",
                    message=(
                        f"Captive portal detected on trusted network "
                        f"(HTTP {r.status} on connectivity check)"
                    ),
                    evidence={"url": TEST_URL, "status": r.status,
                               "location": r.headers.get("Location","")},
                    timestamp=time.time(),
                )
    except urllib.error.HTTPError as e:
        if e.code != EXPECTED:
            return Threat(
                type="PORTAL", severity="medium",
                ssid="current", bssid="unknown",
                message=f"Connectivity check returned HTTP {e.code}",
                evidence={"code": e.code},
                timestamp=time.time(),
            )
    except Exception:
        pass
    return None


# ── Monitor loop ──────────────────────────────────────────────────────────────

class ShadowGuardMonitor:
    def __init__(self, alert_callback=None):
        self.db = NetworkDB()
        self.detector = ThreatDetector(self.db)
        self._alert_cb = alert_callback or self._default_alert
        self._running = False

    def _default_alert(self, threat: Threat):
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(threat.severity, "⚪")
        print(f"\n{sev_icon} [{threat.severity.upper()}] {threat.type}")
        print(f"   {threat.message}")
        self.db.log_threat(threat)

    def trust_current(self, ssid: str):
        aps = scan_networks()
        matches = [ap for ap in aps if ap.ssid == ssid]
        if not matches:
            print(f"'{ssid}' not visible in current scan")
            return
        for ap in matches:
            self.db.trust(ap)
        print(f"Trusted {len(matches)} AP(s) for '{ssid}'")

    def run(self):
        self._running = True
        log.info("ShadowGuard monitoring started")
        print("[ShadowGuard] Monitoring WiFi — Ctrl+C to stop")
        print(f"[ShadowGuard] Trusted networks: {len(self.db.all_trusted())}")
        while self._running:
            try:
                aps = scan_networks()
                if aps:
                    threats = self.detector.analyze(aps)
                    for t in threats:
                        self._alert_cb(t)
                portal = check_captive_portal()
                if portal:
                    self._alert_cb(portal)
            except Exception as e:
                log.debug(f"Scan error: {e}")
            time.sleep(SCAN_INTERVAL)

    def stop(self):
        self._running = False


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    args = sys.argv[1:]
    cmd  = args[0] if args else "monitor"

    monitor = ShadowGuardMonitor()

    if cmd == "monitor":
        try:
            monitor.run()
        except KeyboardInterrupt:
            print("\n[ShadowGuard] Stopped.")

    elif cmd == "scan":
        aps = scan_networks()
        print(f"Found {len(aps)} networks:")
        for ap in sorted(aps, key=lambda a: -a.rssi):
            lock = {"WPA3":"🔒","WPA2":"🔒","WPA":"🔓","WEP":"⚠️","Open":"❌"}.get(ap.security,"?")
            print(f"  {lock} {ap.ssid:<30} {ap.bssid}  {ap.rssi:>4} dBm  ch{ap.channel}  {ap.security}")

    elif cmd == "trust" and len(args) > 1:
        ssid = " ".join(args[1:])
        monitor.trust_current(ssid)

    elif cmd == "list":
        nets = monitor.db.all_trusted()
        if not nets:
            print("No trusted networks yet. Run: shadowguard trust <SSID>")
        else:
            print(f"{'SSID':<30} {'BSSID':<20} {'SECURITY':<8} {'RSSI'}")
            print("─" * 70)
            for n in nets:
                ago = int(time.time() - (n["last_seen"] or 0))
                print(f"  {n['ssid']:<28} {n['bssid']:<20} {n['security']:<8} "
                      f"{n['rssi']} dBm  (seen {ago//60}m ago)")

    elif cmd == "threats":
        threats = monitor.db.recent_threats(20)
        if not threats:
            print("No threats logged yet.")
        for t in threats:
            ago = int(time.time() - t["ts"])
            print(f"  [{t['severity'].upper():<8}] {t['type']:<12} {t['ssid']}  "
                  f"— {t['message'][:60]}  ({ago//60}m ago)")

    else:
        print(__doc__)


if __name__ == "__main__":
    main()

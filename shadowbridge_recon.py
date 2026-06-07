#!/usr/bin/env python3
"""
ShadowBridge Recon Engine
Detects Home vs Corporate network environment and configures the node accordingly.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("shadowbridge-recon")

RESULT_FILE = os.environ.get("RECON_RESULT", "/tmp/shadowbridge_recon.json")


# ── Network discovery ─────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception:
        return ""


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_gateway() -> str:
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via ([\d.]+)", out)
    return m.group(1) if m else ""


def get_subnet() -> str:
    out = _run(["ip", "route"])
    local_ip = get_local_ip()
    prefix = ".".join(local_ip.split(".")[:3])
    for line in out.splitlines():
        if prefix in line and "/" in line:
            parts = line.split()
            if parts:
                return parts[0]
    return f"{prefix}.0/24"


def arp_scan(subnet: str) -> list[dict]:
    """Return list of {ip, mac, vendor} for live hosts."""
    hosts = []
    out = _run(["nmap", "-sn", "-T4", "--host-timeout", "3s", subnet], timeout=40)
    ip, mac = None, None
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (.+)", line)
        if m:
            ip = m.group(1).split()[-1].strip("()")
            mac = None
        m = re.search(r"MAC Address: ([0-9A-F:]+)\s*\((.+?)\)", line)
        if m and ip:
            mac = m.group(1)
            vendor = m.group(2)
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor})
            ip = None
    return hosts


# ── Corporate signals ─────────────────────────────────────────────────────────

CORPORATE_VENDORS = {
    "cisco", "juniper", "fortinet", "palo alto", "aruba", "ubiquiti",
    "hp enterprise", "dell emc", "vmware", "checkpoint",
}

CORPORATE_PORTS = {389, 636, 445, 88, 3268, 3269}   # LDAP, SMB, Kerberos, GlobalCatalog
HOME_PORTS      = {80, 443, 53, 22}


def _scan_ports(ip: str, ports: set, timeout: int = 2) -> set:
    open_ports = set()
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.add(port)
        except Exception:
            pass
    return open_ports


def score_corporate(hosts: list, gateway: str) -> dict:
    score = 0
    evidence = []

    # Corporate network gear
    for h in hosts:
        vendor_lower = h.get("vendor", "").lower()
        for corp_vendor in CORPORATE_VENDORS:
            if corp_vendor in vendor_lower:
                score += 30
                evidence.append(f"Corporate device: {h['ip']} ({h['vendor']})")

    # Host count (>20 = likely corporate)
    if len(hosts) > 20:
        score += 20
        evidence.append(f"Large network: {len(hosts)} hosts")
    elif len(hosts) > 8:
        score += 10
        evidence.append(f"Medium network: {len(hosts)} hosts")

    # Active Directory / LDAP / SMB on gateway or nearby
    if gateway:
        open_corp = _scan_ports(gateway, CORPORATE_PORTS)
        if open_corp:
            score += 40
            evidence.append(f"AD/LDAP/SMB on gateway: ports {open_corp}")

    # Domain suffix in hostname
    fqdn = socket.getfqdn()
    if "." in fqdn and not fqdn.endswith(".local") and not fqdn.endswith(".home"):
        score += 15
        evidence.append(f"Domain-joined hostname: {fqdn}")

    return {"score": score, "evidence": evidence}


# ── Mode decision ─────────────────────────────────────────────────────────────

def decide_mode(corp_score: int) -> str:
    if corp_score >= 50:
        return "corporate"
    if corp_score >= 25:
        return "hybrid"
    return "home"


# ── Config output per mode ────────────────────────────────────────────────────

MODE_CONFIG = {
    "home": {
        "suricata_ruleset": "emerging-threats-lite",
        "honeypot_profile": "home",
        "wazuh_agent": False,
        "aggressive_ids": False,
        "ad_honeypot": False,
        "description": "Otthoni mód: alacsony zajszint, IoT monitoring, alapvető honeypotok",
    },
    "hybrid": {
        "suricata_ruleset": "emerging-threats",
        "honeypot_profile": "smb-basic",
        "wazuh_agent": True,
        "aggressive_ids": False,
        "ad_honeypot": False,
        "description": "Hibrid mód: fokozott monitoring, SMB honeypot",
    },
    "corporate": {
        "suricata_ruleset": "emerging-threats-full",
        "honeypot_profile": "ad-full",
        "wazuh_agent": True,
        "aggressive_ids": True,
        "ad_honeypot": True,
        "description": "Vállalati mód: teljes Wazuh+Suricata, hamis AD/SMB honeypot",
    },
}


# ── Main ──────────────────────────────────────────────────────────────────────

def run_recon() -> dict:
    log.info("ShadowBridge Recon Engine starting...")

    local_ip = get_local_ip()
    gateway  = get_gateway()
    subnet   = get_subnet()

    log.info(f"Local IP: {local_ip} | Gateway: {gateway} | Subnet: {subnet}")
    log.info(f"Scanning {subnet} ...")

    t0    = time.time()
    hosts = arp_scan(subnet)
    log.info(f"Found {len(hosts)} hosts in {round(time.time()-t0, 1)}s")

    corp  = score_corporate(hosts, gateway)
    mode  = decide_mode(corp["score"])
    cfg   = MODE_CONFIG[mode]

    result = {
        "timestamp":  int(time.time()),
        "local_ip":   local_ip,
        "gateway":    gateway,
        "subnet":     subnet,
        "host_count": len(hosts),
        "hosts":      hosts[:20],
        "corp_score": corp["score"],
        "evidence":   corp["evidence"],
        "mode":       mode,
        "config":     cfg,
    }

    with open(RESULT_FILE, "w") as f:
        json.dump(result, f, indent=2)

    log.info(f"Mode: {mode.upper()} (score={corp['score']})")
    log.info(f"Description: {cfg['description']}")
    for e in corp["evidence"]:
        log.info(f"  + {e}")
    log.info(f"Result saved to {RESULT_FILE}")

    return result


if __name__ == "__main__":
    r = run_recon()
    print(json.dumps(r, indent=2))

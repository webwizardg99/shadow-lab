#!/usr/bin/env python3
"""
ShadowKey Profile Engine
Loads environment-specific security profiles based on recon results.

Profiles:
  home       — home/personal network, basic protection
  work       — SMB office/hybrid, medium hardening
  corporate  — AD domain, full SOC mode + Tor bridge

Each profile returns a config dict consumed by shadowkey_init.sh
via JSON on stdout.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

RECON_SCRIPT = Path(__file__).parent.parent / "shadowbridge_recon.py"
PROFILES_DIR = Path(__file__).parent / "profiles"

# ── Profile definitions ───────────────────────────────────────────────────────

PROFILES = {
    "home": {
        "suricata": {
            "enabled": True,
            "ruleset": "emerging-threats-lite",
            "interfaces": ["auto"],
        },
        "honeypot": {
            "enabled": False,
        },
        "shadowmesh": {
            "enabled": True,
            "tor_bridge": False,
            "wg_enabled": True,
        },
        "firewall": {
            "preset": "home",
            "block_inbound": False,
            "allow_mdns": True,
        },
        "dashboard": {
            "theme": "dark",
            "show_recon": False,
            "show_ai_tasks": True,
            "alert_level": "medium",
        },
        "browser_homepage": "http://localhost:8888",
        "description": "Otthoni környezet — alap védelem, mesh hálózat",
    },

    "work": {
        "suricata": {
            "enabled": True,
            "ruleset": "emerging-threats-full",
            "interfaces": ["auto"],
            "alert_on_lateral": True,
        },
        "honeypot": {
            "enabled": True,
            "profile": "office",
            "ports": [2222, 8080],
        },
        "shadowmesh": {
            "enabled": True,
            "tor_bridge": False,
            "wg_enabled": True,
        },
        "firewall": {
            "preset": "work",
            "block_inbound": True,
            "allow_mdns": False,
            "block_smb_outbound": False,
        },
        "dashboard": {
            "theme": "dark",
            "show_recon": True,
            "show_ai_tasks": True,
            "alert_level": "high",
        },
        "browser_homepage": "http://localhost:8888/alerts",
        "description": "Munkahelyi / hibrid környezet — fokozott védelem",
    },

    "corporate": {
        "suricata": {
            "enabled": True,
            "ruleset": "emerging-threats-full",
            "interfaces": ["auto"],
            "alert_on_lateral": True,
            "alert_on_ad_enum": True,
        },
        "honeypot": {
            "enabled": True,
            "profile": "corporate",
            "ports": [2222, 8080, 4450],
            "ad_honeypot": True,
        },
        "shadowmesh": {
            "enabled": True,
            "tor_bridge": True,
            "wg_enabled": True,
        },
        "firewall": {
            "preset": "corporate",
            "block_inbound": True,
            "allow_mdns": False,
            "block_smb_outbound": True,
            "dns_over_https": True,
        },
        "dashboard": {
            "theme": "dark",
            "show_recon": True,
            "show_ai_tasks": True,
            "alert_level": "critical",
        },
        "browser_homepage": "http://localhost:8888/alerts",
        "description": "Vállalati / AD környezet — teljes SOC mód + Tor bridge",
    },
}


# ── Recon runner ──────────────────────────────────────────────────────────────

def run_recon() -> dict:
    if not RECON_SCRIPT.exists():
        return {"mode": "home", "corp_score": 0, "error": "recon script not found"}
    try:
        result = subprocess.run(
            [sys.executable, str(RECON_SCRIPT)],
            capture_output=True, text=True, timeout=90,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception as e:
        pass
    return {"mode": "home", "corp_score": 0}


# ── Profile selector ──────────────────────────────────────────────────────────

def select_profile(recon: dict) -> str:
    mode = recon.get("mode", "home")
    score = recon.get("corp_score", 0)
    # Allow env override (e.g. user chose "work" from boot menu)
    override = os.environ.get("SHADOWKEY_PROFILE")
    if override and override in PROFILES:
        return override
    if mode == "corporate" or score >= 50:
        return "corporate"
    if mode == "hybrid" or score >= 25:
        return "work"
    return "home"


# ── Config merger ─────────────────────────────────────────────────────────────

def build_config(profile_name: str, recon: dict) -> dict:
    profile = dict(PROFILES[profile_name])

    # Inject live recon data
    profile["_meta"] = {
        "profile":    profile_name,
        "recon_mode": recon.get("mode"),
        "corp_score": recon.get("corp_score", 0),
        "gateway":    recon.get("gateway"),
        "ad_domain":  recon.get("ad_domain"),
        "hostname":   recon.get("hostname"),
    }

    # Auto-detect network interface
    iface = _detect_primary_interface()
    if iface:
        profile["suricata"]["interfaces"] = [iface]
        profile["_meta"]["interface"] = iface

    return profile


def _detect_primary_interface() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        result = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if ip in line:
                return line.split()[1]
    except Exception:
        pass
    return ""


# ── Firewall rules writer ─────────────────────────────────────────────────────

def write_nftables(config: dict, path: str = "/tmp/shadowkey_nft.conf"):
    fw = config.get("firewall", {})
    preset = fw.get("preset", "home")

    rules = [
        "#!/usr/sbin/nft -f",
        "flush ruleset",
        "",
        "table inet shadowkey {",
        "  chain input {",
        "    type filter hook input priority 0; policy accept;",
        "    ct state established,related accept",
        "    iif lo accept",
    ]

    if fw.get("block_inbound"):
        rules += [
            "    # Drop unsolicited inbound (work/corp mode)",
            "    tcp dport { 135, 139, 445 } drop comment \"block SMB inbound\"",
            "    tcp dport { 389, 636 } drop comment \"block LDAP inbound\"",
        ]

    if fw.get("block_smb_outbound"):
        rules += [
            "  }",
            "  chain output {",
            "    type filter hook output priority 0; policy accept;",
            "    tcp dport { 445 } drop comment \"block SMB outbound (corp mode)\"",
        ]

    rules += ["  }", "}"]

    Path(path).write_text("\n".join(rules))
    return path


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="ShadowKey profile engine")
    parser.add_argument("--profile", help="Force profile (home/work/corporate)")
    parser.add_argument("--no-recon", action="store_true", help="Skip recon, use forced profile")
    parser.add_argument("--write-nft", action="store_true", help="Write nftables config")
    parser.add_argument("--recon-json", help="Use pre-run recon JSON file")
    args = parser.parse_args()

    if args.recon_json:
        recon = json.loads(Path(args.recon_json).read_text())
    elif args.no_recon:
        recon = {"mode": args.profile or "home", "corp_score": 0}
    else:
        print("[*] Running environment recon...", file=sys.stderr)
        recon = run_recon()
        print(f"[*] Recon result: mode={recon.get('mode')} score={recon.get('corp_score', 0)}", file=sys.stderr)

    profile_name = args.profile if args.profile in PROFILES else select_profile(recon)
    config = build_config(profile_name, recon)

    if args.write_nft:
        nft_path = write_nftables(config)
        print(f"[*] nftables config written to {nft_path}", file=sys.stderr)

    print(json.dumps(config, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

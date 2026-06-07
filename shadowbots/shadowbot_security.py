#!/usr/bin/env python3
"""
ShadowBot Security — IDS Alert Analyst
Continuously monitors Suricata EVE logs and ShadowBridge alerts.
Correlates events, identifies attack patterns, escalates to Sentinel.
"""
import json
import os
import re
import time
from collections import defaultdict
from pathlib import Path

from shadowbot_base import ShadowBotBase, log

SURICATA_LOG = Path(os.environ.get("SURICATA_EVE_LOG", "/tmp/suricata/eve.json"))
SEEN_POSITION_KEY = "suricata_file_pos"
CORRELATION_WINDOW = 300   # 5 min window for attack correlation
ESCALATION_THRESHOLD = 3   # distinct events before escalating to Sentinel


class SecurityBot(ShadowBotBase):
    NAME           = "security"
    PREFERRED_MODEL = "lfm2.5:latest"   # reasoning model for analysis
    TASK_TYPES     = ["security", "threat_analysis", "alert_review"]
    SYSTEM_PROMPT  = """You are ShadowBot Security — an expert threat analyst.
You analyze network events, correlate attack patterns, and classify threats.
Be concise, technical, and actionable. Use MITRE ATT&CK framework when relevant.
Format findings as: SEVERITY | TECHNIQUE | RECOMMENDATION"""

    def __init__(self, token: str = ""):
        super().__init__(token)
        self._recent_events: list = []   # in-memory correlation buffer
        self._attacker_counts: dict = defaultdict(int)

    # ── Autonomous cycle: watch Suricata + dashboard alerts ───────────────────

    def autonomous_cycle(self):
        self._read_suricata_eve()
        self._correlate_and_escalate()
        self._review_dashboard_alerts()

    def _read_suricata_eve(self):
        if not SURICATA_LOG.exists():
            return
        pos = self.memory.get(SEEN_POSITION_KEY, 0)
        try:
            with open(SURICATA_LOG) as f:
                f.seek(pos)
                new_events = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        if ev.get("event_type") in ("alert", "anomaly", "dns", "http"):
                            new_events.append(ev)
                    except json.JSONDecodeError:
                        pass
                new_pos = f.tell()

            if new_events:
                self.memory.set(SEEN_POSITION_KEY, new_pos)
                self.log.info(f"Read {len(new_events)} new Suricata events")
                for ev in new_events:
                    self._process_suricata_event(ev)
        except Exception as e:
            self.log.debug(f"Suricata read error: {e}")

    def _process_suricata_event(self, ev: dict):
        src = ev.get("src_ip", "")
        event_type = ev.get("event_type", "")
        now = time.time()

        if event_type == "alert":
            alert = ev.get("alert", {})
            sig = alert.get("signature", "Unknown")
            severity = alert.get("severity", 3)
            sev_label = {1: "critical", 2: "high", 3: "medium"}.get(severity, "low")

            self.log.warning(f"IDS Alert: [{sev_label}] {sig} from {src}")
            self.memory.log_event("ids_alert", {
                "src": src, "sig": sig, "severity": sev_label, "ts": now
            })
            self._recent_events.append({
                "src": src, "type": "ids_alert", "sig": sig,
                "severity": sev_label, "ts": now
            })
            self._attacker_counts[src] += 1

            # Immediate critical alert to dashboard
            if severity <= 2:
                self.alert(
                    f"IDS [{sev_label.upper()}]: {sig} — src: {src}",
                    severity=sev_label,
                    alert_type="ids.alert",
                    data={"src_ip": src, "signature": sig, "raw": ev},
                )

        # Prune old events
        cutoff = now - CORRELATION_WINDOW
        self._recent_events = [e for e in self._recent_events if e["ts"] > cutoff]

    def _correlate_and_escalate(self):
        """If same source triggers 3+ distinct alerts → full AI analysis."""
        for src, count in list(self._attacker_counts.items()):
            if count >= ESCALATION_THRESHOLD:
                events = [e for e in self._recent_events if e["src"] == src]
                self._escalate_to_ai(src, events)
                self._attacker_counts[src] = 0

    def _escalate_to_ai(self, src_ip: str, events: list):
        self.log.info(f"Escalating {src_ip} ({len(events)} events) to AI analysis")
        summary = "\n".join(
            f"- [{e['severity']}] {e.get('sig','?')} at {e['ts']:.0f}"
            for e in events[:10]
        )
        prompt = (
            f"Analyze this attack pattern from {src_ip}:\n{summary}\n\n"
            "Classify the attack, identify the MITRE technique, "
            "and recommend immediate countermeasures."
        )
        analysis = self.think(prompt)
        self.log.info(f"AI analysis for {src_ip}: {analysis[:200]}")
        self.alert(
            f"Attack pattern from {src_ip}: {analysis[:300]}",
            severity="high",
            alert_type="bot.security.escalation",
            data={"src_ip": src_ip, "event_count": len(events), "analysis": analysis},
        )
        self.memory.log_event("escalation", {
            "src": src_ip, "events": len(events), "analysis": analysis
        })

    def _review_dashboard_alerts(self):
        """Periodically review unacked dashboard alerts with AI eyes."""
        last_review = self.memory.get("last_alert_review", 0)
        if time.time() - last_review < 120:   # every 2 min
            return
        self.memory.set("last_alert_review", time.time())

        alerts = self.get_alerts(unacked_only=True)
        if not alerts:
            return
        if len(alerts) < 3:
            return  # not enough to be interesting

        summary = "\n".join(
            f"- [{a.get('severity','?')}] {a.get('message','')[:100]}"
            for a in alerts[:15]
        )
        prompt = (
            f"Review these {len(alerts)} unacknowledged security alerts:\n{summary}\n\n"
            "Identify the most critical pattern. Is this a coordinated attack? "
            "What single action should the operator take first?"
        )
        insight = self.think(prompt)
        if len(insight) > 50:
            self.alert(
                f"Alert pattern analysis: {insight[:400]}",
                severity="medium",
                alert_type="bot.security.insight",
            )

    # ── Task handler ──────────────────────────────────────────────────────────

    def handle_task(self, task: dict) -> str:
        prompt = task.get("prompt", "")
        ttype  = task.get("type", "security")

        if ttype == "alert_review":
            alerts = self.get_alerts()
            ctx = json.dumps(alerts[:20], indent=2)
            return self.think(
                f"Review and summarize these alerts:\n{ctx}\n\nUser query: {prompt}"
            )

        if ttype == "threat_analysis":
            recon = self.get_recon()
            ctx = json.dumps(recon, indent=2)
            return self.think(
                f"Network recon data:\n{ctx}\n\nAnalyze: {prompt}"
            )

        return self.think(prompt)


if __name__ == "__main__":
    import logging, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    token = sys.argv[1] if len(sys.argv) > 1 else ""
    SecurityBot(token).run()

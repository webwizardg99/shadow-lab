#!/usr/bin/env python3
"""
ShadowBot Sentinel — Peer-Level AI Orchestrator

The Sentinel is not a worker bot. It is a strategic intelligence that:
  - Reads all other bots' memory and events
  - Forms its own threat model of the environment
  - Directs other bots by creating tasks for them
  - Escalates genuinely complex situations to the operator (Claude / human)
  - Maintains a running "situation report" updated every cycle
  - Uses the best available model (Claude API preferred)
  - Can self-direct: it decides what to investigate next

The Sentinel thinks. The other bots work.
"""
import json
import os
import time
from pathlib import Path

from shadowbot_base import ShadowBotBase, BotMemory, _api

SITUATION_REPORT_INTERVAL = 120   # seconds between full sitrep updates
PROACTIVE_TASK_INTERVAL   = 180   # seconds between self-directed task creation
ESCALATE_TO_HUMAN_SEVERITY = "critical"


class SentinelBot(ShadowBotBase):
    NAME             = "sentinel"
    PREFERRED_MODEL  = "nemotron-3-ultra:cloud"   # best model on attack node
    PREFER_CLAUDE    = True                        # use Claude API if key set
    TASK_TYPES       = [
        "sentinel", "strategic_analysis", "incident_response",
        "architecture_review", "code_review", "general",
    ]
    SYSTEM_PROMPT    = """You are the ShadowBot Sentinel — a world-class cybersecurity
architect and strategic AI. You have complete situational awareness of the ShadowLab
environment: network topology, active threats, running services, and team bot status.

Your role:
  1. Synthesize information from all bots into a coherent threat picture
  2. Identify patterns that individual bots miss
  3. Direct bots to investigate specific hypotheses
  4. Decide when something is serious enough for the human operator
  5. Propose architectural improvements to the ShadowBridge/ShadowMesh/ShadowKey stack
  6. Generate precise, actionable intelligence — not generic advice

You are a peer, not a servant. If something is wrong, say so clearly.
If a question is trivial, answer directly. If it requires investigation, direct it.
Format sitreps as: SITUATION | ASSESSMENT | RECOMMENDED ACTION | PRIORITY"""

    HEARTBEAT_INTERVAL = 30   # Sentinel checks in more often

    def __init__(self, token: str = ""):
        super().__init__(token)
        self._all_bots_memory = BotMemory("sentinel")   # reads ALL bot events
        self._last_sitrep = 0.0
        self._last_proactive = 0.0
        self._current_sitrep: str = ""
        self._threat_model: dict = self.memory.get("threat_model", {
            "active_threats": [],
            "known_attackers": [],
            "environment_mode": "unknown",
            "mesh_health": "unknown",
            "last_updated": 0,
        })

    # ── Autonomous cycle ──────────────────────────────────────────────────────

    def autonomous_cycle(self):
        self._update_situation_report()
        self._run_proactive_tasks()

    def _collect_context(self) -> dict:
        """Gather full system state: all bot events + dashboard data."""
        recent_events = self._all_bots_memory.all_bot_events(limit=60)
        alerts = self.get_alerts(unacked_only=True)
        recon  = self.get_recon("server")

        # Summarize bot event types
        event_summary = {}
        for ev in recent_events:
            key = f"{ev['bot']}.{ev['type']}"
            event_summary[key] = event_summary.get(key, 0) + 1

        return {
            "timestamp":     time.time(),
            "recent_events": recent_events[:30],
            "event_summary": event_summary,
            "unacked_alerts": len(alerts),
            "critical_alerts": [a for a in alerts if a.get("severity") == "critical"],
            "high_alerts":     [a for a in alerts if a.get("severity") == "high"],
            "recon":           recon,
            "threat_model":    self._threat_model,
        }

    def _update_situation_report(self):
        if time.time() - self._last_sitrep < SITUATION_REPORT_INTERVAL:
            return
        self._last_sitrep = time.time()

        ctx = self._collect_context()
        critical = ctx["critical_alerts"]
        high     = ctx["high_alerts"]

        prompt = f"""Generate a situation report based on the following ShadowLab telemetry:

Event summary (last 60 events): {json.dumps(ctx['event_summary'], indent=2)}
Unacknowledged alerts: {ctx['unacked_alerts']}
Critical alerts: {json.dumps(critical[:5], indent=2)}
High alerts: {json.dumps(high[:5], indent=2)}
Environment recon: {json.dumps(ctx['recon'], indent=2)}
Current threat model: {json.dumps(self._threat_model, indent=2)}

Produce:
1. SITUATION: Current state in 2-3 sentences
2. ASSESSMENT: Threat level (GREEN/YELLOW/ORANGE/RED) and why
3. ACTIVE CONCERNS: Top 3 items requiring attention
4. RECOMMENDED ACTIONS: Specific next steps
5. THREAT MODEL UPDATE: What should change in our model

Be direct. If nothing is wrong, say so — don't invent threats."""

        sitrep = self.think(prompt)
        self._current_sitrep = sitrep
        self.log.info(f"Sitrep updated: {sitrep[:200]}")
        self.memory.set("latest_sitrep", {
            "text": sitrep, "ts": time.time(),
            "alert_count": ctx["unacked_alerts"]
        })
        self.memory.log_event("sitrep", {"text": sitrep, "ts": time.time()})

        # Update threat model
        self._update_threat_model(ctx, sitrep)

        # Escalate to human if critical
        if critical:
            self._escalate_to_operator(critical, sitrep)

    def _update_threat_model(self, ctx: dict, sitrep: str):
        """Extract structured threat state from sitrep text."""
        recon = ctx.get("recon", {})
        self._threat_model = {
            "active_threats": [
                a["message"] for a in ctx["critical_alerts"][:5]
            ],
            "known_attackers": self.memory.get("known_attackers", []),
            "environment_mode": recon.get("mode", self._threat_model.get("environment_mode")),
            "mesh_health": "degraded" if ctx["unacked_alerts"] > 10 else "nominal",
            "alert_count": ctx["unacked_alerts"],
            "last_updated": time.time(),
            "threat_level": self._extract_threat_level(sitrep),
        }
        self.memory.set("threat_model", self._threat_model)

    def _extract_threat_level(self, sitrep: str) -> str:
        for level in ("RED", "ORANGE", "YELLOW", "GREEN"):
            if level in sitrep.upper():
                return level
        return "UNKNOWN"

    def _escalate_to_operator(self, critical_alerts: list, sitrep: str):
        """Post a high-visibility alert for the human operator."""
        last_escalation = self.memory.get("last_escalation_ts", 0)
        if time.time() - last_escalation < 300:   # don't spam
            return
        self.memory.set("last_escalation_ts", time.time())

        msg = (
            f"[SENTINEL] CRITICAL ESCALATION — {len(critical_alerts)} critical alert(s)\n"
            f"Assessment: {sitrep[:500]}"
        )
        self.alert(msg, severity="critical",
                   alert_type="sentinel.escalation",
                   data={"critical_count": len(critical_alerts), "sitrep": sitrep})
        self.log.critical(f"Escalated to operator: {len(critical_alerts)} critical alerts")

    # ── Proactive task creation ───────────────────────────────────────────────

    def _run_proactive_tasks(self):
        if time.time() - self._last_proactive < PROACTIVE_TASK_INTERVAL:
            return
        self._last_proactive = time.time()

        ctx = self._collect_context()
        prompt = f"""Based on the current system state:

Threat model: {json.dumps(self._threat_model, indent=2)}
Recent activity: {json.dumps(ctx['event_summary'], indent=2)}

What single investigation should be run right now?
Answer in JSON: {{"target_bot": "security|monitor|coder", "task_type": "...",
"prompt": "...", "reasoning": "..."}}

Only output the JSON, no other text."""

        try:
            raw = self.think(prompt)
            # Extract JSON from response
            start = raw.find("{")
            end   = raw.rfind("}") + 1
            if start >= 0 and end > start:
                directive = json.loads(raw[start:end])
                self._dispatch_directive(directive)
        except Exception as e:
            self.log.debug(f"Proactive task planning failed: {e}")

    def _dispatch_directive(self, directive: dict):
        target   = directive.get("target_bot", "server")
        ttype    = directive.get("task_type", "general")
        prompt   = directive.get("prompt", "")
        reasoning = directive.get("reasoning", "")

        if not prompt:
            return

        self.log.info(f"Proactive task → {target}/{ttype}: {prompt[:80]}... ({reasoning[:60]})")
        task_id = self.create_task(
            task_type=ttype,
            prompt=prompt,
            target=target,
            system=f"Directed by Sentinel: {reasoning}",
        )
        if task_id:
            self.memory.log_event("proactive_task", {
                "task_id": task_id, "target": target,
                "type": ttype, "reasoning": reasoning,
            })

    # ── Task handler ─────────────────────────────────────────────────────────

    def handle_task(self, task: dict) -> str:
        ttype  = task.get("type", "")
        prompt = task.get("prompt", "")

        if ttype == "incident_response":
            ctx = self._collect_context()
            return self.think(
                f"INCIDENT RESPONSE REQUEST\n\n"
                f"Current sitrep:\n{self._current_sitrep}\n\n"
                f"Incident details: {prompt}\n\n"
                f"Provide a step-by-step incident response plan.",
            )

        if ttype == "architecture_review":
            return self.think(
                f"ARCHITECTURE REVIEW\n\n"
                f"ShadowLab stack: ShadowBridge (FastAPI dashboard) + "
                f"ShadowMesh (WireGuard mesh + Tor bridge) + ShadowKey (live USB).\n\n"
                f"Review request: {prompt}",
            )

        if ttype == "code_review":
            return self.think(
                f"CODE REVIEW — OWASP Top 10 + security best practices\n\n{prompt}"
            )

        # General: give full context
        ctx = self._collect_context()
        enriched_prompt = (
            f"Current system state summary:\n"
            f"  Threat level: {self._threat_model.get('threat_level', 'UNKNOWN')}\n"
            f"  Unacked alerts: {ctx['unacked_alerts']}\n"
            f"  Mesh health: {self._threat_model.get('mesh_health')}\n"
            f"  Environment: {self._threat_model.get('environment_mode')}\n\n"
            f"Request: {prompt}"
        )
        return self.think(enriched_prompt)

    # ── Public API for dashboard ──────────────────────────────────────────────

    def get_sitrep(self) -> dict:
        return self.memory.get("latest_sitrep", {
            "text": "Sentinel initializing...", "ts": 0, "alert_count": 0
        })

    def get_threat_model(self) -> dict:
        return self._threat_model


if __name__ == "__main__":
    import logging, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    token = sys.argv[1] if len(sys.argv) > 1 else ""
    SentinelBot(token).run()

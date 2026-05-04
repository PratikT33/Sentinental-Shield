"""
logger.py — Sentinel Shield
Step 5: Logging System — records every WAF decision to structured log files.
"""

import json
import os
import time
from datetime import datetime
from waf import DetectionResult

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

ATTACK_LOG  = os.path.join(LOG_DIR, "attack.log")
TRAFFIC_LOG = os.path.join(LOG_DIR, "traffic.log")


def _build_entry(result: DetectionResult) -> dict:
    """Convert a DetectionResult into a structured log dict."""
    req = result.request
    return {
        "timestamp"  : datetime.fromtimestamp(result.timestamp).isoformat(),
        "epoch"      : result.timestamp,
        "ip"         : req.ip,
        "method"     : req.method,
        "path"       : req.path,
        "user_agent" : req.user_agent,
        "body"       : req.body[:200],    # truncate long bodies
        "allowed"    : result.allowed,
        "reason"     : result.reason,
        "rules_hit"  : [
            {
                "id"       : r.rule_id,
                "name"     : r.name,
                "category" : r.category,
                "severity" : r.severity,
            }
            for r in result.triggered
        ],
    }


def log_result(result: DetectionResult):
    """Write a WAF decision to the appropriate log file."""
    entry = _build_entry(result)
    line  = json.dumps(entry)

    # Every request → traffic log
    with open(TRAFFIC_LOG, "a") as f:
        f.write(line + "\n")

    # Only blocked requests → attack log
    if not result.allowed:
        with open(ATTACK_LOG, "a") as f:
            f.write(line + "\n")

    return entry


# ─────────────────────────────────────────────
# Log reader (Step 5 — examination helpers)
# ─────────────────────────────────────────────

def read_attack_log() -> list[dict]:
    """Return all entries from the attack log."""
    return _read_log(ATTACK_LOG)


def read_traffic_log() -> list[dict]:
    """Return all entries from the traffic log."""
    return _read_log(TRAFFIC_LOG)


def _read_log(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def clear_logs():
    """Utility: wipe both logs (use between test runs)."""
    for path in [ATTACK_LOG, TRAFFIC_LOG]:
        if os.path.exists(path):
            os.remove(path)

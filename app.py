"""
app.py — Sentinel Shield Flask Server
Wraps the WAF engine as a real HTTP server with:
  • /inspect  — POST endpoint: submit a request for WAF inspection
  • /dashboard — GET endpoint: live JSON stats
  • /logs      — GET endpoint: recent log entries
  • /health    — GET endpoint: health check
"""

import os, json
from flask import Flask, request, jsonify, abort
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# ── add parent dir so we can import the existing modules ──────────────────
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "sentinel_shield"))

from waf       import WAFEngine, HTTPRequest
from logger    import log_result, read_attack_log, read_traffic_log, clear_logs
from dashboard import run_dashboard

# ─────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)

RATE_LIMIT      = int(os.getenv("RATE_LIMIT",      "15"))
RATE_WINDOW     = int(os.getenv("RATE_WINDOW",     "60"))
BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "3"))

waf = WAFEngine(
    rate_limit       = RATE_LIMIT,
    rate_window      = RATE_WINDOW,
    block_threshold  = BLOCK_THRESHOLD,
)

# ─────────────────────────────────────────────────────────────
# Helper: get real client IP (respects X-Forwarded-For from Nginx)
# ─────────────────────────────────────────────────────────────
def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else request.remote_addr


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Health check — used by Docker and load balancers."""
    return jsonify({"status": "ok", "service": "sentinel-shield"})


@app.route("/inspect", methods=["POST"])
def inspect():
    """
    Submit an HTTP request description for WAF inspection.

    POST body (JSON):
    {
      "method":     "GET",
      "path":       "/products?id=1 UNION SELECT ...",
      "body":       "",
      "headers":    {},
      "user_agent": "Mozilla/5.0"
    }
    """
    data = request.get_json(silent=True) or {}

    req = HTTPRequest(
        method     = data.get("method",     "GET").upper(),
        path       = data.get("path",       "/"),
        body       = data.get("body",       ""),
        headers    = data.get("headers",    {}),
        user_agent = data.get("user_agent", request.headers.get("User-Agent", "")),
        ip         = data.get("ip",         client_ip()),
    )

    result = waf.inspect(req)
    entry  = log_result(result)

    http_status = 200 if result.allowed else 403
    return jsonify({
        "allowed"     : result.allowed,
        "reason"      : result.reason,
        "rules_hit"   : [
            {"id": r.rule_id, "name": r.name,
             "category": r.category, "severity": r.severity}
            for r in result.triggered
        ],
        "timestamp"   : entry["timestamp"],
        "ip"          : req.ip,
    }), http_status


@app.route("/dashboard")
def dashboard():
    """Return live security statistics as JSON."""
    attacks  = read_attack_log()
    traffic  = read_traffic_log()

    total   = len(traffic)
    blocked = len(attacks)

    from collections import Counter
    cat_counter = Counter()
    sev_counter = Counter()
    ip_counter  = Counter()

    for e in attacks:
        ip_counter[e["ip"]] += 1
        for r in e.get("rules_hit", []):
            cat_counter[r["category"]] += 1
            sev_counter[r["severity"]] += 1

    return jsonify({
        "summary": {
            "total":     total,
            "allowed":   total - blocked,
            "blocked":   blocked,
            "block_pct": round(blocked / total * 100, 1) if total else 0,
        },
        "categories"    : dict(cat_counter.most_common()),
        "severities"    : dict(sev_counter),
        "top_ips"       : dict(ip_counter.most_common(10)),
        "blocked_ips"   : list(waf.blocked_ips),
    })


@app.route("/logs")
def logs():
    """Return recent log entries. ?type=attack|traffic  &limit=N"""
    log_type = request.args.get("type",  "traffic")
    limit    = int(request.args.get("limit", "50"))

    entries = read_attack_log() if log_type == "attack" else read_traffic_log()
    return jsonify(entries[-limit:])


@app.route("/logs/clear", methods=["POST"])
def clear():
    """Clear all logs (admin use only — protect this in production!)."""
    admin_key = os.getenv("ADMIN_KEY", "")
    if admin_key and request.headers.get("X-Admin-Key") != admin_key:
        abort(403)
    clear_logs()
    return jsonify({"cleared": True})


@app.route("/blocked-ips")
def blocked_ips():
    """List currently blocked IPs and their violation counts."""
    return jsonify({
        "blocked_ips"     : list(waf.blocked_ips),
        "violation_counts": waf.violation_counts,
    })


@app.route("/blocked-ips/<ip>", methods=["DELETE"])
def unblock_ip(ip):
    """Unblock a specific IP address."""
    admin_key = os.getenv("ADMIN_KEY", "")
    if admin_key and request.headers.get("X-Admin-Key") != admin_key:
        abort(403)
    waf.unblock_ip(ip)
    return jsonify({"unblocked": ip})


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port  = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print(f"[Sentinel Shield] Starting on port {port}  debug={debug}")
    app.run(host="0.0.0.0", port=port, debug=debug)

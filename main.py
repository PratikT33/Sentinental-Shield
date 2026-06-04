"""
main.py — Sentinel Shield
Practical simulation covering Steps 3–6 of the student workflow:
  • Sends normal, malicious, and brute-force requests
  • Displays detection results in the terminal
  • Writes structured logs
  • Runs the dashboard report
"""

import time
from waf     import WAFEngine, HTTPRequest
from logger  import log_result, clear_logs
from dashboard import run_dashboard

# ─────────────────────────────────────────────────────────────
# ANSI colours for terminal output
# ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def print_result(result, index: int):
    req    = result.request
    status = f"{GREEN}✔ ALLOWED{RESET}" if result.allowed else f"{RED}✖ BLOCKED{RESET}"
    print(f"\n  [{index:02d}] {BOLD}{req.method} {req.path}{RESET}")
    print(f"       IP     : {req.ip}")
    print(f"       Status : {status}")
    if not result.allowed:
        print(f"       Reason : {YELLOW}{result.reason}{RESET}")
        for rule in result.triggered:
            print(f"               → [{rule.severity}] {rule.rule_id}: {rule.name}")


# ─────────────────────────────────────────────────────────────
# Test request catalogue (Step 3)
# ─────────────────────────────────────────────────────────────
def build_test_requests() -> list[tuple[str, HTTPRequest]]:
    """
    Returns labelled test cases:
      (label, HTTPRequest)
    Covers normal, malicious, and brute-force scenarios.
    """
    return [
        # ── Normal (benign) requests ─────────────────────────────
        ("Normal – homepage",
         HTTPRequest(method="GET", path="/", ip="10.0.0.1",
                     user_agent="Mozilla/5.0 Chrome/120")),

        ("Normal – product page",
         HTTPRequest(method="GET", path="/products?id=42", ip="10.0.0.1",
                     user_agent="Mozilla/5.0 Safari/605")),

        ("Normal – login form",
         HTTPRequest(method="POST", path="/login", ip="10.0.0.2",
                     body="username=alice&password=securepass123",
                     user_agent="Mozilla/5.0 Firefox/115")),

        ("Normal – search",
         HTTPRequest(method="GET", path="/search?q=python+tutorial", ip="10.0.0.3",
                     user_agent="Mozilla/5.0 Chrome/120")),

        # ── SQL Injection attacks ────────────────────────────────
        ("SQLI – UNION SELECT",
         HTTPRequest(method="GET",
                     path="/products?id=1 UNION SELECT username,password FROM users--",
                     ip="192.168.1.100",
                     user_agent="sqlmap/1.7")),

        ("SQLI – tautology (OR 1=1)",
         HTTPRequest(method="POST", path="/login", ip="192.168.1.100",
                     body="username=admin' OR '1'='1&password=anything",
                     user_agent="curl/7.88")),

        ("SQLI – DROP TABLE",
         HTTPRequest(method="GET",
                     path="/api/users?filter=1; DROP TABLE users--",
                     ip="192.168.1.101",
                     user_agent="python-requests/2.31")),

        # ── XSS attacks ──────────────────────────────────────────
        ("XSS – script tag",
         HTTPRequest(method="GET",
                     path='/search?q=<script>alert("XSS")</script>',
                     ip="10.10.10.50",
                     user_agent="Mozilla/5.0")),

        ("XSS – event handler",
         HTTPRequest(method="POST", path="/comment", ip="10.10.10.50",
                     body='text=Hello <img src=x onerror=alert(1)>',
                     user_agent="Mozilla/5.0")),

        ("XSS – javascript URI",
         HTTPRequest(method="GET",
                     path='/profile?redirect=javascript:document.cookie',
                     ip="10.10.10.51",
                     user_agent="Mozilla/5.0")),

        # ── Path traversal attacks ───────────────────────────────
        ("PATH – directory traversal",
         HTTPRequest(method="GET",
                     path="/download?file=../../../../etc/passwd",
                     ip="172.16.0.77",
                     user_agent="Wget/1.21")),

        ("PATH – sensitive file",
         HTTPRequest(method="GET",
                     path="/etc/shadow",
                     ip="172.16.0.77",
                     user_agent="curl/7.88")),

        # ── Command injection ────────────────────────────────────
        ("CMD – shell injection",
         HTTPRequest(method="POST", path="/ping", ip="192.168.100.5",
                     body="host=8.8.8.8; cat /etc/passwd",
                     user_agent="Mozilla/5.0")),

        # ── Admin panel probing ──────────────────────────────────
        ("BF – admin probe 1",
         HTTPRequest(method="GET", path="/wp-admin/", ip="203.0.113.10",
                     user_agent="Go-http-client/1.1")),

        ("BF – admin probe 2",
         HTTPRequest(method="GET", path="/phpmyadmin/", ip="203.0.113.10",
                     user_agent="Go-http-client/1.1")),

        ("BF – admin probe 3",
         HTTPRequest(method="GET", path="/administrator/", ip="203.0.113.10",
                     user_agent="Go-http-client/1.1")),
    ]


# ─────────────────────────────────────────────────────────────
# Brute-force simulation (rate limit trigger)
# ─────────────────────────────────────────────────────────────
def simulate_brute_force(waf: WAFEngine) -> list:
    """Send 20 rapid requests from the same IP to trip the rate limiter."""
    results = []
    bf_ip   = "10.99.99.99"
    print(f"\n{CYAN}{BOLD}  ── Brute-force / rate-limit simulation ({bf_ip}) ──{RESET}")
    for i in range(1, 21):
        req = HTTPRequest(method="POST", path="/login",
                          ip=bf_ip, body=f"user=admin&pass=guess{i}")
        result = waf.inspect(req)
        log_result(result)
        icon = "✔" if result.allowed else "✖"
        print(f"     Request {i:02d}: {icon} {'allowed' if result.allowed else 'BLOCKED — ' + result.reason[:40]}")
    return results


# ─────────────────────────────────────────────────────────────
# Main entrypoint
# ─────────────────────────────────────────────────────────────
def main():
    print(f"\n{BOLD}{'=' * 58}")
    print("  SENTINEL SHIELD — Intrusion Detection Simulation")
    print(f"{'=' * 58}{RESET}")

    # Fresh run
    clear_logs()

    # Initialise WAF (rate limit: 10 req/min, block after 3 violations)
    waf = WAFEngine(rate_limit=10, rate_window=60, block_threshold=3)

    # ── Step 3: Submit test requests ────────────────────────────
    print(f"\n{CYAN}{BOLD}  ── Test request simulation ──{RESET}")
    test_cases = build_test_requests()
    for i, (label, req) in enumerate(test_cases, start=1):
        print(f"\n  {BOLD}[Test {i:02d}] {label}{RESET}")
        result = waf.inspect(req)
        log_result(result)
        print_result(result, i)

    # ── Step 3 (brute-force): Rate limit simulation ──────────────
    simulate_brute_force(waf)

    # ── Step 5: Log file info ────────────────────────────────────
    print(f"\n{CYAN}{BOLD}  ── Log files written ──{RESET}")
    print("  logs/traffic.log  — all requests (JSON lines)")
    print("  logs/attack.log   — blocked requests only")

    # ── Step 6: Dashboard report ─────────────────────────────────
    print(f"\n{CYAN}{BOLD}  ── Security Dashboard Report ──{RESET}")
    run_dashboard()

    # ── Blocked IP summary ───────────────────────────────────────
    if waf.blocked_ips:
        print(f"  {RED}Permanently blocked IPs:{RESET}")
        for ip in waf.blocked_ips:
            print(f"   → {ip}  ({waf.violation_counts.get(ip, 0)} violations)")
        print()


if __name__ == "__main__":
    main()

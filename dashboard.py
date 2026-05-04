"""
dashboard.py — Sentinel Shield
Step 6: Dashboard — reads log files and prints a human-readable security report.
"""

from collections import Counter
from logger import read_attack_log, read_traffic_log


def run_dashboard():
    attacks  = read_attack_log()
    traffic  = read_traffic_log()

    total     = len(traffic)
    blocked   = len(attacks)
    allowed   = total - blocked
    block_pct = (blocked / total * 100) if total else 0

    print("\n" + "=" * 58)
    print("  SENTINEL SHIELD — Security Dashboard")
    print("=" * 58)

    # ── Traffic summary ─────────────────────────────────────────
    print(f"\n  Total requests  : {total}")
    print(f"  Allowed         : {allowed}")
    print(f"  Blocked         : {blocked}  ({block_pct:.1f}%)")

    if not attacks:
        print("\n  No attacks recorded.\n")
        return

    # ── Attack categories ────────────────────────────────────────
    category_counter: Counter = Counter()
    severity_counter: Counter = Counter()
    rule_counter    : Counter = Counter()
    ip_counter      : Counter = Counter()

    for entry in attacks:
        ip_counter[entry["ip"]] += 1
        for rule in entry.get("rules_hit", []):
            category_counter[rule["category"]] += 1
            severity_counter[rule["severity"]] += 1
            rule_counter[rule["id"]] += 1

    # ── By category ─────────────────────────────────────────────
    print("\n  Attack categories:")
    print("  " + "-" * 40)
    for cat, count in category_counter.most_common():
        bar = "█" * min(count * 2, 30)
        print(f"  {cat:<22} {count:>4}  {bar}")

    # ── By severity ─────────────────────────────────────────────
    print("\n  Severity breakdown:")
    print("  " + "-" * 40)
    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for sev in SEV_ORDER:
        count = severity_counter.get(sev, 0)
        icon  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "  ")
        print(f"  {icon} {sev:<10} {count:>4}")

    # ── Top offending IPs ────────────────────────────────────────
    print("\n  Top offending IPs:")
    print("  " + "-" * 40)
    for ip, count in ip_counter.most_common(5):
        print(f"  {ip:<20} {count:>4} violations")

    # ── Top triggered rules ──────────────────────────────────────
    print("\n  Top triggered rules:")
    print("  " + "-" * 40)
    for rule_id, count in rule_counter.most_common(5):
        print(f"  {rule_id:<12} {count:>4} hits")

    # ── Recent attacks (last 5) ──────────────────────────────────
    print("\n  Recent attacks (last 5):")
    print("  " + "-" * 40)
    for entry in attacks[-5:]:
        ts  = entry["timestamp"][:19]
        ip  = entry["ip"]
        pth = entry["path"][:35]
        rsn = entry["reason"][:40]
        print(f"  [{ts}] {ip:<16} {pth}")
        print(f"    ↳ {rsn}")

    print("\n" + "=" * 58 + "\n")


if __name__ == "__main__":
    run_dashboard()

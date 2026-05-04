"""
waf.py — Sentinel Shield
Step 3 & 4: WAF Engine — matches rules against incoming HTTP requests,
enforces rate limits, maintains IP blocklist.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from rules import RULES

# ─────────────────────────────────────────────
# HTTP Request model (Step 3)
# ─────────────────────────────────────────────
@dataclass
class HTTPRequest:
    method  : str
    path    : str
    headers : dict = field(default_factory=dict)
    body    : str  = ""
    ip      : str  = "127.0.0.1"
    user_agent: str = ""

    def full_text(self) -> str:
        """Concatenate all inspectable parts for pattern matching."""
        return " ".join([
            self.path,
            self.body,
            self.user_agent,
            " ".join(f"{k}:{v}" for k, v in self.headers.items()),
        ])


# ─────────────────────────────────────────────
# Detection result
# ─────────────────────────────────────────────
@dataclass
class DetectionResult:
    allowed    : bool
    request    : HTTPRequest
    triggered  : list     = field(default_factory=list)   # list of Rule objects
    reason     : str      = ""
    timestamp  : float    = field(default_factory=time.time)


# ─────────────────────────────────────────────
# Rate Limiter
# ─────────────────────────────────────────────
class RateLimiter:
    """Sliding window rate limiter per IP address."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests     = max_requests
        self.window_seconds   = window_seconds
        self._windows: dict   = defaultdict(list)   # ip → [timestamps]

    def is_allowed(self, ip: str) -> tuple[bool, int]:
        """Returns (allowed, current_count)."""
        now = time.time()
        cutoff = now - self.window_seconds
        # Prune old entries
        self._windows[ip] = [t for t in self._windows[ip] if t > cutoff]
        count = len(self._windows[ip])
        if count >= self.max_requests:
            return False, count
        self._windows[ip].append(now)
        return True, count + 1

    def get_count(self, ip: str) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        return len([t for t in self._windows[ip] if t > cutoff])


# ─────────────────────────────────────────────
# WAF Engine (Step 4)
# ─────────────────────────────────────────────
class WAFEngine:
    """
    Core Web Application Firewall.
    Checks requests against rules and rate limits.
    """

    def __init__(
        self,
        rules            = RULES,
        rate_limit       : int = 15,       # max requests per window
        rate_window      : int = 60,       # window in seconds
        block_threshold  : int = 3,        # auto-block IP after N violations
    ):
        self.rules           = rules
        self.rate_limiter    = RateLimiter(rate_limit, rate_window)
        self.block_threshold = block_threshold
        self._ip_violations  : dict = defaultdict(int)   # ip → violation count
        self._blocked_ips    : set  = set()

    def inspect(self, request: HTTPRequest) -> DetectionResult:
        """
        Inspect a single HTTP request.
        Returns a DetectionResult with allow/block decision.
        """

        # 1. Permanent IP block check
        if request.ip in self._blocked_ips:
            return DetectionResult(
                allowed   = False,
                request   = request,
                reason    = "IP permanently blocked due to repeated violations",
            )

        # 2. Rate limit check
        allowed_by_rate, count = self.rate_limiter.is_allowed(request.ip)
        if not allowed_by_rate:
            self._ip_violations[request.ip] += 1
            self._maybe_block_ip(request.ip)
            return DetectionResult(
                allowed = False,
                request = request,
                reason  = f"Rate limit exceeded ({count} requests in window)",
            )

        # 3. Rule-based inspection
        text = request.full_text()
        triggered = [rule for rule in self.rules if rule.matches(text)]

        if triggered:
            self._ip_violations[request.ip] += 1
            self._maybe_block_ip(request.ip)
            categories = list({r.category for r in triggered})
            return DetectionResult(
                allowed   = False,
                request   = request,
                triggered = triggered,
                reason    = f"Attack detected: {', '.join(categories)}",
            )

        # 4. Clean request
        return DetectionResult(allowed=True, request=request)

    def _maybe_block_ip(self, ip: str):
        if self._ip_violations[ip] >= self.block_threshold:
            self._blocked_ips.add(ip)

    def unblock_ip(self, ip: str):
        self._blocked_ips.discard(ip)
        self._ip_violations.pop(ip, None)

    @property
    def blocked_ips(self) -> set:
        return set(self._blocked_ips)

    @property
    def violation_counts(self) -> dict:
        return dict(self._ip_violations)

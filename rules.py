"""
rules.py — Sentinel Shield
Step 2: Attack signature definitions.
Each rule has a pattern (regex), category, severity, and description.
"""

import re

# ─────────────────────────────────────────────
# Rule schema
# ─────────────────────────────────────────────
class Rule:
    def __init__(self, rule_id, name, pattern, category, severity, description):
        self.rule_id    = rule_id
        self.name       = name
        self.pattern    = re.compile(pattern, re.IGNORECASE)
        self.category   = category
        self.severity   = severity        # "LOW", "MEDIUM", "HIGH", "CRITICAL"
        self.description = description

    def matches(self, text: str) -> bool:
        return bool(self.pattern.search(text))


# ─────────────────────────────────────────────
# Pre-defined attack signatures (Step 2)
# ─────────────────────────────────────────────
RULES = [

    # ── SQL Injection ──────────────────────────
    Rule(
        rule_id    = "SQLI-001",
        name       = "Basic SQL injection",
        pattern    = r"(union(\s+all)?\s+select|select\s+\*\s+from|drop\s+table|insert\s+into|delete\s+from)",
        category   = "SQL_INJECTION",
        severity   = "CRITICAL",
        description= "Detects UNION-based and destructive SQL injection attempts"
    ),
    Rule(
        rule_id    = "SQLI-002",
        name       = "SQL tautology attack",
        pattern    = r"(\bor\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+|(\bor\b|\band\b)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?)",
        category   = "SQL_INJECTION",
        severity   = "HIGH",
        description= "Detects OR 1=1 style tautology attacks"
    ),
    Rule(
        rule_id    = "SQLI-003",
        name       = "SQL comment stripping",
        pattern    = r"(--|;--|\/\*.*?\*\/|#\s)",
        category   = "SQL_INJECTION",
        severity   = "MEDIUM",
        description= "Detects SQL comment injection used to strip query logic"
    ),

    # ── Cross-Site Scripting ───────────────────
    Rule(
        rule_id    = "XSS-001",
        name       = "Script tag injection",
        pattern    = r"<\s*script[^>]*>.*?<\s*/\s*script\s*>|<\s*script[^>]*/?>",
        category   = "XSS",
        severity   = "HIGH",
        description= "Detects <script> tag injection"
    ),
    Rule(
        rule_id    = "XSS-002",
        name       = "Event handler injection",
        pattern    = r"on(load|click|mouseover|error|focus|submit|keyup|keydown)\s*=",
        category   = "XSS",
        severity   = "HIGH",
        description= "Detects JS event handler attribute injection (onload=, onclick=, ...)"
    ),
    Rule(
        rule_id    = "XSS-003",
        name       = "JavaScript URI",
        pattern    = r"javascript\s*:",
        category   = "XSS",
        severity   = "HIGH",
        description= "Detects javascript: protocol in href or src attributes"
    ),

    # ── Path Traversal ─────────────────────────
    Rule(
        rule_id    = "PATH-001",
        name       = "Directory traversal",
        pattern    = r"(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)",
        category   = "PATH_TRAVERSAL",
        severity   = "HIGH",
        description= "Detects ../ and URL-encoded variants used to escape the webroot"
    ),
    Rule(
        rule_id    = "PATH-002",
        name       = "Sensitive file access",
        pattern    = r"(\/etc\/passwd|\/etc\/shadow|\/proc\/self|win\.ini|boot\.ini)",
        category   = "PATH_TRAVERSAL",
        severity   = "CRITICAL",
        description= "Detects attempts to read OS-level sensitive files"
    ),

    # ── Command Injection ──────────────────────
    Rule(
        rule_id    = "CMD-001",
        name       = "Shell command injection",
        pattern    = r"(;|\||\`|\$\()\s*(ls|cat|wget|curl|bash|sh|python|nc|ncat|whoami|id|uname)",
        category   = "COMMAND_INJECTION",
        severity   = "CRITICAL",
        description= "Detects shell metacharacters followed by dangerous commands"
    ),

    # ── Brute-Force / Enumeration ──────────────
    Rule(
        rule_id    = "BF-001",
        name       = "Admin panel probing",
        pattern    = r"\/(admin|administrator|wp-admin|phpmyadmin|cpanel|manager|console)(\/|$)",
        category   = "BRUTE_FORCE",
        severity   = "MEDIUM",
        description= "Detects probing of common admin panel URLs"
    ),

    # ── Local File Inclusion ───────────────────
    Rule(
        rule_id    = "LFI-001",
        name       = "Local file inclusion",
        pattern    = r"(include|require)(_once)?\s*\(\s*['\"]?(\.\.\/|\/etc\/|\/proc\/)",
        category   = "LFI",
        severity   = "HIGH",
        description= "Detects PHP-style local file inclusion exploitation"
    ),
]

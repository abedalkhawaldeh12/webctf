"""
Intelligence Engine for WebCTF Suite.
A decision-making layer that evaluates findings, prioritizes what matters,
and filters out noise. This is the "brain" that tells the tool:
  - Which endpoints/params are worth attacking (HIGH value)
  - Which findings are false positives / low value (IGNORE)
  - Which attack path is most likely to succeed first

The engine assigns a VALUE SCORE (0-100) to every finding based on:
  1. Signal strength (does it look like a real vuln vs. generic 404?)
  2. Exploitability (can we actually do something with it?)
  3. Flag proximity (is it near where flags usually live?)
  4. Tech-stack fit (does it match the detected framework?)
  5. Historical success (have similar findings worked before?)

Usage:
    from modules.intelligence_engine import IntelligenceEngine
    brain = IntelligenceEngine(state, learning_engine)
    prioritized = brain.prioritize_findings()
    brain.print_priority_report()
"""

import re
import time
from typing import List, Dict, Any, Optional, Set, Tuple

from core.ui import (
    console, print_header, print_success, print_info, print_warning,
    print_error, print_table, print_flag
)


# ─────────────────────────────────────────────────────────────────────
# SIGNAL PATTERNS - things that indicate a finding is IMPORTANT
# ─────────────────────────────────────────────────────────────────────
HIGH_VALUE_PATTERNS = {
    # Endpoints that commonly hold flags or admin functionality
    "admin": ["admin", "dashboard", "panel", "manage", "control"],
    "flag": ["flag", "secret", "hidden", "private", "confidential"],
    "upload": ["upload", "file", "files", "media", "images", "assets"],
    "api": ["api", "json", "ajax", "graphql", "rest", "v1", "v2"],
    "auth": ["login", "signin", "auth", "session", "token", "password"],
    "debug": ["debug", "test", "dev", "staging", "backup", "old", "tmp"],
    "config": ["config", "settings", "env", "database", "db", "sql"],
    "user": ["user", "profile", "account", "member", "customer"],
}

# Endpoints that are almost always noise (ignore these)
# NOTE: robots.txt is intentionally NOT here - it's a critical CTF hint source
# that often reveals hidden files/dirs (sometimes base64-encoded).
LOW_VALUE_PATTERNS = [
    "favicon", "sitemap", "index.html", "index.php",
    "error", "404", "notfound", "css", "js", "images", "img",
    "fonts", "icons", "vendor", "node_modules", "bower_components",
    "wp-content", "wp-includes", "wp-json", "xmlrpc",
]

# File extensions that indicate static content (low value)
STATIC_EXTENSIONS = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                     ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                     ".map", ".min.js", ".min.css"}

# Extensions that indicate dynamic content (high value)
DYNAMIC_EXTENSIONS = {".php", ".asp", ".aspx", ".jsp", ".py", ".rb",
                      ".pl", ".cgi", ".do", ".action", ".json", ".xml",
                      ".txt", ".bak", ".old", ".swp", ".sql", ".env",
                      ".log", ".conf", ".yml", ".yaml", ".ini"}

# Parameters that are commonly injectable (high value)
HIGH_VALUE_PARAMS = [
    "id", "user", "username", "password", "pass", "email", "file",
    "path", "url", "redirect", "next", "return", "page", "view",
    "search", "q", "query", "name", "cmd", "command", "exec",
    "code", "data", "json", "token", "session", "cookie", "lang",
    "theme", "template", "include", "download", "upload", "action",
    "type", "format", "callback", "debug", "test", "admin", "role",
]

# Parameters that are almost always noise
LOW_VALUE_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "ref", "source", "campaign", "affiliate",
    "ga", "gtm", "recaptcha", "captcha", "csrf", "nonce",
]

# Response signatures that indicate a REAL vulnerability vs. noise
VULN_SIGNATURES = {
    "sqli": [
        r"SQL syntax", r"mysql_fetch", r"Warning:.*mysql", r"Uncaught.*SQL",
        r"sqlite3\.", r"OperationalError", r"you have an error in your SQL",
        r"ORA-\d{5}", r"PostgreSQL.*ERROR", r"Microsoft.*ODBC",
    ],
    "ssti": [
        r"TemplateSyntaxError", r"jinja2\.exceptions", r"UndefinedError",
        r"TemplateNotFound", r"Twig\\Error", r"Smarty", r"freemarker",
        r"velocity", r"Template.*Error",
    ],
    "xss": [
        r"<script>", r"onerror=", r"onload=", r"javascript:", r"alert\(",
    ],
    "lfi": [
        r"root:x:0:0", r"etc/passwd", r"php://filter", r"file://",
        r"Warning:.*include", r"failed to open stream",
    ],
    "cmd_inj": [
        r"uid=\d+", r"gid=\d+", r"www-data", r"root@", r"Command not found",
        r"sh: ", r"bash: ", r"Permission denied",
    ],
    "rce": [
        r"uid=\d+", r"gid=\d+", r"www-data", r"root@", r"PHP Notice",
        r"Warning:.*exec", r"system\(\)",
    ],
    "jwt": [
        r"alg.*none", r"invalid signature", r"jwt", r"token",
    ],
    "deserialization": [
        r"unserialize", r"Object of class", r"__wakeup", r"__destruct",
        r"pickle", r"yaml", r"node-serialize",
    ],
    "ssrf": [
        r"127\.0\.0\.1", r"localhost", r"169\.254\.169\.254", r"metadata",
    ],
    "xxe": [
        r"XMLParseError", r"DOCTYPE", r"ENTITY", r"xxe",
    ],
}

# Tech-stack specific high-value indicators
TECH_HIGH_VALUE = {
    "php": ["php", "laravel", "symfony", "wordpress", "drupal", "joomla"],
    "python": ["flask", "django", "fastapi", "jinja2", "werkzeug"],
    "node": ["express", "node", "next", "nuxt", "react"],
    "java": ["spring", "struts", "java", "jsp", "tomcat"],
    "ruby": ["rails", "sinatra", "ruby"],
    "go": ["gin", "echo", "go"],
    "dotnet": ["asp.net", "c#", "iis", "dotnet"],
}


class IntelligenceEngine:
    """
    Decision-making layer that evaluates findings and tells the tool
    what to attack first and what to ignore.
    """

    def __init__(self, state: Dict[str, Any], learning_engine=None):
        self.state = state or {}
        self.learning = learning_engine
        self.target_url = self.state.get("target_url", "")
        self.tech_stack = [t.lower() for t in self.state.get("tech_stack", [])]
        self.flag_prefix = self.state.get("flag_prefix", "")

        # Scoring results
        self.endpoint_scores: List[Dict[str, Any]] = []
        self.param_scores: List[Dict[str, Any]] = []
        self.vuln_scores: List[Dict[str, Any]] = []
        self.attack_priority: List[Dict[str, Any]] = []

    # ═════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═════════════════════════════════════════════════════════════════
    def analyze(self) -> Dict[str, Any]:
        """
        Run the full intelligence analysis:
        1. Score all discovered endpoints
        2. Score all discovered parameters
        3. Score all discovered vulnerabilities
        4. Build a prioritized attack plan
        Returns a structured intelligence report.
        """
        self._score_endpoints()
        self._score_parameters()
        self._score_vulnerabilities()
        self._build_attack_priority()

        return {
            "endpoint_scores": self.endpoint_scores,
            "param_scores": self.param_scores,
            "vuln_scores": self.vuln_scores,
            "attack_priority": self.attack_priority,
            "high_value_endpoints": [e for e in self.endpoint_scores if e["score"] >= 60],
            "ignore_list": [e for e in self.endpoint_scores if e["score"] < 30],
        }

    def should_attack(self, endpoint: str, score: Optional[int] = None) -> bool:
        """Decide whether an endpoint is worth attacking."""
        if score is not None:
            return score >= 50
        # Score on the fly
        s = self._score_single_endpoint(endpoint)
        return s >= 50

    def should_ignore(self, endpoint: str) -> bool:
        """Decide whether an endpoint is noise and should be skipped."""
        return not self.should_attack(endpoint)

    def get_top_attack_targets(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Return the top N attack targets by priority."""
        return self.attack_priority[:limit]

    def get_ignore_list(self) -> List[str]:
        """Return list of endpoints that should be ignored."""
        return [e["endpoint"] for e in self.endpoint_scores if e["score"] < 30]

    def print_priority_report(self):
        """Print a human-readable intelligence report."""
        print_header("محرك الذكاء", "Intelligence Engine - Prioritization Report")

        # High-value endpoints
        high = [e for e in self.endpoint_scores if e["score"] >= 60]
        if high:
            rows = [[e["endpoint"], f"{e['score']}/100", e["reason"]] for e in high]
            print_table(["Endpoint", "Value", "Why Important"], rows,
                        title="🎯 HIGH-VALUE Targets (Attack First)")
        else:
            print_info("No high-value endpoints found yet.")

        # Medium-value endpoints
        medium = [e for e in self.endpoint_scores if 30 <= e["score"] < 60]
        if medium:
            rows = [[e["endpoint"], f"{e['score']}/100", e["reason"]] for e in medium]
            print_table(["Endpoint", "Value", "Why"], rows,
                        title="📋 MEDIUM-VALUE Targets (Investigate)")

        # Ignore list
        ignore = [e for e in self.endpoint_scores if e["score"] < 30]
        if ignore:
            rows = [[e["endpoint"], f"{e['score']}/100", e["reason"]] for e in ignore]
            print_table(["Endpoint", "Value", "Why Ignore"], rows,
                        title="🚫 IGNORE (Noise / Low Value)")

        # Attack priority
        if self.attack_priority:
            rows = [[str(i + 1), p["target"], p["vuln_class"], f"{p['priority']}/100", p["reason"]]
                    for i, p in enumerate(self.attack_priority)]
            print_table(["#", "Target", "Vuln", "Priority", "Reason"], rows,
                        title="⚡ ATTACK ORDER (Highest Priority First)")

    # ═════════════════════════════════════════════════════════════════
    # ENDPOINT SCORING
    # ═════════════════════════════════════════════════════════════════
    def _score_endpoints(self):
        """Score all discovered endpoints."""
        self.endpoint_scores = []
        endpoints = self.state.get("sensitive_hits", [])
        if not endpoints:
            # Fall back to raw endpoints set
            for ep in self.state.get("endpoints", []):
                endpoints.append({"path": ep, "url": ep, "status": 200, "length": 0})

        for ep in endpoints:
            path = ep.get("path", "") if isinstance(ep, dict) else str(ep)
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            status = ep.get("status", 200) if isinstance(ep, dict) else 200
            length = ep.get("length", 0) if isinstance(ep, dict) else 0

            score, reason = self._score_single_endpoint_full(path, status, length)
            self.endpoint_scores.append({
                "endpoint": path,
                "url": url,
                "status": status,
                "length": length,
                "score": score,
                "reason": reason,
            })

        # Sort by score descending
        self.endpoint_scores.sort(key=lambda x: x["score"], reverse=True)

    def _score_single_endpoint(self, endpoint: str) -> int:
        """Quick score for a single endpoint (used by should_attack)."""
        score, _ = self._score_single_endpoint_full(endpoint, 200, 0)
        return score

    def _score_single_endpoint_full(self, path: str, status: int, length: int) -> Tuple[int, str]:
        """Score a single endpoint. Returns (score, reason)."""
        score = 0
        reasons = []
        path_lower = path.lower().strip("/")

        # ── 1. Status code signal ─────────────────────────────────────
        if status == 200:
            score += 20
            reasons.append("HTTP 200 (accessible)")
        elif status in (301, 302, 307, 308):
            score += 10
            reasons.append("Redirect (may lead to hidden content)")
        elif status == 403:
            score += 15
            reasons.append("HTTP 403 (exists but restricted - interesting)")
        elif status == 401:
            score += 15
            reasons.append("HTTP 401 (auth required - potential bypass)")
        elif status == 500:
            score += 10
            reasons.append("HTTP 500 (server error - may be exploitable)")

        # ── 2. Path content signal ────────────────────────────────────
        # High-value keywords - critical categories get more weight
        critical_categories = {"admin", "flag", "config", "auth", "api"}
        matched_category = None
        for category, keywords in HIGH_VALUE_PATTERNS.items():
            if any(k in path_lower for k in keywords):
                matched_category = category
                if category in critical_categories:
                    score += 40
                    reasons.append(f"Contains critical '{category}' keyword")
                else:
                    score += 25
                    reasons.append(f"Contains '{category}' keyword")
                break

        # Extra boost for very sensitive paths (flag, secret, backup, config)
        sensitive_exact = ["flag", "secret", "backup", "config", "admin", "debug"]
        if any(s in path_lower for s in sensitive_exact):
            score += 15
            reasons.append("Sensitive path detected")

        # Low-value / noise patterns
        if any(p in path_lower for p in LOW_VALUE_PATTERNS):
            score -= 20
            reasons.append("Known noise pattern")

        # ── 3. File extension signal ──────────────────────────────────
        ext = ""
        if "." in path_lower:
            ext = "." + path_lower.rsplit(".", 1)[-1]
        if ext in DYNAMIC_EXTENSIONS:
            score += 15
            reasons.append(f"Dynamic extension {ext}")
        elif ext in STATIC_EXTENSIONS:
            score -= 15
            reasons.append(f"Static content {ext}")

        # ── 4. Tech-stack fit ─────────────────────────────────────────
        for tech, keywords in TECH_HIGH_VALUE.items():
            if any(t in self.tech_stack for t in keywords):
                # If the endpoint matches the tech, it's more interesting
                if any(k in path_lower for k in keywords):
                    score += 10
                    reasons.append(f"Matches {tech} stack")
                break

        # ── 5. Flag proximity ─────────────────────────────────────────
        if self.flag_prefix and self.flag_prefix.lower() in path_lower:
            score += 30
            reasons.append("Contains flag prefix!")

        # ── 6. Historical learning ────────────────────────────────────
        if self.learning:
            learned = self.learning.get_recommendations(self.tech_stack, ["endpoint"])
            # Simple heuristic: if we've solved similar challenges, boost
            if self.learning.data.get("stats", {}).get("total_solved_challenges", 0) > 0:
                score += 5

        # Clamp score to 0-100
        score = max(0, min(100, score))
        reason_str = "; ".join(reasons) if reasons else "No strong signals"
        return score, reason_str

    # ═════════════════════════════════════════════════════════════════
    # PARAMETER SCORING
    # ═════════════════════════════════════════════════════════════════
    def _score_parameters(self):
        """Score all discovered parameters."""
        self.param_scores = []
        params = self.state.get("parameters", [])

        for param in params:
            p = param.lower()
            score = 0
            reasons = []

            # High-value params (injectable)
            if p in HIGH_VALUE_PARAMS:
                score += 40
                reasons.append("Commonly injectable parameter")

            # Param name hints at sensitive data
            if any(k in p for k in ["pass", "token", "secret", "key", "auth", "session"]):
                score += 20
                reasons.append("Sensitive data parameter")

            # Param hints at file/path operations
            if any(k in p for k in ["file", "path", "url", "redirect", "download", "include"]):
                score += 20
                reasons.append("File/path operation parameter")

            # Param hints at command execution
            if any(k in p for k in ["cmd", "command", "exec", "code", "shell"]):
                score += 25
                reasons.append("Command execution parameter")

            # Low-value params (tracking, etc.)
            if p in LOW_VALUE_PARAMS:
                score -= 30
                reasons.append("Tracking/analytics parameter (noise)")

            # Clamp
            score = max(0, min(100, score))
            self.param_scores.append({
                "param": param,
                "score": score,
                "reason": "; ".join(reasons) if reasons else "No strong signals",
            })

        self.param_scores.sort(key=lambda x: x["score"], reverse=True)

    # ═════════════════════════════════════════════════════════════════
    # VULNERABILITY SCORING
    # ═════════════════════════════════════════════════════════════════
    def _score_vulnerabilities(self):
        """Score discovered vulnerabilities by exploitability."""
        self.vuln_scores = []
        vulns = self.state.get("vulnerabilities", [])

        for vuln in vulns:
            if isinstance(vuln, str):
                vuln = {"type": vuln, "confidence": 0.5, "evidence": []}
            vtype = vuln.get("type", vuln.get("vuln_class", "unknown")).lower()
            confidence = vuln.get("confidence", 0.5)
            evidence = vuln.get("evidence", [])

            score = 0
            reasons = []

            # Base score from confidence
            score += int(confidence * 50)

            # High-impact vuln types
            high_impact = ["rce", "cmd_inj", "sqli", "deserialization", "file_upload", "graphql", "idor", "race_condition", "smuggling", "mass_assignment", "zip_slip", "ssi", "latex", "md5_id_bruteforce", "source_credentials"]
            if vtype in high_impact:
                score += 30
                reasons.append("High-impact vulnerability type")

            # Medium-impact
            medium_impact = ["ssti", "lfi", "ssrf", "xxe", "jwt", "auth_bypass", "cors", "open_redirect", "hpp", "crlf", "csrf", "ldap", "web_cache", "dom_clobbering", "oauth", "csv_injection", "clickjacking", "dns_rebinding", "tabnabbing", "css_injection", "xslt", "xs_leak", "cookie_manipulation"]
            if vtype in medium_impact:
                score += 20
                reasons.append("Medium-impact vulnerability type")

            # Evidence strength
            if evidence:
                score += 10
                reasons.append(f"{len(evidence)} pieces of evidence")

            # Check for strong signatures in evidence
            sigs = VULN_SIGNATURES.get(vtype, [])
            for sig in sigs:
                if any(re.search(sig, str(e), re.IGNORECASE) for e in evidence):
                    score += 15
                    reasons.append("Strong vulnerability signature detected")
                    break

            # Clamp
            score = max(0, min(100, score))
            self.vuln_scores.append({
                "type": vtype,
                "score": score,
                "confidence": confidence,
                "reason": "; ".join(reasons) if reasons else "Low confidence",
            })

        self.vuln_scores.sort(key=lambda x: x["score"], reverse=True)

    # ═════════════════════════════════════════════════════════════════
    # ATTACK PRIORITY
    # ═════════════════════════════════════════════════════════════════
    def _build_attack_priority(self):
        """
        Build a prioritized attack plan combining endpoint scores,
        param scores, and vuln scores. This is the "what to do first"
        decision that the brain makes.
        """
        self.attack_priority = []

        # 1. High-value endpoints with matching vuln types
        for ep in self.endpoint_scores:
            if ep["score"] >= 60:
                # Find matching vuln for this endpoint
                best_vuln = None
                for v in self.vuln_scores:
                    if v["score"] >= 50:
                        best_vuln = v
                        break

                priority = ep["score"]
                if best_vuln:
                    priority = min(100, priority + 10)

                self.attack_priority.append({
                    "target": ep["endpoint"],
                    "url": ep["url"],
                    "vuln_class": best_vuln["type"] if best_vuln else "recon",
                    "priority": priority,
                    "reason": f"High-value endpoint ({ep['reason']})"
                              + (f" + {best_vuln['type']} vuln" if best_vuln else ""),
                })

        # 2. High-value params (injectable)
        for p in self.param_scores:
            if p["score"] >= 40:
                self.attack_priority.append({
                    "target": f"param:{p['param']}",
                    "url": self.target_url,
                    "vuln_class": "param_injection",
                    "priority": p["score"],
                    "reason": f"Injectable parameter '{p['param']}' ({p['reason']})",
                })

        # 3. High-confidence vulns
        for v in self.vuln_scores:
            if v["score"] >= 60:
                self.attack_priority.append({
                    "target": self.target_url,
                    "url": self.target_url,
                    "vuln_class": v["type"],
                    "priority": v["score"],
                    "reason": f"Confirmed {v['type']} vulnerability ({v['reason']})",
                })

        # Sort by priority descending
        self.attack_priority.sort(key=lambda x: x["priority"], reverse=True)

        # Deduplicate (keep first occurrence)
        seen = set()
        deduped = []
        for item in self.attack_priority:
            key = f"{item['target']}|{item['vuln_class']}"
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        self.attack_priority = deduped

    # ═════════════════════════════════════════════════════════════════
    # FILTERING HELPERS
    # ═════════════════════════════════════════════════════════════════
    def filter_noise(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out noise from a list of findings.
        Keeps items with score >= 30, removes obvious noise.
        """
        filtered = []
        for item in items:
            path = item.get("path", item.get("endpoint", ""))
            if self.should_ignore(path):
                continue
            filtered.append(item)
        return filtered

    def is_interesting_response(self, body: str, status: int) -> bool:
        """
        Decide if a response body is worth investigating.
        Returns True if it contains interesting content.
        """
        if status in (200, 301, 302, 403, 401, 500):
            # Check for interesting content
            interesting = [
                r"flag", r"secret", r"password", r"admin", r"token",
                r"api[_-]?key", r"private", r"hidden", r"debug",
                r"sql", r"select", r"insert", r"update", r"delete",
                r"php", r"python", r"flask", r"django", r"node",
                r"<form", r"<input", r"<script", r"<iframe",
            ]
            for pat in interesting:
                if re.search(pat, body, re.IGNORECASE):
                    return True
        return False

    def decide_next_action(self) -> Optional[Dict[str, Any]]:
        """
        The brain's main decision: what should the tool do next?
        Returns the single highest-priority action, or None if nothing.
        """
        if not self.attack_priority:
            return None
        return self.attack_priority[0]

    def summarize(self) -> Dict[str, Any]:
        """Return a compact summary of the intelligence analysis."""
        return {
            "high_value_endpoints": len([e for e in self.endpoint_scores if e["score"] >= 60]),
            "medium_value_endpoints": len([e for e in self.endpoint_scores if 30 <= e["score"] < 60]),
            "ignored_endpoints": len([e for e in self.endpoint_scores if e["score"] < 30]),
            "high_value_params": len([p for p in self.param_scores if p["score"] >= 40]),
            "confirmed_vulns": len([v for v in self.vuln_scores if v["score"] >= 60]),
            "next_action": self.decide_next_action(),
        }

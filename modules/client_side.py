"""
Client-Side JavaScript Offensive Analysis, Deobfuscation & Credential Extractor for Web CTF.
Analyzes inline scripts, external JS files, hardcoded authentication logic, String.fromCharCode,
atob, unescape, hex escapes, string reversal, XOR ciphers, and client-side validation routines.
"""

import re
import base64
import urllib.parse
from typing import Dict, List, Any, Optional
from core.utils import find_flags


class ClientSideAnalyzer:
    """Intelligent client-side offensive JavaScript analysis and payload solver."""

    @staticmethod
    def extract_js_auth_checks(js_code: str) -> List[Dict[str, Any]]:
        """Extract hardcoded authentication credentials and logic from JS code."""
        results = []
        seen_credentials = set()

        # 1. Dual condition: pseudo == "..." && password == "..." (in any order)
        dual_patterns = [
            r'(?:pseudo|user|username|login|id)\s*===?\s*["\']([^"\'\n]+)["\']\s*&&\s*(?:password|pass|passwd|pwd|key|token)\s*===?\s*["\']([^"\'\n]+)["\']',
            r'(?:password|pass|passwd|pwd|key|token)\s*===?\s*["\']([^"\'\n]+)["\']\s*&&\s*(?:pseudo|user|username|login|id)\s*===?\s*["\']([^"\'\n]+)["\']',
            r'["\']([^"\'\n]+)["\']\s*===?\s*(?:pseudo|user|username|login|id)\s*&&\s*["\']([^"\'\n]+)["\']\s*===?\s*(?:password|pass|passwd|pwd|key|token)',
            r'["\']([^"\'\n]+)["\']\s*===?\s*(?:password|pass|passwd|pwd|key|token)\s*&&\s*["\']([^"\'\n]+)["\']\s*===?\s*(?:pseudo|user|username|login|id)'
        ]

        for pat in dual_patterns:
            for m in re.finditer(pat, js_code, re.IGNORECASE):
                val1, val2 = m.group(1), m.group(2)
                # Determine which is user and which is password based on regex match order
                if "pass" in pat.split("&&")[0].lower():
                    u, p = val2, val1
                else:
                    u, p = val1, val2
                cred_key = (u, p)
                if cred_key not in seen_credentials:
                    seen_credentials.add(cred_key)
                    results.append({
                        "type": "dual_auth_check",
                        "username": u,
                        "password": p,
                        "flag_candidate": p,
                        "raw_match": m.group(0)
                    })

        # 2. Single password / key / secret comparison
        single_patterns = [
            (r'(?:password|pass|passwd|pwd|flag|secret|key|token|access_code)\s*===?\s*["\']([^"\'\n]{2,100})["\']', "password"),
            (r'["\']([^"\'\n]{2,100})["\']\s*===?\s*(?:password|pass|passwd|pwd|flag|secret|key|token|access_code)', "password"),
            (r'document\.(?:login|[a-zA-Z0-9_]+)\.(?:password|pass|pwd|key)\.value\s*===?\s*["\']([^"\'\n]{2,100})["\']', "form_password"),
            (r'document\.(?:forms\[\d+\]|[a-zA-Z0-9_]+)\.(?:elements\[\d+\]|[a-zA-Z0-9_]+)\.value\s*===?\s*["\']([^"\'\n]{2,100})["\']', "form_element"),
            (r'checkPassword\s*\(\s*["\']([^"\'\n]{2,100})["\']\s*\)', "check_password"),
            (r'var\s+(?:password|pass|flag|secret|flag_val|the_pass)\s*=\s*["\']([^"\'\n]{2,100})["\']', "var_decl"),
            (r'let\s+(?:password|pass|flag|secret|flag_val|the_pass)\s*=\s*["\']([^"\'\n]{2,100})["\']', "let_decl"),
            (r'const\s+(?:password|pass|flag|secret|flag_val|the_pass)\s*=\s*["\']([^"\'\n]{2,100})["\']', "const_decl")
        ]

        for pat, tag in single_patterns:
            for m in re.finditer(pat, js_code, re.IGNORECASE):
                val = m.group(1).strip()
                cred_key = ("", val)
                if cred_key not in seen_credentials and len(val) >= 2:
                    seen_credentials.add(cred_key)
                    results.append({
                        "type": tag,
                        "username": "admin",
                        "password": val,
                        "flag_candidate": val,
                        "raw_match": m.group(0)
                    })

        return results

    @staticmethod
    def evaluate_js_charcodes(js_code: str) -> List[str]:
        """Extract and evaluate String.fromCharCode(...) sequences."""
        decoded = []
        for m in re.finditer(r'String\.fromCharCode\s*\(([\d\s,]+)\)', js_code, re.IGNORECASE):
            raw_nums = m.group(1)
            try:
                numbers = [int(n.strip()) for n in raw_nums.split(",") if n.strip().isdigit()]
                text = "".join(chr(n) for n in numbers if 0 <= n <= 65535)
                if text and text not in decoded:
                    decoded.append(text)
            except Exception:
                pass
        return decoded

    @staticmethod
    def evaluate_js_atob(js_code: str) -> List[str]:
        """Extract and decode atob(...) Base64 strings."""
        decoded = []
        for m in re.finditer(r'(?:window\.)?atob\s*\(\s*["\']([A-Za-z0-9+/=]{4,})["\']\s*\)', js_code, re.IGNORECASE):
            b64_str = m.group(1)
            try:
                raw = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                if raw and raw not in decoded:
                    decoded.append(raw)
            except Exception:
                pass
        return decoded

    @staticmethod
    def evaluate_js_unescape(js_code: str) -> List[str]:
        """Extract and decode unescape(...) strings."""
        decoded = []
        for m in re.finditer(r'unescape\s*\(\s*["\']([^"\'\n]+)["\']\s*\)', js_code, re.IGNORECASE):
            raw_str = m.group(1)
            try:
                text = urllib.parse.unquote(raw_str)
                if text and text not in decoded and text != raw_str:
                    decoded.append(text)
            except Exception:
                pass
        return decoded

    @staticmethod
    def evaluate_js_reverse_strings(js_code: str) -> List[str]:
        """Extract and evaluate string reversal logic (e.g., 'foo'.split('').reverse().join(''))."""
        decoded = []
        for m in re.finditer(r'["\']([^"\'\n]+)["\']\.split\s*\(\s*["\']["\']\s*\)\.reverse\s*\(\s*\)\.join\s*\(\s*["\']["\']\s*\)', js_code, re.IGNORECASE):
            target_str = m.group(1)
            rev = target_str[::-1]
            if rev and rev not in decoded:
                decoded.append(rev)
        return decoded

    @staticmethod
    def evaluate_js_hex_escapes(js_code: str) -> List[str]:
        """Extract and decode consecutive hex escape sequences (\\x41\\x42\\x43)."""
        decoded = []
        for m in re.finditer(r'((?:\\x[0-9a-fA-F]{2}){3,})', js_code):
            hex_seq = m.group(1)
            try:
                raw_bytes = bytes.fromhex(hex_seq.replace("\\x", ""))
                text = raw_bytes.decode("utf-8", errors="ignore")
                if text and text not in decoded:
                    decoded.append(text)
            except Exception:
                pass
        return decoded

    @staticmethod
    def solve_xor_comparisons(js_code: str) -> List[str]:
        """Detect and solve simple JS XOR loops against arrays or key values."""
        results = []
        # Pattern: [12, 34, 56...] with ^ key or charCodeAt
        array_match = re.search(r'(?:var|let|const)\s+[a-zA-Z0-9_]+\s*=\s*\[([\d\s,]+)\]', js_code)
        xor_key_match = re.search(r'\^\s*(\d+|0x[0-9a-fA-F]+)', js_code)
        
        if array_match and xor_key_match:
            try:
                nums = [int(n.strip()) for n in array_match.group(1).split(",") if n.strip().isdigit()]
                key_str = xor_key_match.group(1)
                key = int(key_str, 16) if key_str.startswith("0x") else int(key_str)
                recovered = "".join(chr(n ^ key) for n in nums if 0 <= (n ^ key) <= 255)
                if len(recovered) >= 4:
                    results.append(recovered)
            except Exception:
                pass
        return results

    @classmethod
    def analyze_javascript(cls, js_code: str, source_name: str = "") -> Dict[str, Any]:
        """Comprehensive analysis of JavaScript code to extract credentials, secrets, and flags."""
        auth_creds = cls.extract_js_auth_checks(js_code)
        charcodes = cls.evaluate_js_charcodes(js_code)
        atob_strings = cls.evaluate_js_atob(js_code)
        unescaped = cls.evaluate_js_unescape(js_code)
        reversed_strs = cls.evaluate_js_reverse_strings(js_code)
        hex_decoded = cls.evaluate_js_hex_escapes(js_code)
        xor_recovered = cls.solve_xor_comparisons(js_code)

        all_recovered_texts = [js_code] + charcodes + atob_strings + unescaped + reversed_strs + hex_decoded + xor_recovered
        
        # Scan all recovered text for standard flags
        discovered_flags = set()
        for t in all_recovered_texts:
            for f in find_flags(t):
                discovered_flags.add(f)

        return {
            "source": source_name,
            "auth_credentials": auth_creds,
            "charcodes": charcodes,
            "atob_strings": atob_strings,
            "unescaped": unescaped,
            "reversed_strings": reversed_strs,
            "hex_decoded": hex_decoded,
            "xor_recovered": xor_recovered,
            "flags": list(discovered_flags)
        }

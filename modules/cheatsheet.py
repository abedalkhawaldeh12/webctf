"""
CTF Cheatsheets, PHP Quirks Matrix, and Source Code Vulnerability Analyzer.
"""

import re
from typing import List, Dict, Tuple, Any
from core.ui import print_table, print_header, print_info, print_warning

PHP_QUIRKS = [
    {"Expression": "0 == '0e12345'", "Result": "TRUE", "Explanation": "Both strings starting with 0e followed by digits evaluate to float (0.0)."},
    {"Expression": "0 == 'admin'", "Result": "TRUE (PHP < 8.0)", "Explanation": "String 'admin' converts to int 0 during loose comparison (==). Fixed in PHP 8."},
    {"Expression": "'123' == '123foo'", "Result": "FALSE (PHP 8) / TRUE (< 8)", "Explanation": "Leading numeric string conversion."},
    {"Expression": "strcmp('secret', [])", "Result": "NULL (Evaluates to 0 in ==)", "Explanation": "strcmp on an array returns NULL. If compared with == 0, evaluates to TRUE."},
    {"Expression": "md5([]) === NULL", "Result": "TRUE", "Explanation": "md5() with array parameter returns NULL and triggers a warning."},
    {"Expression": "sha1([]) === NULL", "Result": "TRUE", "Explanation": "sha1() with array parameter returns NULL."},
    {"Expression": "in_array(0, ['admin', 'user'])", "Result": "TRUE (PHP < 8.0)", "Explanation": "in_array default comparison is loose (!strict). 0 == 'admin' -> true."},
    {"Expression": "preg_match('/^[a-z]+$/', \"foo\\n\")", "Result": "MATCHES", "Explanation": "$ matches before trailing newline \\n. Use /D modifier or \\z instead."},
    {"Expression": "parse_url('http://evil.com#@target.com')", "Result": "Host: evil.com", "Explanation": "PHP parse_url parsing inconsistency compared to cURL."},
]

DANGEROUS_SINKS = {
    "php": [
        (r"\b(eval|assert|passthru|system|shell_exec|exec|proc_open|popen)\s*\(", "Critical RCE Sink: Arbitrary code or system command execution."),
        (r"\b(unserialize)\s*\(", "High Deserialization Sink: Object Injection and magic method triggers."),
        (r"\b(include|include_once|require|require_once)\s*\(?", "High LFI / RFI Sink: File inclusion vulnerability."),
        (r"\b(file_get_contents|readfile|file|fopen)\s*\(", "Medium/High SSRF or Arbitrary File Read Sink."),
        (r"\b(extract)\s*\(", "High Variable Hijacking: Overwrites local variables (e.g. $GLOBALS, $admin)."),
        (r"\b(preg_replace)\s*\(\s*['\"].*\/e['\"]", "Critical PHP preg_replace /e Modifier: Direct code evaluation."),
        (r"\b(create_function)\s*\(", "Critical Deprecated Function RCE: Evaluates string as PHP function code."),
        (r"\b(strcmp|strcasecmp)\s*\(", "Medium Type Juggling Risk: Pass array [] via GET/POST to bypass comparison."),
    ],
    "python": [
        (r"\b(eval|exec)\s*\(", "Critical RCE Sink: Direct Python code execution."),
        (r"\b(os\.system|os\.popen|subprocess\.Popen|subprocess\.run|subprocess\.call)\s*\(", "Critical Command Injection Sink."),
        (r"\b(pickle\.loads|pickle\.load|_pickle\.loads)\s*\(", "Critical Deserialization Sink: Python Pickle RCE."),
        (r"\b(yaml\.load|yaml\.unsafe_load)\s*\(", "Critical PyYAML Unsafe Load: Deserialization RCE."),
        (r"\b(render_template_string)\s*\(", "Critical SSTI Sink: Template rendered directly from string instead of file."),
        (r"\b(jinja2\.Template)\s*\(", "High SSTI Sink: Jinja2 template initialized with dynamic user string."),
        (r"\b(sqlite3\.connect|cursor\.execute)\s*\([^\?\%]*\%", "High SQL Injection: String formatting inside SQL query execution."),
    ],
    "javascript": [
        (r"\b(eval|Function|setTimeout|setInterval)\s*\(", "Critical Code Injection: Evaluates string as JavaScript."),
        (r"\b(child_process\.exec|child_process\.execSync|child_process\.spawn)\s*\(", "Critical Node.js Command Injection Sink."),
        (r"\b(serialize\.unserialize|node-serialize)\b", "Critical Node.js Deserialization RCE Sink."),
        (r"\b(innerHTML|outerHTML|document\.write)\s*=", "High DOM XSS Sink: Raw HTML injection."),
        (r"\b(vm\.runInThisContext|vm\.runInNewContext)\s*\(", "High Node.js VM Sandbox Escape Sink."),
    ]
}

def analyze_code_snippet(code: str, language: str = "php") -> List[Dict[str, Any]]:
    """Scan source code snippet for dangerous vulnerability sinks."""
    lang = language.lower()
    patterns = DANGEROUS_SINKS.get(lang, [])
    if not patterns:
        for k in DANGEROUS_SINKS:
            if k in lang:
                patterns = DANGEROUS_SINKS[k]
                break
    if not patterns:
        patterns = DANGEROUS_SINKS["php"] + DANGEROUS_SINKS["python"] + DANGEROUS_SINKS["javascript"]

    findings = []
    lines = code.splitlines()
    for line_idx, line in enumerate(lines, 1):
        for pattern, desc in patterns:
            for match in re.finditer(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": line_idx,
                    "matched": match.group(0),
                    "code": line.strip(),
                    "description": desc
                })
    return findings

FILE_UPLOAD_TRICKS = [
    {"Technique": "PHP Alternate Extensions", "Payload/Tip": ".php3, .php4, .php5, .phtml, .phar, .pht, .pgif"},
    {"Technique": "Apache Configuration Hijack", "Payload/Tip": "Upload `.htaccess` containing: `AddType application/x-httpd-php .png`"},
    {"Technique": "PHP User Config Hijack", "Payload/Tip": "Upload `.user.ini` containing: `auto_prepend_file=shell.png`"},
    {"Technique": "MIME Type Spoofing", "Payload/Tip": "Change `Content-Type: application/octet-stream` to `image/jpeg` or `image/png`"},
    {"Technique": "Magic Bytes Header", "Payload/Tip": "Prepend `GIF89a;` at the beginning of the PHP file to pass `getimagesize()` checks"},
    {"Technique": "Trailing Dots & Spaces (Windows)", "Payload/Tip": "Upload `shell.php.` or `shell.php ` or `shell.php::$DATA` (NTFS alternate data streams)"},
    {"Technique": "Double Extensions", "Payload/Tip": "`shell.php.jpg` or `shell.jpg.php` (if Apache processes right-to-left)"},
    {"Technique": "Null Byte Injection (PHP <= 5.3.4)", "Payload/Tip": "`shell.php%00.jpg` or `shell.php\\x00.jpg`"}
]

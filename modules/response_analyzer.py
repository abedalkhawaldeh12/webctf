"""
Intelligent Semantic Response Analyzer & Error Feedback Diagnostic Engine.
Parses server responses, stack traces, WAF blocks, SQL/LFI/SSTI error signatures,
and generates actionable adaptive exploit recommendations.
"""

import re
import html
from typing import Dict, List, Any, Optional

# Database Error Signatures & Engine Identification
DB_ERROR_PATTERNS = {
    "MySQL / MariaDB": [
        r"you have an error in your sql syntax",
        r"warning: mysql_",
        r"unclosed quotation mark after the character string",
        r"mysql_fetch_array\(\)",
        r"mysqli_fetch_array\(\)",
        r"column count doesn't match value count",
        r"unknown column '[^']+' in 'field list'"
    ],
    "PostgreSQL": [
        r"pg_query\(\): query failed:",
        r"psycopg2\.errors\.",
        r"syntax error at or near",
        r"unterminated quoted string at or near",
        r"current transaction is aborted, commands ignored until end of transaction block"
    ],
    "SQLite": [
        r"sqlite3\.operationalerror",
        r"sqlite error:",
        r"unrecognized token:",
        r"incomplete input",
        r"near \"[^\"]+\": syntax error",
        r"no such table:",
        r"no such column:"
    ],
    "Microsoft SQL Server (MSSQL)": [
        r"driver\]\[sql server\]",
        r"unclosed quotation mark before the character string",
        r"conversion failed when converting the varchar value",
        r"syntax error converting the varchar value"
    ],
    "Oracle": [
        r"ora-00933: sql command not properly ended",
        r"ora-00936: missing expression",
        r"ora-01756: quoted string not properly terminated",
        r"ora-00942: table or view does not exist"
    ]
}

# Template Engine / SSTI Error Signatures
SSTI_ERROR_PATTERNS = {
    "Jinja2 (Python)": [
        r"jinja2\.exceptions\.TemplateSyntaxError",
        r"jinja2\.exceptions\.UndefinedError",
        r"jinja2\.exceptions\.TemplateRuntimeError",
        r"builtins\.KeyError",
        r"builtins\.AttributeError"
    ],
    "Twig (PHP)": [
        r"Twig_Error_Syntax",
        r"Twig\\Error\\SyntaxError",
        r"Unexpected token \"[^\"]+\" of value",
        r"Unknown filter \"[^\"]+\""
    ],
    "Smarty (PHP)": [
        r"SmartyCompilerException",
        r"Smarty: [^<]+",
        r"Syntax Error in template"
    ],
    "Spring SpEL / Java": [
        r"org\.springframework\.expression\.spel\.SpelEvaluationException",
        r"EL1001E:",
        r"EL1004E:",
        r"org\.springframework\.expression\.spel\.SpelParseException"
    ],
    "Mako (Python)": [
        r"mako\.exceptions\.SyntaxException",
        r"mako\.exceptions\.CompileException"
    ]
}

# LFI & Path / Permission Signatures
LFI_ERROR_PATTERNS = [
    (r"failed to open stream: No such file or directory", "LFI Path Not Found: Target file does not exist in requested relative path. Try increasing directory traversal depth (../../)."),
    (r"open_basedir restriction in effect\. File\(([^\)]+)\) is not within the allowed path\(s\)", "PHP open_basedir Sandbox Active: Direct path traversal blocked by open_basedir. Use PHP stream wrappers (php://filter, data://, zip://, phar://)."),
    (r"failed to open stream: Permission denied", "LFI Permission Denied: Target file exists but web server user lacks read privileges. Target files readable by all (e.g. /etc/passwd, /proc/self/environ)."),
    (r"include\(\): Failed opening '([^']+)' for inclusion", "LFI Extension Appending: Backend code may be appending extension (e.g. .php). Try null-byte (%00) or path truncation (/. /.)."),
    (r"allow_url_include is disabled", "RFI Blocked: Remote file inclusion is disabled in php.ini. Focus on Local File Inclusion (LFI).")
]

# WAF & Filter Signatures
WAF_ERROR_PATTERNS = [
    (r"cloudflare", "Cloudflare WAF / Bot Management detected. Use IP bypass, header spoofing, or alternate encoding."),
    (r"mod_security|modsecurity", "ModSecurity WAF detected. Space, single quote, or keyword filter active. Use $IFS, hex encoding, or comment bypasses."),
    (r"blocked by web application firewall|403 forbidden|access denied", "Generic WAF / Security Filter blocked request. Payload triggered signature. Apply evasion encoding."),
    (r"malicious characters detected|illegal character|bad request", "Input Validation / Regex Filter triggered. Avoid specific characters (quotes, backticks, semicolons).")
]

class ResponseAnalyzer:
    """
    Semantic analysis engine for HTTP responses, errors, stack traces, and reflections.
    Provides contextual diagnosis and recommendations.
    """

    @staticmethod
    def analyze_response(
        response_text: str,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        probe_sent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform complete semantic inspection of a server response.
        Returns detailed diagnostics, identified errors, stack traces, and action recommendations.
        """
        headers = headers or {}
        text_lower = response_text.lower()
        
        diagnostics = {
            "status_code": status_code,
            "is_error": status_code >= 400 or any(k in text_lower for k in ["error", "exception", "fatal", "warning", "traceback"]),
            "db_errors": [],
            "ssti_errors": [],
            "lfi_errors": [],
            "waf_detected": [],
            "stack_traces": [],
            "leaked_paths": [],
            "recommendations": []
        }

        # 1. Database Error Diagnosis
        for dbms, patterns in DB_ERROR_PATTERNS.items():
            for pat in patterns:
                m = re.search(pat, response_text, re.IGNORECASE)
                if m:
                    diagnostics["db_errors"].append({
                        "dbms": dbms,
                        "matched_error": m.group(0),
                        "context": ResponseAnalyzer._get_snippet_context(response_text, m.start())
                    })
                    diagnostics["recommendations"].append(
                        f"SQL Injection confirmed on {dbms}. Use {dbms} specific syntax (e.g. comments, union syntax, auth bypasses)."
                    )

        # 2. SSTI Engine Error Diagnosis
        for engine, patterns in SSTI_ERROR_PATTERNS.items():
            for pat in patterns:
                m = re.search(pat, response_text, re.IGNORECASE)
                if m:
                    diagnostics["ssti_errors"].append({
                        "engine": engine,
                        "matched_error": m.group(0),
                        "context": ResponseAnalyzer._get_snippet_context(response_text, m.start())
                    })
                    diagnostics["recommendations"].append(
                        f"Template Engine confirmed as {engine}. Switch directly to {engine} RCE payload matrices."
                    )

        # 3. LFI & Path / Permission Diagnosis
        for pat, rec in LFI_ERROR_PATTERNS:
            m = re.search(pat, response_text, re.IGNORECASE)
            if m:
                diagnostics["lfi_errors"].append({
                    "matched_error": m.group(0),
                    "context": ResponseAnalyzer._get_snippet_context(response_text, m.start())
                })
                diagnostics["recommendations"].append(rec)

        # 4. WAF / Security Filter Detection
        for pat, rec in WAF_ERROR_PATTERNS:
            m = re.search(pat, response_text, re.IGNORECASE)
            if m or (status_code == 403 and "forbidden" in text_lower):
                diagnostics["waf_detected"].append({
                    "matched": m.group(0) if m else "403 Forbidden Filter",
                    "status": status_code
                })
                diagnostics["recommendations"].append(rec)
                break

        # 5. Extract Server Internal Paths
        path_matches = re.findall(r"(\/(?:var\/www|home|app|usr|etc|opt|tmp)[\w\/\.\-]+|[A-Z]:\\[\w\s\\\.\-]+)", response_text)
        if path_matches:
            diagnostics["leaked_paths"] = list(set(path_matches[:6]))
            diagnostics["recommendations"].append(
                f"Discovered backend server absolute paths: {', '.join(diagnostics['leaked_paths'][:3])}. Target these in LFI / RCE."
            )

        # 6. Extract Stack Trace Snippets (Python / PHP / JS)
        if "traceback (most recent call last)" in text_lower:
            tb_m = re.search(r"Traceback \(most recent call last\):.*?(?:\n[A-Za-z0-9_]+: .*)", response_text, re.DOTALL)
            if tb_m:
                diagnostics["stack_traces"].append({
                    "type": "Python Traceback",
                    "snippet": tb_m.group(0)[:500]
                })
        elif "fatal error:" in text_lower or "uncaught exception" in text_lower:
            err_m = re.search(r"(?:Fatal error|Uncaught Exception):.*?(?:\n.*)?", response_text, re.IGNORECASE)
            if err_m:
                diagnostics["stack_traces"].append({
                    "type": "PHP Fatal Error",
                    "snippet": err_m.group(0)[:500]
                })

        # Remove duplicate recommendations
        diagnostics["recommendations"] = list(dict.fromkeys(diagnostics["recommendations"]))
        return diagnostics

    @staticmethod
    def _get_snippet_context(text: str, match_pos: int, window: int = 100) -> str:
        """Extract a clean snippet of text around a matched position."""
        start = max(0, match_pos - 40)
        end = min(len(text), match_pos + window)
        snippet = text[start:end].replace("\n", " ").replace("\r", " ")
        return re.sub(r"\s+", " ", snippet).strip()

    @staticmethod
    def format_diagnostic_summary(diag: Dict[str, Any]) -> str:
        """Render a readable terminal summary of response analysis."""
        lines = []
        if diag["db_errors"]:
            for d in diag["db_errors"]:
                lines.append(f"[bold red]► Database Error ({d['dbms']}):[/bold red] {d['matched_error']}")
        if diag["ssti_errors"]:
            for s in diag["ssti_errors"]:
                lines.append(f"[bold magenta]► Template Engine Error ({s['engine']}):[/bold magenta] {s['matched_error']}")
        if diag["lfi_errors"]:
            for l in diag["lfi_errors"]:
                lines.append(f"[bold yellow]► LFI / Path Notice:[/bold yellow] {l['matched_error']}")
        if diag["waf_detected"]:
            for w in diag["waf_detected"]:
                lines.append(f"[bold red]► WAF / Filter Triggered:[/bold red] {w['matched']}")
        if diag["leaked_paths"]:
            lines.append(f"[bold cyan]► Leaked Absolute Paths:[/bold cyan] {', '.join(diag['leaked_paths'][:3])}")
        if diag["recommendations"]:
            lines.append("[bold green]► Intelligent Action Recommendations:[/bold green]")
            for r in diag["recommendations"]:
                lines.append(f"   • {r}")
        return "\n".join(lines)

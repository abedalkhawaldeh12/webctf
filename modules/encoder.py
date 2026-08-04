"""
Encoder and Decoder module for Web CTF challenges.
Supports multi-layer auto decoding, custom ciphers, and PHP magic hashes.
"""

import base64
import binascii
import html
import hashlib
import re
import urllib.parse
from typing import Dict, List, Tuple
from core.ui import print_table, print_success, print_info, print_warning, print_error, print_flag
from core.utils import find_flags

# Known PHP Magic Hashes for type juggling (0e...)
PHP_MAGIC_HASHES = {
    "MD5": [
        {"input": "QNKCDZO", "hash": "0e830400451993494058024219903391", "type": "string"},
        {"input": "240610708", "hash": "0e462097431906509019562988736854", "type": "int"},
        {"input": "s878926199a", "hash": "0e546589742199948578144234410965", "type": "string"},
        {"input": "s155964671a", "hash": "0e342768416822451524974117254469", "type": "string"},
        {"input": "s214587387a", "hash": "0e848240448830537924465865611904", "type": "string"},
        {"input": "s1091221200a", "hash": "0e940624217856561557816327384675", "type": "string"},
        {"input": "0e215962017", "hash": "0e291242476940776840726934186749", "type": "string (starts with 0e)"},
    ],
    "SHA1": [
        {"input": "aaroZmOk", "hash": "0e66507019969427134894567496905882469905", "type": "string"},
        {"input": "aaK1STfY", "hash": "0e76651200049037509391330104977259456776", "type": "string"},
        {"input": "aaO8zKZF", "hash": "0e89252659864285377915520935131330787724", "type": "string"},
        {"input": "10932435112", "hash": "0e07766914998860379159981409708616190682", "type": "string"},
    ],
    "SHA256": [
        {"input": "TyNOQHUS", "hash": "0e66298694359207596086555224342882617905053001026053632997758736", "type": "string"},
    ]
}

def encode_all(text: str) -> Dict[str, str]:
    """Encode a string into various common Web CTF formats."""
    results = {}
    raw_bytes = text.encode("utf-8")

    # Base64
    results["Base64"] = base64.b64encode(raw_bytes).decode()
    results["Base64 (URL-safe)"] = base64.urlsafe_b64encode(raw_bytes).decode()
    
    # Base32 & Base85
    results["Base32"] = base64.b32encode(raw_bytes).decode()
    results["Base85"] = base64.b85encode(raw_bytes).decode()
    
    # Hex
    results["Hex (Raw)"] = raw_bytes.hex()
    results["Hex (\\x..)"] = "".join(f"\\x{b:02x}" for b in raw_bytes)
    results["Hex (0x..)"] = "0x" + raw_bytes.hex()
    
    # URL Encoded
    results["URL (Standard)"] = urllib.parse.quote(text)
    results["URL (All Chars)"] = "".join(f"%{b:02X}" for b in raw_bytes)
    results["Double URL"] = urllib.parse.quote(urllib.parse.quote(text))
    
    # HTML Entities
    results["HTML Entity (Dec)"] = "".join(f"&#{ord(c)};" for c in text)
    results["HTML Entity (Hex)"] = "".join(f"&#x{ord(c):02x};" for c in text)
    
    # Rot13
    results["ROT13"] = rot_n(text, 13)
    
    # Binary & Octal
    results["Binary (8-bit)"] = " ".join(f"{b:08b}" for b in raw_bytes)
    results["Octal (\\...)"] = "".join(f"\\{b:03o}" for b in raw_bytes)
    
    # Unicode Escape
    results["Unicode (\\u....)"] = "".join(f"\\u{ord(c):04x}" for c in text)
    
    # Code-specific bypasses
    results["JS String.fromCharCode"] = f"String.fromCharCode({','.join(str(ord(c)) for c in text)})"
    results["PHP chr() concat"] = ".".join(f"chr({ord(c)})" for c in text)
    results["SQL CHAR() concat"] = f"CHAR({','.join(str(ord(c)) for c in text)})"
    
    return results

def decode_all(text: str) -> Dict[str, str]:
    """Attempt decoding a string across various common encodings."""
    results = {}
    text_clean = text.strip()

    # Base64
    try:
        b64_decoded = base64.b64decode(text_clean).decode("utf-8", errors="ignore")
        if b64_decoded and b64_decoded.isprintable():
            results["Base64"] = b64_decoded
    except Exception:
        pass

    # Hex
    try:
        hex_clean = text_clean.replace("\\x", "").replace("0x", "").replace(" ", "")
        hex_decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
        if hex_decoded and hex_decoded.isprintable():
            results["Hex"] = hex_decoded
    except Exception:
        pass

    # URL
    try:
        url_decoded = urllib.parse.unquote(text_clean)
        if url_decoded != text_clean:
            results["URL"] = url_decoded
            # Double URL
            double_url = urllib.parse.unquote(url_decoded)
            if double_url != url_decoded:
                results["Double URL"] = double_url
    except Exception:
        pass

    # HTML Entities
    try:
        html_decoded = html.unescape(text_clean)
        if html_decoded != text_clean:
            results["HTML Entities"] = html_decoded
    except Exception:
        pass

    # ROT13
    results["ROT13"] = rot_n(text_clean, 13)

    # Binary
    try:
        bin_tokens = text_clean.replace(" ", "")
        if re.fullmatch(r"[01]+", bin_tokens) and len(bin_tokens) % 8 == 0:
            bin_bytes = bytearray(int(bin_tokens[i:i+8], 2) for i in range(0, len(bin_tokens), 8))
            results["Binary"] = bin_bytes.decode("utf-8", errors="ignore")
    except Exception:
        pass

    # Unicode escapes (\u0041...)
    try:
        if "\\u" in text_clean:
            u_decoded = text_clean.encode("utf-8").decode("unicode_escape")
            if u_decoded != text_clean:
                results["Unicode Escape"] = u_decoded
    except Exception:
        pass

    return results

def rot_n(text: str, n: int) -> str:
    """Caesar cipher / ROT-N rotation."""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        else:
            result.append(c)
    return "".join(result)

def caesar_bruteforce(text: str) -> List[Tuple[int, str]]:
    """Bruteforce all 25 Caesar cipher shifts."""
    return [(shift, rot_n(text, shift)) for shift in range(1, 26)]

def auto_smart_decode(text: str, max_depth: int = 8) -> List[Dict[str, str]]:
    """
    Intelligently unwrap layered encodings (e.g. Base64(URL(Hex(Flag)))).
    Returns the step-by-step decoding chain and detects any flags.
    """
    current = text.strip()
    history = [{"step": "Original", "format": "Input", "output": current}]
    seen = {current}

    for depth in range(1, max_depth + 1):
        found_layer = False
        candidates = []

        # Try URL decode
        try:
            unquoted = urllib.parse.unquote(current)
            if unquoted != current and unquoted not in seen:
                candidates.append(("URL Decode", unquoted))
        except Exception:
            pass

        # Try HTML unescape
        try:
            unescaped = html.unescape(current)
            if unescaped != current and unescaped not in seen:
                candidates.append(("HTML Unescape", unescaped))
        except Exception:
            pass

        # Try Base64
        try:
            if re.match(r"^[A-Za-z0-9+/=]{4,}$", current) and len(current) % 4 == 0:
                b64_out = base64.b64decode(current).decode("utf-8", errors="ignore")
                if b64_out and b64_out.isprintable() and b64_out not in seen and len(b64_out) > 0:
                    candidates.append(("Base64", b64_out))
        except Exception:
            pass

        # Try Hex
        try:
            hex_clean = current.replace("\\x", "").replace("0x", "").replace(" ", "").replace(":", "")
            if re.fullmatch(r"[0-9a-fA-F]+", hex_clean) and len(hex_clean) % 2 == 0 and len(hex_clean) >= 4:
                hex_out = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
                if hex_out and hex_out.isprintable() and hex_out not in seen and len(hex_out) > 0:
                    candidates.append(("Hex", hex_out))
        except Exception:
            pass

        # Try Binary
        try:
            bin_clean = current.replace(" ", "")
            if re.fullmatch(r"[01]+", bin_clean) and len(bin_clean) % 8 == 0 and len(bin_clean) >= 8:
                bin_bytes = bytearray(int(bin_clean[i:i+8], 2) for i in range(0, len(bin_clean), 8))
                bin_out = bin_bytes.decode("utf-8", errors="ignore")
                if bin_out and bin_out.isprintable() and bin_out not in seen:
                    candidates.append(("Binary", bin_out))
        except Exception:
            pass

        # Check if candidate found
        if candidates:
            # Pick best candidate
            best_fmt, best_val = candidates[0]
            current = best_val
            seen.add(current)
            history.append({"step": f"Layer {depth}", "format": best_fmt, "output": current})
            found_layer = True
            
            # Check if flag uncovered
            flags = find_flags(current)
            if flags:
                break
        else:
            break

    return history

def compute_hashes(text: str) -> Dict[str, str]:
    """Compute common cryptographic hashes for given text."""
    raw = text.encode("utf-8")
    return {
        "MD5": hashlib.md5(raw).hexdigest(),
        "SHA1": hashlib.sha1(raw).hexdigest(),
        "SHA224": hashlib.sha224(raw).hexdigest(),
        "SHA256": hashlib.sha256(raw).hexdigest(),
        "SHA384": hashlib.sha384(raw).hexdigest(),
        "SHA512": hashlib.sha512(raw).hexdigest(),
    }

def lookup_magic_hashes(algo: str = "ALL") -> List[Dict[str, str]]:
    """Retrieve PHP magic hashes that evaluate to 0 in loose comparisons (0e...)."""
    records = []
    target_algos = [algo.upper()] if algo.upper() in PHP_MAGIC_HASHES else PHP_MAGIC_HASHES.keys()
    for alg in target_algos:
        for entry in PHP_MAGIC_HASHES[alg]:
            records.append({
                "Algorithm": alg,
                "Input": entry["input"],
                "Hash Output": entry["hash"],
                "Type": entry["type"]
            })
    return records

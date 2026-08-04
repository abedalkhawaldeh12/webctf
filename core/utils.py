"""
Common utility functions for WebCTF Suite (flag matching, HTTP wrapper, clipboard helper).
"""

import re
import urllib.parse
from typing import List, Optional
import requests
from core.ui import print_flag, print_info

FLAG_PATTERNS = [
    r"(?:picoCTF|flag|ctf|htb|thm|cscg|ductf|seccon|hitcon|[a-zA-Z0-9_\-]{3,25})\{[a-zA-Z0-9_\-\.!@#%^&*+=~?]{4,100}\}", # Standard: flag{...}, CTF{...}, picoCTF{...}
    r"FLAG:[a-zA-Z0-9_\-]{4,100}",                       # FLAG:xyz
    r"flag_[a-zA-Z0-9_\-]{6,100}",                       # flag_xyz
]

def find_flags(text: str, custom_prefix: Optional[str] = None) -> List[str]:
    """Scan arbitrary text for CTF flags using regex patterns."""
    flags = []
    patterns = list(FLAG_PATTERNS)
    if custom_prefix:
        patterns.insert(0, rf"{re.escape(custom_prefix)}\{{[^\}}\n\r\t ]+\}}")
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            # Filter out obvious false positives like programming macros or variable templates
            if m.startswith("AX_CHECK_") or "{$" in m or m.startswith("features{") or m.startswith("ENV{"):
                continue
            if m not in flags:
                flags.append(m)
    return flags

def check_and_print_flags(text: str, prefix: Optional[str] = None) -> bool:
    """Check text for flags and print nicely if found."""
    flags = find_flags(text, prefix)
    if flags:
        for f in flags:
            print_flag(f)
        return True
    return False

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def make_session(proxy: Optional[str] = None, headers: Optional[dict] = None) -> requests.Session:
    """Create a configured requests session."""
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WebCTF-Tool/1.0"
    })
    if headers:
        session.headers.update(headers)
    if proxy:
        session.proxies = {
            "http": proxy,
            "https": proxy
        }
    return session


create_session = make_session


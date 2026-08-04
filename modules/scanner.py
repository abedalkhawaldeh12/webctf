"""
CTF Fast Reconnaissance & Flag Sniffer Module for Web CTF challenges.
Probes common CTF source leaks (.git, .env, backups) and scrapes flags from headers and HTML comments.
"""

import concurrent.futures
import requests
import re
from typing import List, Dict, Tuple, Optional, Any
from core.ui import print_table, print_success, print_info, print_warning, print_error, print_flag
from core.utils import find_flags

CTF_SENSITIVE_PATHS = [
    # Information & Search Engines
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    # Source Code Repositories
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".svn/entries",
    ".hg/requires",
    # Environment & Configurations
    ".env",
    ".env.local",
    ".env.production",
    "config.php",
    "config.json",
    "web.config",
    ".htaccess",
    # Docker & Infrastructure
    "Dockerfile",
    "docker-compose.yml",
    # Backup & Source Leaks
    "index.php.bak",
    "index.php.old",
    "index.php~",
    "index.phps",
    ".index.php.swp",
    "config.php.bak",
    "config.php.old",
    "admin.php.bak",
    "login.php.bak",
    "source.php",
    "src.php",
    "test.php",
    "phpinfo.php",
    "app.py.bak",
    "main.py.bak",
    "server.js.bak",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "dump.sql",
    ".DS_Store",
    # CTF Flag endpoints
    "flag.txt",
    "flag.php",
    "flag",
    "secret.txt",
    "secret.php",
    "secret.txt",
    "hint.txt",
    # Debug / Admin Consoles
    "console",
    "phpinfo.php",
    "info.php",
    "test.php",
    "swagger.json",
    "openapi.json",
    "api/docs",
    "graphql",
]

def check_endpoint(base_url: str, path: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Check if single endpoint exists and scan for flags."""
    target = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(target, timeout=timeout, allow_redirects=False, verify=False, headers={
            "User-Agent": "Mozilla/5.0 (CTF-Recon/1.0)"
        })

        if r.status_code in [200, 301, 302, 403]:
            # Scan response for flags
            flags = find_flags(r.text)
            
            # Check headers
            header_flags = []
            for k, v in r.headers.items():
                hf = find_flags(f"{k}: {v}")
                if hf:
                    header_flags.extend(hf)
                    
            return {
                "path": path,
                "url": target,
                "status": r.status_code,
                "length": len(r.content),
                "flags": flags + header_flags,
                "is_hit": r.status_code == 200 and len(r.content) > 0
            }
    except Exception:
        pass
    return None

def scan_target(base_url: str, max_workers: int = 10, flag_prefix: Optional[str] = None) -> List[Dict[str, Any]]:
    """Run concurrent quick scan against target CTF web challenge."""
    print_info(f"Starting Quick CTF Recon against: [bold cyan]{base_url}[/bold cyan]")
    results = []
    
    # 1. Check Root Page & Extract Comments / Headers
    try:
        root_resp = requests.get(base_url, timeout=5)
        root_flags = find_flags(root_resp.text, flag_prefix)
        
        # Check comments
        comments = re.findall(r"<!--(.*?)-->", root_resp.text, re.DOTALL)
        for comment in comments:
            c_flags = find_flags(comment, flag_prefix)
            if c_flags:
                root_flags.extend(c_flags)
                
        # Check headers & cookies
        for k, v in root_resp.headers.items():
            h_flags = find_flags(f"{k}: {v}", flag_prefix)
            if h_flags:
                root_flags.extend(h_flags)
                
        if root_flags:
            for f in set(root_flags):
                print_flag(f)
                
        if comments:
            print_info(f"Found {len(comments)} HTML comments in root page.")
    except Exception as e:
        print_warning(f"Could not fetch root page: {e}")

    # 2. Concurrently Probe Sensitive Paths
    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_endpoint, base_url, p): p for p in CTF_SENSITIVE_PATHS}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res and (res["is_hit"] or res["status"] in [200, 301, 302]):
                hits.append(res)
                if res["flags"]:
                    for f in res["flags"]:
                        print_flag(f)
                        
    # Sort hits by status code then length
    hits.sort(key=lambda x: (x["status"], -x["length"]))
    return hits

def extract_forms_and_links(html_text: str, base_url: str) -> Dict[str, Any]:
    """Extract links, forms, inputs, and JavaScript API endpoints from HTML."""
    from urllib.parse import urljoin, urlparse, parse_qs
    
    links = set()
    parameters = set()
    forms = []
    
    # 1. Extract <a href="...">
    for href in re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\'](.*?)["\']', html_text, re.IGNORECASE):
        full_url = urljoin(base_url, href.strip())
        if full_url.startswith("http"):
            links.add(full_url)
            parsed = urlparse(full_url)
            for param in parse_qs(parsed.query).keys():
                parameters.add(param)

    # 2. Extract <script src="..."> and inline <script>...</script>
    scripts = set()
    js_endpoints = set()
    for src in re.findall(r'<script\s+[^>]*?src=["\'](.*?)["\']', html_text, re.IGNORECASE):
        full_src = urljoin(base_url, src.strip())
        if full_src.startswith("http"):
            scripts.add(full_src)
            links.add(full_src)

    for js_route in re.findall(r'["\'](/api/[^"\']+|/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)["\']', html_text):
        full_route = urljoin(base_url, js_route)
        js_endpoints.add(full_route)

    inline_scripts = re.findall(r'<script(?:\s+[^>]*)?>(.*?)</script>', html_text, re.DOTALL | re.IGNORECASE)

    # 3. Extract <form> elements
    form_blocks = re.findall(r'<form(.*?)>(.*?)</form>', html_text, re.DOTALL | re.IGNORECASE)
    for form_attr, form_body in form_blocks:
        action_match = re.search(r'action=["\']([^"\']*?)["\']', form_attr, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']*?)["\']', form_attr, re.IGNORECASE)
        form_id_match = re.search(r'id=["\']([^"\']*?)["\']', form_attr, re.IGNORECASE)
        
        action = urljoin(base_url, action_match.group(1).strip()) if action_match else base_url
        method = method_match.group(1).upper() if method_match else "POST"  # Default POST (most auth/CTF forms)
        form_id = form_id_match.group(1) if form_id_match else None
        
        inputs = []
        for inp in re.finditer(r'<input\s+([^>]*?)>', form_body, re.IGNORECASE):
            attrs = inp.group(1)
            name_m = re.search(r'name=["\']([^"\']*?)["\']', attrs, re.IGNORECASE)
            type_m = re.search(r'type=["\']([^"\']*?)["\']', attrs, re.IGNORECASE)
            val_m = re.search(r'value=["\']([^"\']*?)["\']', attrs, re.IGNORECASE)
            if name_m:
                inputs.append({
                    "name": name_m.group(1),
                    "type": type_m.group(1).lower() if type_m else "text",
                    "value": val_m.group(1) if val_m else ""
                })
                parameters.add(name_m.group(1))

        # Textarea
        for ta in re.finditer(r'<textarea\s+([^>]*?)name=["\']([^"\']*?)["\']', form_body, re.IGNORECASE):
            name = ta.group(2)
            inputs.append({"name": name, "type": "textarea", "value": ""})
            parameters.add(name)

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
            "id": form_id
        })

    # 4. Detect JavaScript-based form submissions
    # Pattern: initAuthForm('form-id', '/auth/login') or similar
    for js_init in re.findall(r"initAuthForm\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", html_text):
        form_id_js, endpoint_js = js_init
        full_endpoint = urljoin(base_url, endpoint_js)
        # Update matching form's action and ensure method is POST (fetch uses POST)
        for f in forms:
            if f.get("id") == form_id_js:
                f["action"] = full_endpoint
                f["method"] = "POST"
                break

    # Pattern: fetch('/endpoint', { method: 'POST', ... }) in inline scripts
    for inline in inline_scripts:
        fetch_matches = re.findall(r"fetch\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*\{[^}]*method\s*:\s*['\"](\w+)['\"]", inline, re.DOTALL)
        for fetch_url, fetch_method in fetch_matches:
            full_fetch = urljoin(base_url, fetch_url)
            if full_fetch not in [f["action"] for f in forms]:
                links.add(full_fetch)

    return {
        "links": list(links),
        "forms": forms,
        "parameters": list(parameters),
        "js_endpoints": list(js_endpoints),
        "scripts": list(scripts),
        "inline_scripts": inline_scripts
    }


def fingerprint_tech(headers: Dict[str, str], html_text: str, cookies: Dict[str, str]) -> List[str]:
    """Detect backend server, framework, language, and template engines."""
    tech = set()
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()
    
    # Server headers
    if "apache" in server: tech.add("Apache")
    if "nginx" in server: tech.add("Nginx")
    if "werkzeug" in server or "gunicorn" in server:
        tech.add("Python")
        tech.add("Flask/Werkzeug")
    if "express" in powered or "node" in server:
        tech.add("Node.js")
        tech.add("Express")
    if "php" in powered or "php" in server:
        tech.add("PHP")
    if "kestrel" in server or "asp.net" in powered:
        tech.add("ASP.NET")

    # Cookies
    for cname in cookies.keys():
        cl = cname.lower()
        if "phpsessid" in cl: tech.add("PHP")
        elif "session" in cl or "flask" in cl: tech.add("Python/Flask")
        elif "connect.sid" in cl: tech.add("Node.js")
        elif "jwt" in cl or "token" in cl: tech.add("JWT")
        elif "csrftoken" in cl: tech.add("Django")

    # HTML Signatures
    hl = html_text.lower()
    if "django" in hl: tech.add("Django")
    if "flask" in hl or "jinja2" in hl: tech.add("Jinja2")
    if "laravel" in hl: tech.add("Laravel")
    if "wordpress" in hl: tech.add("WordPress")
    if "twig" in hl: tech.add("Twig")
    if "thymeleaf" in hl: tech.add("Thymeleaf")

    return list(tech)


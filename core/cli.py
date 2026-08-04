"""
CLI Interface & Interactive Shell for WebCTF Suite.
Provides command routing, rich output formatting, and interactive prompt.
"""

import sys
import os
import cmd
import shlex
import json
import argparse
from typing import List

from core.ui import (
    console, print_banner, print_header, print_success, print_error,
    print_info, print_warning, print_flag, print_table, print_payload, print_code
)
from core.utils import find_flags, check_and_print_flags

from modules.encoder import (
    encode_all, decode_all, auto_smart_decode, caesar_bruteforce,
    compute_hashes, lookup_magic_hashes
)
from modules.ssti import (
    get_all_ssti_engines, get_ssti_detection_tree, DETECTION_PAYLOADS
)
from modules.cmd_inj import (
    get_space_bypasses, get_keyword_bypasses, get_reverse_shells
)
from modules.sqli import (
    AUTH_BYPASSES, get_mysql_payloads, get_sqlite_payloads,
    get_postgres_payloads, get_mssql_payloads, get_oracle_payloads
)
from modules.lfi_tool import (
    get_php_wrappers, get_traversal_bypasses, get_poisoning_targets
)
from modules.ssrf import (
    obfuscate_ip, CLOUD_METADATA_ENDPOINTS
)
from modules.xxe_xss import (
    get_xxe_payloads, get_xss_payloads
)
from modules.deserializer import (
    generate_pickle_payload, generate_nodejs_serialize_payload,
    generate_pyyaml_payload, get_php_unserialize_tips,
    generate_php_serialized_object, get_java_deserialization_templates
)
from modules.jwt_tool import (
    decode_jwt, forge_alg_none, sign_jwt_hs256, bruteforce_secret,
    key_confusion_rs256_to_hs256
)
from modules.blind_exfiltrator import (
    generate_boolean_blind_script, generate_time_blind_script, live_boolean_exfiltrate
)
from modules.scanner import scan_target
from modules.cheatsheet import (
    PHP_QUIRKS, FILE_UPLOAD_TRICKS, analyze_code_snippet
)
from modules.autopwn import AutoPwnPipeline
from core.memory import LearningEngine, SessionStorage, LootManager
from modules.response_analyzer import ResponseAnalyzer
from modules.bypass_engine import BypassEngine
from modules.chaining_engine import VulnerabilityChainEngine
from modules.container_escape import ContainerEscapeAdvisor




class WebCTFShell(cmd.Cmd):
    """Interactive Shell for WebCTF Suite."""
    intro = ""
    prompt = "\033[1;36mwebctf\033[0m \033[1;33m>\033[0m "

    def default(self, line):
        print_error(f"Unknown command: '{line}'. Type 'help' or '?' for available commands.")

    def do_clear(self, arg):
        """Clear terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()

    def do_exit(self, arg):
        """Exit WebCTF Suite."""
        console.print("[bold red]Good luck with your CTF! Goodbye![/bold red]")
        return True

    def do_quit(self, arg):
        """Exit WebCTF Suite."""
        return self.do_exit(arg)

    # ─── ENCODE / DECODE ──────────────────────────────────────────────
    def do_encode(self, arg):
        """Encode text across multiple CTF formats: encode <text>"""
        if not arg:
            print_warning("Usage: encode <text>")
            return
        results = encode_all(arg)
        rows = [[fmt, val] for fmt, val in results.items()]
        print_table(["Format / Method", "Encoded Value"], rows, title=f"Encodings for: '{arg}'")

    def do_decode(self, arg):
        """Decode text using smart auto-detection: decode <text> or decode auto <text>"""
        if not arg:
            print_warning("Usage: decode <text> or decode auto <text>")
            return
        args = shlex.split(arg)
        if args[0].lower() == "auto":
            text = " ".join(args[1:]) if len(args) > 1 else ""
            if not text:
                print_warning("Usage: decode auto <text>")
                return
            layers = auto_smart_decode(text)
            rows = [[l["step"], l["format"], l["output"]] for l in layers]
            print_table(["Step", "Layer Format", "Decoded Output"], rows, title="Smart Multi-Layer Decoding Chain")
            check_and_print_flags(layers[-1]["output"])
        else:
            text = arg
            results = decode_all(text)
            if results:
                rows = [[fmt, val] for fmt, val in results.items()]
                print_table(["Format", "Decoded Result"], rows, title=f"Decoded Variants for: '{text}'")
                for val in results.values():
                    check_and_print_flags(val)
            else:
                print_warning("No standard single-layer decoding matched. Try: decode auto <text>")

    def do_magic(self, arg):
        """Display PHP Magic Hashes for loose comparison bypass: magic [md5|sha1|sha256]"""
        algo = arg.strip() if arg else "ALL"
        hashes = lookup_magic_hashes(algo)
        rows = [[h["Algorithm"], h["Input"], h["Hash Output"], h["Type"]] for h in hashes]
        print_table(["Algo", "Input String/Number", "Hash Output (Starts with 0e)", "Input Type"], rows, title="PHP Magic Hashes Database")

    # ─── SSTI MODULE ───────────────────────────────────────────────────
    def do_ssti(self, arg):
        """Generate SSTI payloads: ssti <jinja2|twig|smarty|mako|freemarker|spel|tree> [cmd]"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: ssti <jinja2|twig|smarty|mako|freemarker|spel|tree> [command]")
            return
        
        target = args[0].lower()
        if target == "tree":
            print_header("SSTI Identification Decision Tree")
            console.print(get_ssti_detection_tree())
            rows = [[d["engine"], d["payload"], d["desc"]] for d in DETECTION_PAYLOADS]
            print_table(["Test Engine", "Probe Expression", "Description"], rows, title="SSTI Polyglots & Probes")
            return
            
        engines = get_all_ssti_engines()
        if target in engines:
            cmd_to_run = " ".join(args[1:]) if len(args) > 1 else "id"
            payloads = engines[target](cmd_to_run)
            print_header(f"SSTI Payloads: {target.upper()}", f"Command: {cmd_to_run}")
            for p in payloads:
                print_payload(p["name"], p["payload"], p["desc"])
        else:
            print_error(f"Unknown template engine: {target}. Available: {', '.join(engines.keys())}, tree")

    # ─── COMMAND INJECTION ─────────────────────────────────────────────
    def do_cmd(self, arg):
        """Command Injection & Reverse Shell Crafter: cmd <bypass|rev> [args]"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: cmd bypass <command>  OR  cmd rev <ip> <port>")
            return
            
        action = args[0].lower()
        if action == "bypass":
            target_cmd = " ".join(args[1:]) if len(args) > 1 else "cat /etc/passwd"
            print_header("Command Injection Bypasses", f"Command: {target_cmd}")
            space_bypasses = get_space_bypasses(target_cmd)
            for p in space_bypasses:
                print_payload(p["name"], p["payload"], p["desc"])
            keyword_bypasses = get_keyword_bypasses(target_cmd)
            for p in keyword_bypasses:
                print_payload(p["name"], p["payload"], p["desc"])
                
        elif action == "rev":
            ip = args[1] if len(args) > 1 else "10.10.14.1"
            port = int(args[2]) if len(args) > 2 else 4444
            print_header("Reverse Shell One-Liners", f"Target: {ip}:{port}")
            shells = get_reverse_shells(ip, port)
            for s in shells:
                print_payload(s["name"], s["payload"], s["desc"])
        else:
            print_warning("Unknown action. Use 'cmd bypass <command>' or 'cmd rev <ip> <port>'")

    # ─── SQL INJECTION ─────────────────────────────────────────────────
    def do_sqli(self, arg):
        """SQLi Payloads and DBMS Cheatsheet: sqli <mysql|sqlite|postgres|mssql|oracle|auth>"""
        target = arg.strip().lower() if arg else ""
        if not target:
            print_warning("Usage: sqli <mysql|sqlite|postgres|mssql|oracle|auth>")
            return
            
        if target == "auth":
            print_header("SQLi Authentication Bypasses")
            for p in AUTH_BYPASSES:
                print_payload(p["name"], p["payload"], p["desc"])
        elif target == "mysql":
            print_header("MySQL / MariaDB Injection Vectors")
            for p in get_mysql_payloads():
                print_payload(p["name"], p["payload"], p["desc"])
        elif target == "sqlite":
            print_header("SQLite Injection Vectors")
            for p in get_sqlite_payloads():
                print_payload(p["name"], p["payload"], p["desc"])
        elif target == "postgres":
            print_header("PostgreSQL Injection Vectors")
            for p in get_postgres_payloads():
                print_payload(p["name"], p["payload"], p["desc"])
        elif target == "mssql":
            print_header("MSSQL Server Injection Vectors")
            for p in get_mssql_payloads():
                print_payload(p["name"], p["payload"], p["desc"])
        elif target == "oracle":
            print_header("Oracle Database Injection Vectors")
            for p in get_oracle_payloads():
                print_payload(p["name"], p["payload"], p["desc"])
        else:
            print_error(f"Unknown DBMS: {target}. Available: mysql, sqlite, postgres, mssql, oracle, auth")

    # ─── LFI & PHP WRAPPERS ────────────────────────────────────────────
    def do_lfi(self, arg):
        """LFI and PHP Wrapper Payload Crafter: lfi <wrappers|traversal|poison> [target]"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: lfi <wrappers|traversal|poison> [target_file]")
            return
            
        action = args[0].lower()
        target = args[1] if len(args) > 1 else ""
        
        if action == "wrappers":
            fname = target or "index.php"
            print_header("PHP Stream Wrappers", f"Target: {fname}")
            for p in get_php_wrappers(fname):
                print_payload(p["name"], p["payload"], p["desc"])
        elif action == "traversal":
            fname = target or "/etc/passwd"
            print_header("Path Traversal Bypasses", f"Target: {fname}")
            for p in get_traversal_bypasses(fname):
                print_payload(p["name"], p["payload"], p["desc"])
        elif action == "poison":
            print_header("LFI Log & Session Poisoning Reference")
            targets = get_poisoning_targets()
            rows = [[t["name"], t["path"], t["technique"]] for t in targets]
            print_table(["Service / Source", "Default Path", "Poisoning Technique"], rows, title="Poisoning Reference")
        else:
            print_warning("Unknown action. Available: lfi wrappers, lfi traversal, lfi poison")

    # ─── SSRF & IP OBFUSCATION ────────────────────────────────────────
    def do_ssrf(self, arg):
        """SSRF IP Obfuscator & Cloud Metadata Endpoints: ssrf <ip> or ssrf cloud"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: ssrf <ip_address>  OR  ssrf cloud")
            return
            
        if args[0].lower() == "cloud":
            print_header("Cloud Instance Metadata Service (IMDS) Endpoints")
            rows = [[c["provider"], c["url"], c["desc"]] for c in CLOUD_METADATA_ENDPOINTS]
            print_table(["Provider", "Metadata URL", "Notes"], rows, title="Cloud Endpoints")
        else:
            ip = args[0]
            print_header("SSRF IP Obfuscation Formats", f"Base IP: {ip}")
            results = obfuscate_ip(ip)
            rows = [[fmt, val] for fmt, val in results.items()]
            print_table(["Format / Evasion Technique", "Obfuscated Target"], rows, title=f"Obfuscations for: {ip}")

    # ─── XXE & XSS ─────────────────────────────────────────────────────
    def do_xxe(self, arg):
        """XML External Entity (XXE) Payloads: xxe [target_file] [attacker_url]"""
        args = shlex.split(arg) if arg else []
        tf = args[0] if len(args) > 0 else "/etc/passwd"
        att = args[1] if len(args) > 1 else "http://attacker.com"
        print_header("XXE Injection Payloads", f"File: {tf}")
        for p in get_xxe_payloads(tf, att):
            print_payload(p["name"], p["payload"], p["desc"])

    def do_xss(self, arg):
        """XSS & Prototype Pollution Vectors: xss"""
        print_header("XSS & Prototype Pollution Vectors")
        for p in get_xss_payloads():
            print_payload(p["name"], p["payload"], p["desc"])

    # ─── DESERIALIZATION ───────────────────────────────────────────────
    def do_deser(self, arg):
        """Deserialization Exploit Crafter: deser <pickle|node|yaml|php> [cmd]"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: deser <pickle|node|yaml|php> [command]")
            return
            
        target = args[0].lower()
        cmd_str = " ".join(args[1:]) if len(args) > 1 else "id"
        
        if target == "pickle":
            print_header("Python Pickle RCE Payload", f"Command: {cmd_str}")
            res = generate_pickle_payload(cmd_str)
            for k, v in res.items():
                print_payload(k, v)
        elif target == "node":
            print_header("Node.js node-serialize IIFE RCE Payload", f"Command: {cmd_str}")
            res = generate_nodejs_serialize_payload(cmd_str)
            for k, v in res.items():
                print_payload(k, v)
        elif target == "yaml":
            print_header("PyYAML Unsafe Load RCE Payload", f"Command: {cmd_str}")
            res = generate_pyyaml_payload(cmd_str)
            for k, v in res.items():
                print_payload(k, v)
        elif target == "php":
            print_header("PHP Object Injection & Magic Methods")
            tips = get_php_unserialize_tips()
            rows = [[t["Magic Method"], t["Trigger"], t["Use Case"]] for t in tips]
            print_table(["Magic Method", "Trigger Condition", "Exploit Usage"], rows, title="PHP Magic Methods")
        elif target in ["java", "ysoserial"]:
            print_header("Java Deserialization Gadget Templates", f"Command: {cmd_str}")
            templates = get_java_deserialization_templates(cmd_str)
            for t in templates:
                print_payload(t["Gadget Chain"], t["Ysoserial Command"], f"Dependency: {t['Dependency']} | Trigger: {t['Trigger']}")
        else:
            print_error(f"Unknown target: {target}. Available: pickle, node, yaml, php, java")

    # ─── WAF BYPASS & MUTATION ─────────────────────────────────────────
    def do_bypass(self, arg):
        """WAF Bypass & Payload Mutation Core: bypass <sqli|cmd|ssti|lfi> <payload_or_command> [level] [engine]"""
        args = shlex.split(arg) if arg else []
        if len(args) < 2:
            print_warning("Usage: bypass <sqli|cmd|ssti|lfi> <payload_or_cmd> [level: 1, 2, 3] [engine: jinja2|twig|spel]")
            return

        vtype = args[0].lower()
        payload_cmd = args[1]
        level = int(args[2]) if len(args) > 2 and args[2].isdigit() else 2
        engine = args[3] if len(args) > 3 else "jinja2"

        print_header(f"WAF Bypass & Mutation Core: {vtype.upper()}", f"Level {level} Aggression")
        mutations = BypassEngine.mutate_payload(vtype, payload_cmd, level=level, engine=engine)

        if not mutations:
            print_warning("No mutations generated for given input.")
            return

        for m in mutations:
            print_payload(m["name"], m["payload"], m.get("desc", ""))

    # ─── CONTAINER & SANDBOX ESCAPE ────────────────────────────────────
    def do_escape(self, arg):
        """Container & Sandbox Escape / PrivEsc Generator: escape <cgroup|docker|suid|recon> [arg]"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: escape <cgroup|docker|suid|recon> [binary/command]")
            return

        mode = args[0].lower()
        if mode == "cgroup":
            cmd_str = " ".join(args[1:]) if len(args) > 1 else "cat /root/flag* > /tmp/host_flag.txt"
            print_header("cgroup v1 release_agent Container Escape Script (CAP_SYS_ADMIN)", f"Host Cmd: {cmd_str}")
            script = ContainerEscapeAdvisor.generate_cgroup_escape_script(cmd=cmd_str)
            print_code(script, "bash", "cgroup_escape.sh")
        elif mode in ["docker", "sock"]:
            cmd_str = " ".join(args[1:]) if len(args) > 1 else "cat /root/flag*"
            print_header("Docker Socket Mount Escape & Host Takeover (/var/run/docker.sock)")
            res = ContainerEscapeAdvisor.generate_docker_socket_exploit(flag_cmd=cmd_str)
            for k, v in res.items():
                print_payload(k, v)
        elif mode == "suid":
            bname = args[1] if len(args) > 1 else "find"
            exploit = ContainerEscapeAdvisor.audit_suid_binary(bname)
            if exploit:
                print_header(f"GTFOBins SUID Privilege Escalation: {bname}")
                print_payload(f"SUID Exploit ({bname})", exploit)
            else:
                print_warning(f"No specific SUID GTFOBin recorded for '{bname}'. Try find, bash, cp, vim, env, python, etc.")
        elif mode == "recon":
            print_header("Container Detection & Reconnaissance Commands")
            for c in ContainerEscapeAdvisor.get_recon_commands():
                print_payload(c["name"], c["cmd"])
        else:
            print_error(f"Unknown escape mode: {mode}. Available: cgroup, docker, suid, recon")

    # ─── VULNERABILITY CHAINING ────────────────────────────────────────
    def do_chain(self, arg):
        """Multi-Stage Vulnerability Chaining Advisor: chain <ssrf|lfi> <target_url> [param]"""
        args = shlex.split(arg) if arg else []
        if len(args) < 2:
            print_warning("Usage: chain ssrf <target_url> [param] | chain lfi <source_file_path>")
            return

        mode = args[0].lower()
        target = args[1]

        if mode == "ssrf":
            param = args[2] if len(args) > 2 else "url"
            print_header("Multi-Hop Cloud & Internal SSRF Extraction Chains", f"Target: {target} (Param: {param})")
            chains = VulnerabilityChainEngine.generate_ssrf_cloud_chains(target, param)
            for c in chains:
                print_payload(c["Target"], c["Probe URL"], c["Description"])
        elif mode == "lfi":
            if os.path.exists(target):
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                print_header("Analyzing Leaked Source Code for Secondary Exploit Chains", f"File: {target}")
                chains = VulnerabilityChainEngine.analyze_lfi_source_leak_for_chains("http://target.ctf", "file", {os.path.basename(target): content})
                if chains:
                    for ch in chains:
                        print_success(f"Discovered Chain: {ch['chain_name']} ({ch['impact']})")
                        print_info(f"  Action: {ch['action']}")
                        for r in ch["recipe"]:
                            print_info(f"    {r}")
                else:
                    print_info("No obvious hardcoded secrets or deserialization sinks found in file.")
            else:
                print_error(f"Source file not found: {target}")
        else:
            print_error(f"Unknown chaining mode: {mode}. Available: ssrf, lfi")


    # ─── JWT LABORATORY ───────────────────────────────────────────────
    def do_jwt(self, arg):
        """JWT Security & Exploit Toolkit: jwt <decode|none|brute|sign> [args]"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: jwt decode <token> | jwt none <token> | jwt brute <token> | jwt sign <payload_json> <secret>")
            return
            
        sub = args[0].lower()
        if sub == "decode":
            token = args[1] if len(args) > 1 else ""
            if not token:
                print_warning("Usage: jwt decode <token>")
                return
            res = decode_jwt(token)
            if "error" in res:
                print_error(res["error"])
                return
            print_header("JWT Decoded Tokens")
            print_code(json.dumps(res["header"], indent=2), "json", "Header")
            print_code(json.dumps(res["payload"], indent=2), "json", "Payload")
            print_info(f"Signature: {res['signature']}")
            
        elif sub == "none":
            token = args[1] if len(args) > 1 else ""
            if not token:
                print_warning("Usage: jwt none <token_or_payload_json>")
                return
            # If full token, extract payload
            if "." in token:
                decoded = decode_jwt(token)
                payload = decoded.get("payload", {})
            else:
                try:
                    payload = json.loads(token)
                except Exception:
                    payload = {"user": "admin", "role": "admin", "isAdmin": True}
                    
            forged = forge_alg_none(payload)
            print_header("JWT alg:none Forged Token")
            print_payload("Forged Token (No Signature)", forged, "Header: {'alg':'none'}, Signature: ''")
            
        elif sub == "brute":
            token = args[1] if len(args) > 1 else ""
            if not token:
                print_warning("Usage: jwt brute <token>")
                return
            print_info("Starting dictionary attack with common CTF secret words...")
            secret = bruteforce_secret(token)
            if secret:
                print_success(f"CRACKED! JWT Secret Key: [bold yellow]{secret}[/bold yellow]")
            else:
                print_warning("Secret key not found in default wordlist.")
                
        elif sub == "sign":
            if len(args) < 3:
                print_warning("Usage: jwt sign <payload_json> <secret>")
                return
            try:
                payload = json.loads(args[1])
                secret = args[2]
                signed = sign_jwt_hs256({}, payload, secret)
                print_success("JWT Signed Successfully!")
                print_payload("HS256 Signed Token", signed)
            except Exception as e:
                print_error(f"Error signing JWT: {e}")

    # ─── BLIND EXFILTRATION ────────────────────────────────────────────
    def do_blind(self, arg):
        """Blind SQLi/SSTI Automation & Script Generator: blind <script|run> [args]"""
        args = shlex.split(arg) if arg else []
        if not args:
            print_warning("Usage: blind script <boolean|time> <url> [param] [needle/sleep]  OR  blind run <url> <param> <needle> <query>")
            return
            
        action = args[0].lower()
        if action == "script":
            stype = args[1].lower() if len(args) > 1 else "boolean"
            url = args[2] if len(args) > 2 else "http://target.ctf/page.php"
            param = args[3] if len(args) > 3 else "id"
            
            if stype == "time":
                sleep_s = int(args[4]) if len(args) > 4 else 3
                script = generate_time_blind_script(url, "GET", param, sleep_s)
                print_code(script, "python", "Generated Time-Based Blind Solver")
            else:
                needle = args[4] if len(args) > 4 else "Welcome"
                script = generate_boolean_blind_script(url, "GET", param, needle)
                print_code(script, "python", "Generated Boolean Blind Solver")
                
        elif action == "run":
            if len(args) < 5:
                print_warning("Usage: blind run <url> <param> <needle> <query>")
                return
            url, param, needle, query = args[1], args[2], args[3], args[4]
            live_boolean_exfiltrate(url, "GET", param, needle, query)
            
        else:
            print_warning("Unknown action. Available: blind script, blind run")

    # ─── RECON & QUICK SCANNER ────────────────────────────────────────
    def do_scan(self, arg):
        """Quick CTF Endpoint Recon & Flag Finder: scan <url>"""
        if not arg:
            print_warning("Usage: scan <url>")
            return
        url = arg.strip()
        hits = scan_target(url)
        if hits:
            rows = [[h["status"], h["length"], h["path"], h["url"]] for h in hits]
            print_table(["Status", "Length", "Path", "Full URL"], rows, title=f"Recon Hits for {url}")
        else:
            print_info("No standard sensitive paths responded with 200/301.")

    # ─── FLAG SCRAPER ──────────────────────────────────────────────────
    def do_flag(self, arg):
        """Scan text for flags using regex: flag <text_or_paste>"""
        if not arg:
            print_warning("Usage: flag <text_to_search>")
            return
        flags = find_flags(arg)
        if flags:
            for f in flags:
                print_flag(f)
        else:
            print_info("No flag patterns detected in text.")

    # ─── CHEATSHEET & CODE ANALYZER ────────────────────────────────────
    def do_cheat(self, arg):
        """CTF Cheatsheets & Tricks: cheat <quirks|upload>"""
        target = arg.strip().lower() if arg else "quirks"
        if target == "quirks":
            print_header("PHP Loose Comparison & Quirks Matrix")
            rows = [[q["Expression"], q["Result"], q["Explanation"]] for q in PHP_QUIRKS]
            print_table(["Expression", "Result", "Technical Reason"], rows, title="PHP Loose Comparisons")
        elif target == "upload":
            print_header("File Upload Filter Bypass Techniques")
            rows = [[u["Technique"], u["Payload/Tip"]] for u in FILE_UPLOAD_TRICKS]
            print_table(["Technique", "Payload / Method"], rows, title="File Upload Bypasses")
        else:
            print_warning("Available cheatsheets: cheat quirks, cheat upload")

    def do_analyze(self, arg):
        """Scan source code snippet for dangerous vulnerability sinks: analyze <code_or_file> [language]"""
        if not arg:
            print_warning("Usage: analyze <file_path_or_snippet> [php|python|javascript]")
            return
            
        arg_clean = arg.strip()
        lang = "all"
        code_content = arg_clean
        
        # Check if last word is a known language
        words = arg_clean.rsplit(maxsplit=1)
        if len(words) == 2 and words[1].lower() in ["php", "python", "javascript", "js", "py"]:
            lang = words[1].lower()
            code_content = words[0].strip()
            
        # Check if file path
        if os.path.isfile(code_content):
            try:
                fname = code_content
                with open(fname, "r", encoding="utf-8", errors="ignore") as f:
                    code_content = f.read()
                print_info(f"Loaded {len(code_content)} chars from file: {fname}")
                if lang == "all":
                    if fname.endswith(".php"): lang = "php"
                    elif fname.endswith(".py"): lang = "python"
                    elif fname.endswith(".js"): lang = "javascript"
            except Exception as e:
                print_error(f"Could not read file: {e}")
                return

        findings = analyze_code_snippet(code_content, lang)
        if findings:
            print_header("Code Vulnerability Findings", f"Total Sinks Detected: {len(findings)}")
            rows = [[f["line"], f["matched"], f["description"]] for f in findings]
            print_table(["Line", "Matched Sink", "Vulnerability Impact"], rows, title="Detected Sinks")
        else:
            print_info("No known dangerous sink patterns found in snippet.")

    def do_autopwn(self, arg):
        """Autonomous 7-Phase CTF Exploit Pipeline: autopwn <target_url> [--step] [--prefix PREFIX]"""
        if not arg:
            print_warning("Usage: autopwn <target_url> [--step] [--prefix PREFIX]")
            return
            
        args = shlex.split(arg)
        url = args[0]
        step_mode = "--step" in args
        prefix = None
        if "--prefix" in args:
            idx = args.index("--prefix")
            if idx + 1 < len(args):
                prefix = args[idx + 1]

        pipeline = AutoPwnPipeline(url, step_by_step=step_mode, custom_flag_prefix=prefix)
        pipeline.run()

    def do_memory(self, arg):
        """Persistent Memory & Learning Engine: memory [stats|loot|sessions|reset]"""
        action = arg.strip().lower() if arg else "stats"
        le = LearningEngine()

        if action == "stats":
            stats = le.get_stats()
            s = stats["stats"]
            print_header("Adaptive Learning Memory Stats", f"Last Update: {s.get('last_learning_update') or 'Never'}")
            print_info(f"Total Solved Challenges: [bold green]{s.get('total_solved_challenges', 0)}[/bold green]")
            print_info(f"Total Flags Captured:    [bold yellow]{s.get('total_captured_flags', 0)}[/bold yellow]")
            print_info(f"Successful Exploits:     [bold cyan]{s.get('successful_exploits', 0)}[/bold cyan]")
            print_info(f"Learned Technologies:    [bold magenta]{stats.get('learned_technologies_count', 0)}[/bold magenta]")
            print_info(f"Weighted Payloads:       [bold white]{stats.get('learned_payloads_count', 0)}[/bold white]")

            top = stats.get("top_payloads", [])
            if top:
                rows = [[p.get("vuln_type", ""), p.get("name", ""), str(p.get("weight", 1)), str(p.get("success_count", 1))] for p in top]
                print_table(["Vulnerability", "Payload Name", "Weight", "Successes"], rows, title="Top Weighted Winning Payloads")

        elif action == "loot":
            all_loot = LootManager.list_all_loot()
            print_header("Stored Challenge Loot & Exfiltrated Data", f"Total Targets: {len(all_loot)}")
            if all_loot:
                rows = [[item["target_id"], str(item["flags_captured"]), str(item["source_files_leaked"]), "Yes" if item["has_exploit"] else "No"] for item in all_loot]
                print_table(["Target ID", "Flags", "Source Files", "Exploit Script"], rows, title="Challenge Loot")
            else:
                print_info("No loot stored yet. Run 'autopwn <url>' on a target challenge.")

        elif action == "sessions":
            sessions = SessionStorage.list_sessions()
            print_header("Saved CTF Target Sessions", f"Total Sessions: {len(sessions)}")
            if sessions:
                rows = [[s["url"], str(s["flags"]), str(s["endpoints"]), s["updated_at"]] for s in sessions]
                print_table(["Target URL", "Flags", "Endpoints", "Last Updated"], rows, title="Saved Sessions")
            else:
                print_info("No saved sessions.")

        elif action == "reset":
            le.reset_memory()
            print_success("Learning database reset to default state.")
        else:
            print_warning("Usage: memory [stats|loot|sessions|reset]")

    def do_response(self, arg):
        """Semantic diagnosis for server output/errors: response <text_or_file>"""
        if not arg:
            print_warning("Usage: response <raw_error_text_or_filepath>")
            return
            
        content = arg.strip()
        if os.path.isfile(content):
            try:
                with open(content, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print_error(f"Failed to read file: {e}")
                return

        diag = ResponseAnalyzer.analyze_response(content)
        print_header("Semantic Response & Error Diagnostics", f"Identified Errors: {len(diag['db_errors']) + len(diag['ssti_errors']) + len(diag['lfi_errors']) + len(diag['waf_detected'])}")
        summary = ResponseAnalyzer.format_diagnostic_summary(diag)
        if summary:
            console.print(summary)
        else:
            print_info("No known database/SSTI/LFI error signatures or stack traces detected in output.")


def run_cli_arguments():
    """Handle direct terminal command execution (non-interactive)."""
    parser = argparse.ArgumentParser(
        prog="webctf",
        description="Ultimate Web CTF Toolkit & Exploit Assistant (CLI Edition)"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Module to execute")

    # AutoPwn
    p_auto = subparsers.add_parser("autopwn", help="7-Phase Autonomous CTF Exploit Pipeline")
    p_auto.add_argument("url", help="Challenge target URL")
    p_auto.add_argument("--step", action="store_true", help="Guided step-by-step mode")
    p_auto.add_argument("--prefix", dest="flag_prefix", help="Custom flag prefix (e.g. picoCTF)")

    # Memory
    p_mem = subparsers.add_parser("memory", help="Persistent Memory & Learning Engine stats")
    p_mem.add_argument("action", choices=["stats", "loot", "sessions", "reset"], nargs="?", default="stats", help="Memory action")

    # Encode
    p_enc = subparsers.add_parser("encode", help="Encode text across all formats")
    p_enc.add_argument("text", help="Text to encode")

    # Decode
    p_dec = subparsers.add_parser("decode", help="Decode text across formats")
    p_dec.add_argument("text", help="Text to decode")
    p_dec.add_argument("--auto", action="store_true", help="Auto multi-layer decode")

    # Magic Hashes
    p_magic = subparsers.add_parser("magic", help="PHP Magic Hashes database")
    p_magic.add_argument("algo", nargs="?", default="ALL", help="Algorithm (MD5, SHA1, SHA256)")

    # SSTI
    p_ssti = subparsers.add_parser("ssti", help="Generate SSTI payloads")
    p_ssti.add_argument("engine", choices=["jinja2", "twig", "smarty", "mako", "freemarker", "spel", "tree"], help="Template engine")
    p_ssti.add_argument("--cmd", default="id", help="Command to execute")

    # Cmd
    p_cmd = subparsers.add_parser("cmd", help="Command injection & reverse shell")
    p_cmd.add_argument("action", choices=["bypass", "rev"], help="Action (bypass or rev)")
    p_cmd.add_argument("args", nargs="*", help="Command string or IP PORT")

    # SQLi
    p_sqli = subparsers.add_parser("sqli", help="SQLi payloads and cheatsheets")
    p_sqli.add_argument("dbms", choices=["mysql", "sqlite", "postgres", "mssql", "oracle", "auth"], help="Target DBMS")

    # LFI
    p_lfi = subparsers.add_parser("lfi", help="LFI & PHP Wrappers")
    p_lfi.add_argument("action", choices=["wrappers", "traversal", "poison"], help="LFI Action")
    p_lfi.add_argument("target", nargs="?", default="index.php", help="Target filename or path")

    # SSRF
    p_ssrf = subparsers.add_parser("ssrf", help="SSRF IP Obfuscator & Cloud Endpoints")
    p_ssrf.add_argument("target", help="IP address or 'cloud'")

    # XXE
    p_xxe = subparsers.add_parser("xxe", help="XXE injection payloads")
    p_xxe.add_argument("target_file", nargs="?", default="/etc/passwd", help="Target file")
    p_xxe.add_argument("attacker_url", nargs="?", default="http://attacker.com", help="Attacker URL")

    # XSS
    p_xss = subparsers.add_parser("xss", help="XSS & Prototype Pollution payloads")

    # Deserialization
    p_deser = subparsers.add_parser("deser", help="Deserialization RCE payloads")
    p_deser.add_argument("target", choices=["pickle", "node", "yaml", "php", "java"], help="Target platform")
    p_deser.add_argument("cmd", nargs="?", default="id", help="Command to execute")

    # WAF Bypass & Mutation
    p_byp = subparsers.add_parser("bypass", help="WAF Bypass & dynamic payload mutation engine")
    p_byp.add_argument("vuln_type", choices=["sqli", "cmd", "ssti", "lfi"], help="Vulnerability class")
    p_byp.add_argument("payload", help="Base payload or command string")
    p_byp.add_argument("--level", type=int, choices=[1, 2, 3], default=2, help="Mutation aggression level (1-3)")
    p_byp.add_argument("--engine", default="jinja2", help="Template engine (for SSTI, e.g. jinja2, twig, spel)")

    # Container & Sandbox Escape
    p_esc = subparsers.add_parser("escape", help="Container/sandbox detection and privilege escalation generator")
    p_esc.add_argument("mode", choices=["cgroup", "docker", "suid", "recon"], help="Escape vector / technique")
    p_esc.add_argument("arg", nargs="?", default="", help="Command or binary name")

    # Vulnerability Chaining
    p_chn = subparsers.add_parser("chain", help="Multi-stage vulnerability chaining advisor")
    p_chn.add_argument("mode", choices=["ssrf", "lfi"], help="Chaining mode")
    p_chn.add_argument("target", help="Target URL or source file path")
    p_chn.add_argument("param", nargs="?", default="url", help="Parameter name")

    # JWT
    p_jwt = subparsers.add_parser("jwt", help="JWT tools")
    p_jwt.add_argument("action", choices=["decode", "none", "brute", "sign"], help="JWT action")
    p_jwt.add_argument("token", help="JWT token string or payload JSON")
    p_jwt.add_argument("secret", nargs="?", default="", help="Secret key for signing")

    # Blind
    p_blind = subparsers.add_parser("blind", help="Blind SQLi/SSTI solver script generator")
    p_blind.add_argument("action", choices=["script", "run"], help="Action (script or run)")
    p_blind.add_argument("args", nargs="*", help="Script arguments")

    # Scan
    p_scan = subparsers.add_parser("scan", help="Quick CTF target scanner")
    p_scan.add_argument("url", help="Target URL")

    # Flag
    p_flag = subparsers.add_parser("flag", help="Extract flag from text")
    p_flag.add_argument("text", help="Text to search")

    # Cheat
    p_cheat = subparsers.add_parser("cheat", help="CTF Cheatsheets")
    p_cheat.add_argument("topic", choices=["quirks", "upload"], help="Cheatsheet topic")

    # Analyze
    p_ana = subparsers.add_parser("analyze", help="Scan code snippet/file for vulnerability sinks")
    p_ana.add_argument("file_or_code", help="File path or code string")
    p_ana.add_argument("language", nargs="?", default="php", help="Language (php, python, javascript)")

    # Response Diagnostic
    p_resp = subparsers.add_parser("response", help="Semantic analysis of HTTP response, stacktrace, or server error")
    p_resp.add_argument("content", help="Raw response text or file path")

    if len(sys.argv) == 1:
        # Launch interactive shell
        print_banner()
        shell = WebCTFShell()
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted. Exiting WebCTF.[/bold red]")
    else:
        args = parser.parse_args()
        shell = WebCTFShell()
        
        if args.subcommand == "autopwn":
            prefix_arg = f" --prefix {args.flag_prefix}" if args.flag_prefix else ""
            step_arg = " --step" if args.step else ""
            shell.do_autopwn(f"{args.url}{step_arg}{prefix_arg}")
        elif args.subcommand == "response":
            shell.do_response(args.content)
        elif args.subcommand == "memory":
            shell.do_memory(args.action)
        elif args.subcommand == "bypass":
            shell.do_bypass(f"{args.vuln_type} \"{args.payload}\" {args.level} {args.engine}")
        elif args.subcommand == "escape":
            shell.do_escape(f"{args.mode} {args.arg}")
        elif args.subcommand == "chain":
            shell.do_chain(f"{args.mode} {args.target} {args.param}")
        elif args.subcommand == "encode":
            shell.do_encode(args.text)
        elif args.subcommand == "decode":
            if args.auto:
                shell.do_decode(f"auto {args.text}")
            else:
                shell.do_decode(args.text)
        elif args.subcommand == "magic":
            shell.do_magic(args.algo)
        elif args.subcommand == "ssti":
            if args.engine == "tree":
                shell.do_ssti("tree")
            else:
                shell.do_ssti(f"{args.engine} \"{args.cmd}\"")
        elif args.subcommand == "cmd":
            shell.do_cmd(f"{args.action} {' '.join(args.args)}")
        elif args.subcommand == "sqli":
            shell.do_sqli(args.dbms)
        elif args.subcommand == "lfi":
            shell.do_lfi(f"{args.action} {args.target}")
        elif args.subcommand == "ssrf":
            shell.do_ssrf(args.target)
        elif args.subcommand == "xxe":
            shell.do_xxe(f"{args.target_file} {args.attacker_url}")
        elif args.subcommand == "xss":
            shell.do_xss("")
        elif args.subcommand == "deser":
            shell.do_deser(f"{args.target} {args.cmd}")
        elif args.subcommand == "jwt":
            if args.action == "sign":
                shell.do_jwt(f"sign {args.token} {args.secret}")
            else:
                shell.do_jwt(f"{args.action} {args.token}")
        elif args.subcommand == "blind":
            shell.do_blind(f"{args.action} {' '.join(args.args)}")
        elif args.subcommand == "scan":
            shell.do_scan(args.url)
        elif args.subcommand == "flag":
            shell.do_flag(args.text)
        elif args.subcommand == "cheat":
            shell.do_cheat(args.topic)
        elif args.subcommand == "analyze":
            shell.do_analyze(f"{args.file_or_code} {args.language}")
        else:
            parser.print_help()


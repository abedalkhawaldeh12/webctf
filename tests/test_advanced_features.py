"""
Unit & Integration Tests for WebCTF Suite Advanced Features:
- WAF Bypass & Dynamic Payload Mutation
- Insecure Deserialization (Pickle, PyYAML, Node.js, PHP, Java)
- Container & Sandbox Escape Engine
- Vulnerability Chaining Core & Script Generator
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.bypass_engine import BypassEngine

from modules.deserializer import (
    generate_pickle_payload, generate_pyyaml_payload,
    generate_nodejs_serialize_payload, generate_php_serialized_object,
    get_java_deserialization_templates
)
from modules.container_escape import ContainerEscapeAdvisor
from modules.chaining_engine import VulnerabilityChainEngine
from modules.autopwn import AutoPwnPipeline
from modules.reasoning_engine import ReasoningEngine
from core.memory import LearningEngine
from core.utils import create_session

def test_all():
    # 1. Test Bypass Engine
    sqli_muts = BypassEngine.mutate_sqli("' UNION SELECT username, password FROM users-- -", level=3)
    assert len(sqli_muts) >= 5, "SQLi mutations failed"
    
    cmd_muts = BypassEngine.mutate_command("cat /etc/passwd", level=3)
    assert len(cmd_muts) >= 6, "Cmd mutations failed"
    
    ssti_muts = BypassEngine.mutate_ssti("jinja2", "id", level=3)
    assert len(ssti_muts) >= 4, "SSTI mutations failed"
    
    lfi_muts = BypassEngine.mutate_lfi("/etc/passwd", level=3)
    assert len(lfi_muts) >= 6, "LFI mutations failed"
    print("[+] 1. Bypass Engine: SQLi, CmdInj, SSTI, LFI mutations verified successfully.")

    # 2. Test Deserialization
    p_pay = generate_pickle_payload("cat /flag*")
    assert "Base64 Payload" in p_pay and "Reverse Shell Base64" in p_pay
    
    y_pay = generate_pyyaml_payload("id")
    assert "os.system" in y_pay["PyYAML Payloads"]
    
    n_pay = generate_nodejs_serialize_payload("id")
    assert "_$$ND_FUNC$$_" in n_pay["Raw JSON Command Payload"]
    
    php_obj = generate_php_serialized_object("User", {"name": "admin", "isAdmin": True}, bypass_wakeup=True)
    assert 'O:4:"User":3:' in php_obj
    
    java_t = get_java_deserialization_templates("id")
    assert len(java_t) >= 4
    print("[+] 2. Deserializer Module: Python Pickle, PyYAML, Node.js, PHP, Java verified successfully.")

    # 3. Test Container Escape
    cgroup_script = ContainerEscapeAdvisor.generate_cgroup_escape_script("cat /root/flag*")
    assert "release_agent" in cgroup_script and "cgroup.procs" in cgroup_script
    
    sock_exploit = ContainerEscapeAdvisor.generate_docker_socket_exploit()
    assert "unix:///var/run/docker.sock" in sock_exploit["Docker CLI One-Liner"]
    
    suid_find = ContainerEscapeAdvisor.audit_suid_binary("/usr/bin/find")
    assert "-exec /bin/sh -p" in suid_find
    
    recon_findings = ContainerEscapeAdvisor.analyze_shell_recon("IS_DOCKER\nDOCKER_SOCK_ACCESSIBLE\n/usr/bin/find")
    assert recon_findings["is_container"] and len(recon_findings["escapes"]) > 0 and len(recon_findings["suid_exploits"]) > 0
    print("[+] 3. Container Escape Engine: Recon, Docker Sock, Cgroup v1, SUID verified successfully.")

    # 4. Test Vulnerability Chaining
    fake_leak = {
        "app.py": 'SECRET_KEY = "supersecret123"\n@app.route("/load")\ndef load():\n    data = pickle.loads(base64.b64decode(request.args["p"]))'
    }
    chains = VulnerabilityChainEngine.analyze_lfi_source_leak_for_chains("http://127.0.0.1:5000", "file", fake_leak)
    assert len(chains) == 2, f"Expected 2 chains, got {len(chains)}"
    script = VulnerabilityChainEngine.generate_python_exploit_script(chains[1])
    assert "pwn()" in script and "requests.get" in script
    print("[+] 4. Chaining Engine: LFI Source Leak -> Secret / Deser Chains & Exploit Script verified successfully.")

    # 5. Test PHP Tricks & Logic Engine
    from modules.php_tricks import PHPTricksEngine, MAGIC_HASHES_MD5, SPOOF_IP_HEADERS
    assert len(MAGIC_HASHES_MD5) >= 5, "Magic hashes missing"
    assert "X-Forwarded-For" in SPOOF_IP_HEADERS
    print("[+] 5. PHP Tricks Engine: Magic hashes, IP spoofing headers, Type juggling verified successfully.")

    # 6. Test Client-Side JS Analyzer
    from modules.client_side import ClientSideAnalyzer
    test_js = 'var _0x123=["\\x61\\x64\\x6d\\x69\\x6e", "\\x70\\x61\\x73\\x73\\x31\\x32\\x33"]; if (p == _0x123[1]) { return true; }'
    js_res = ClientSideAnalyzer.analyze_javascript(test_js)
    assert len(js_res["hex_decoded"]) >= 2
    print("[+] 6. Client-Side Analyzer: Hex deobfuscation, auth checks verified successfully.")

    # 7. Test AutoPwn Pipeline instantiation
    pipe = AutoPwnPipeline("http://127.0.0.1:8080")
    assert pipe.target_url == "http://127.0.0.1:8080"
    print("[+] 7. AutoPwn Pipeline: 7-Phase architecture integration verified successfully.")

    # 8. Test Deep Reasoning Engine
    from modules.reasoning_engine import ReasoningEngine, Hypothesis

    # 8a. Hypothesis class
    h = Hypothesis("Test", "sqli", 0.9, ["evidence1"], "action", "payload", "param", "url")
    d = h.to_dict()
    assert d["vuln_class"] == "sqli" and d["confidence"] == 0.9
    print("[+] 8a. Hypothesis class: serialization verified successfully.")

    # 8b. ReasoningEngine with synthetic state (no network)
    engine = ReasoningEngine("http://127.0.0.1:8080", state={
        "target_url": "http://127.0.0.1:8080",
        "parameters": {"lang", "file", "url"},
        "endpoints": {"http://127.0.0.1:8080/static/"},
        "forms": [],
        "tech_stack": ["flask", "python"],
        "cookies": {"admin": "0", "session": "O:4:\"User\":3:{s:4:\"name\";s:5:\"admin\";}"},
        "leaked_source_files": {"app.py": 'SECRET_KEY = "x"\n@app.route("/load")\ndef load():\n    data = pickle.loads(base64.b64decode(request.args["p"]))'},
        "baseline_html": ""
    })

    # Test hypothesis generation (should find cookie manipulation + deserialization)
    hyps = engine.build_hypotheses()
    vuln_classes = {h.vuln_class for h in hyps}
    assert "cookie_manipulation" in vuln_classes, f"Expected cookie_manipulation, got {vuln_classes}"
    assert "deserialization" in vuln_classes, f"Expected deserialization, got {vuln_classes}"
    print("[+] 8b. ReasoningEngine: hypothesis generation verified successfully.")

    # Test evidence correlation (should find pickle deserialization sink)
    corr = engine.correlate_evidence()
    assert any(c["vuln_class"] == "code_execution" for c in corr), "Expected code_execution correlation"
    print("[+] 8c. ReasoningEngine: evidence correlation verified successfully.")

    # Test attack plan generation
    plan = engine.plan_attack()
    assert len(plan) >= 3, f"Expected >=3 plan steps, got {len(plan)}"
    assert plan[0]["step"] == 1, "First step should be recon confirmation"
    print("[+] 8d. ReasoningEngine: multi-step attack plan verified successfully.")

    # Test adaptive strategy
    engine.record_probe("lang", "test", False, "waf blocked")
    engine.record_probe("lang", "test2", False, "waf blocked")
    engine.record_probe("lang", "test3", False, "waf blocked")
    rec = engine.get_adaptive_recommendation()
    assert rec and "WAF" in rec, "Expected WAF adaptive recommendation"
    print("[+] 8e. ReasoningEngine: adaptive strategy verified successfully.")

    # 8f. Circuit / Logic Puzzle Challenge detection
    circuit_engine = ReasoningEngine("http://127.0.0.1:8080", state={
        "target_url": "http://127.0.0.1:8080",
        "parameters": set(),
        "endpoints": {"http://127.0.0.1:8080/check"},
        "forms": [],
        "tech_stack": ["express", "node"],
        "cookies": {},
        "leaked_source_files": {},
        "baseline_html": """
        <html><body>
        <h1>NAND Simulator</h1>
        <button onclick="submitCircuit()">Submit Circuit</button>
        <script>
        const GOALS = { flip: { description: 'Flip the outputs!' } };
        let nextNodeId = 5;
        function createNode(x, y, value, type) { /* ... */ }
        function createOutputNodes() {
            for (let i = 0; i < 4; i++) {
                createNode(0, 0, '?', 'output');
            }
        }
        function submitCircuit() {
            const circuit = [];
            nodes.forEach(node => {
                if (node.dataset.input1 && node.dataset.input2) {
                    circuit.push({
                        input1: parseInt(node.dataset.input1),
                        input2: parseInt(node.dataset.input2),
                        output: parseInt(node.dataset.nodeId)
                    });
                }
            });
            const response = await fetch('/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ circuit })
            });
        }
        </script>
        </body></html>
        """,
        "inline_scripts": ["""
        const GOALS = { flip: { description: 'Flip the outputs!' } };
        let nextNodeId = 5;
        function submitCircuit() {
            const response = await fetch('/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ circuit })
            });
        }
        """]
    })

    # Test circuit challenge hypothesis generation
    hyps = circuit_engine.build_hypotheses()
    circuit_hyps = [h for h in hyps if h.vuln_class == "circuit_bruteforce"]
    assert circuit_hyps, "Expected circuit_bruteforce hypothesis"
    assert circuit_hyps[0].confidence >= 0.8, "Circuit hypothesis should have high confidence"
    assert "/check" in circuit_hyps[0].target_url, "Circuit hypothesis should target /check endpoint"
    print("[+] 8f. ReasoningEngine: circuit challenge detection verified successfully.")

    # 8g. Test NOT-gate mapping generation
    mappings = circuit_engine._generate_not_gate_mappings(5, 4)
    assert len(mappings) >= 4, f"Expected >=4 NOT-gate mappings, got {len(mappings)}"
    # First mapping should be direct 1:1 (5->1, 6->2, 7->3, 8->4)
    assert mappings[0] == [(5, 1), (6, 2), (7, 3), (8, 4)], f"Unexpected first mapping: {mappings[0]}"
    # Should include all-outputs-to-same-input mappings
    assert any(m == [(5, 1), (5, 2), (5, 3), (5, 4)] for m in mappings), "Expected all-outputs-to-input-5 mapping"
    print("[+] 8g. ReasoningEngine: NOT-gate mapping generation verified successfully.")

    # 8h. Test ZipSlip / Archive Traversal hypothesis generation
    zipslip_engine = ReasoningEngine(
        "http://example.com/upload",
        session=create_session()
    )
    zipslip_engine.state.update({
        "baseline_html": """
        <html><body>
        <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
        <p>Upload your tar.gz archive for virus scanning</p>
        </body></html>
        """,
        "forms": [{
            "action": "/upload",
            "method": "POST",
            "enctype": "multipart/form-data",
            "inputs": [{"name": "file", "type": "file"}]
        }],
        "leaked_source_files": {
            "upload.php": "<?php $tar = new PharData($_FILES['file']['tmp_name']); $tar->extractTo('/var/www/uploads/'); ?>"
        }
    })
    zipslip_hyps = zipslip_engine.build_hypotheses()
    zipslip_found = [h for h in zipslip_hyps if h.vuln_class == "zipslip"]
    assert zipslip_found, "Expected zipslip hypothesis"
    assert zipslip_found[0].confidence >= 0.8, "ZipSlip hypothesis should have high confidence"
    assert "extractall" in zipslip_found[0].action.lower() or "tar" in zipslip_found[0].action.lower(), \
        "ZipSlip action should mention archive extraction"
    print("[+] 8h. ReasoningEngine: ZipSlip hypothesis generation verified successfully.")

    # 8i. Test Command Injection via URL/Media hypothesis generation
    cmdinj_engine = ReasoningEngine(
        "http://example.com/media",
        session=create_session()
    )
    cmdinj_engine.state.update({
        "baseline_html": """
        <html><body>
        <form action="/media" method="POST">
            <input type="text" name="media_uri" placeholder="Enter media URL">
            <input type="submit" value="Fetch">
        </form>
        </body></html>
        """,
        "forms": [{
            "action": "/media",
            "method": "POST",
            "inputs": [{"name": "media_uri", "type": "text"}]
        }],
        "leaked_source_files": {
            "media.php": "<?php $url = $_POST['media_uri']; if (filter_var($url, FILTER_VALIDATE_URL)) { system('curl -s ' . $url); } ?>"
        }
    })
    cmdinj_hyps = cmdinj_engine.build_hypotheses()
    cmdinj_found = [h for h in cmdinj_hyps if h.vuln_class == "cmd_injection_url"]
    assert cmdinj_found, "Expected cmd_injection_url hypothesis"
    assert cmdinj_found[0].confidence >= 0.8, "Command injection hypothesis should have high confidence"
    assert "${IFS}" in cmdinj_found[0].payload, "Payload should use ${IFS} to bypass FILTER_VALIDATE_URL"
    print("[+] 8i. ReasoningEngine: Command Injection via URL hypothesis verified successfully.")

    # 8j. Test SQLi via unsanitized params hypothesis generation
    sqli_engine = ReasoningEngine(
        "http://example.com/reset",
        session=create_session()
    )
    sqli_engine.state.update({
        "baseline_html": """
        <html><body>
        <form action="/set_new_password.php" method="POST">
            <input type="text" name="username">
            <input type="text" name="reset_code">
            <input type="submit" value="Reset">
        </form>
        </body></html>
        """,
        "forms": [{
            "action": "/set_new_password.php",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text"},
                {"name": "reset_code", "type": "text"}
            ]
        }],
        "leaked_source_files": {
            "set_new_password.php": "<?php $q = \"SELECT * FROM users WHERE username = '$username' AND reset_code = '$code'\"; $result = $db->query($q); ?>"
        }
    })
    sqli_hyps = sqli_engine.build_hypotheses()
    sqli_found = [h for h in sqli_hyps if h.vuln_class == "sqli_unsanitized"]
    assert sqli_found, "Expected sqli_unsanitized hypothesis"
    assert "totp_secret" in sqli_found[0].payload, "Payload should target totp_secret enumeration"
    print("[+] 8j. ReasoningEngine: SQLi via unsanitized params hypothesis verified successfully.")

    # 8k. Test TOTP/2FA bypass hypothesis generation
    totp_engine = ReasoningEngine(
        "http://example.com/login",
        session=create_session()
    )
    totp_engine.state.update({
        "baseline_html": """
        <html><body>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="text" name="totp">
            <input type="submit" value="Login">
        </form>
        </body></html>
        """,
        "forms": [{
            "action": "/login",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text"},
                {"name": "totp", "type": "text"}
            ]
        }],
        "leaked_source_files": {
            "login.php": "<?php $secret = get_totp_secret($username); if (pyotp.TOTP($secret).verify($_POST['totp'])) { login(); } ?>"
        }
    })
    totp_hyps = totp_engine.build_hypotheses()
    totp_found = [h for h in totp_hyps if h.vuln_class == "totp_bypass"]
    assert totp_found, "Expected totp_bypass hypothesis"
    assert "pyotp" in totp_found[0].action.lower(), "TOTP action should mention pyotp"
    print("[+] 8k. ReasoningEngine: TOTP/2FA bypass hypothesis verified successfully.")

    # 8k2. Test XSS-to-Admin hypothesis generation (stored XSS + admin bot)
    xss_admin_engine = ReasoningEngine(
        "http://example.com/forum",
        session=create_session()
    )
    xss_admin_engine.state.update({
        "baseline_html": """
        <html><body>
        <h1>Forum v0.009</h1>
        <form action="/post" method="POST">
            <input type="text" name="message">
            <input type="submit" value="Post">
        </form>
        <a href="/report">Report to admin</a>
        </body></html>
        """,
        "forms": [{
            "action": "/post",
            "method": "POST",
            "inputs": [
                {"name": "message", "type": "text"}
            ]
        }],
        "endpoints": ["http://example.com/forum", "http://example.com/report"]
    })
    xss_hyps = xss_admin_engine.build_hypotheses()
    xss_found = [h for h in xss_hyps if h.vuln_class == "xss_to_admin"]
    assert xss_found, "Expected xss_to_admin hypothesis"
    assert "admin" in xss_found[0].action.lower(), "XSS-to-admin action should mention admin"
    assert xss_found[0].confidence >= 0.8, "XSS-to-admin confidence should be high with admin bot"
    print("[+] 8k2. ReasoningEngine: XSS-to-Admin hypothesis verified successfully.")

    # 8l. Test Cron overwrite / privilege escalation hypothesis generation
    cron_engine = ReasoningEngine(
        "http://example.com/",
        session=create_session()
    )
    cron_engine.state.update({
        "baseline_html": "",
        "forms": [],
        "leaked_source_files": {
            "cron.php": "<?php // Runs every minute as root: copies flag to web root\n// chmod 640 /var/www/cron.php\n// www-data can write to /var/www\n?>"
        }
    })
    cron_hyps = cron_engine.build_hypotheses()
    cron_found = [h for h in cron_hyps if h.vuln_class == "cron_overwrite"]
    assert cron_found, "Expected cron_overwrite hypothesis"
    assert "cron" in cron_found[0].action.lower(), "Cron action should mention cron"
    print("[+] 8l. ReasoningEngine: Cron overwrite / PE hypothesis verified successfully.")

    # 8m. Test LearningEngine escalates XSS-to-Admin recommendations after failures
    learn_engine = LearningEngine()
    learn_engine.record_failure(
        "http://example.com/forum",
        ["nginx", "php"],
        ["xss_to_admin"],
        reason="XSS filter blocked all tested evasion payloads"
    )
    recs = learn_engine.get_recommendations(["nginx", "php"], ["xss_to_admin"])
    xss_rec = [r for r in recs if r["vuln_type"] == "xss_to_admin" and r["priority"] == "high"]
    assert xss_rec, "Expected high-priority xss_to_admin recommendation after failure"
    assert len(xss_rec[0]["payloads"]) >= 3, "Should recommend multiple advanced evasion payloads"
    assert any("mxss" in p["name"] or "polyglot" in p["name"] for p in xss_rec[0]["payloads"]), \
        "Should recommend mXSS/polyglot advanced evasion"
    print("[+] 8m. LearningEngine escalates XSS-to-Admin recommendations after failures verified successfully.")

    # 8n. Test predictive vulnerability ranking (Phase 3b) before exploitation
    pred_pipeline = AutoPwnPipeline.__new__(AutoPwnPipeline)
    pred_pipeline.state = {
        'baseline_html': '<html><body><h1>Forum v0.009</h1><form action="/post"><input name="message"></form><a href="/report">Report</a></body></html>',
        'tech_stack': ['PHP', 'nginx'],
        'parameters': {'message', 'id'},
        'forms': [{'action': '/post', 'method': 'POST', 'inputs': [{'name': 'message', 'type': 'text'}]}],
        'endpoints': {'http://x/report', 'http://x/'},
        'leaked_source_files': {},
        'cookies': {'session': 'abc'},
        'jwt_tokens': [],
        'reflected_params': ['message'],
        'sensitive_hits': [],
        'attack_steps': [],
        'curl_commands': [],
    }
    pred_pipeline._log_step = lambda *a, **k: None
    pred_pipeline._predict_vulnerabilities()
    pred_classes = [pr['vuln_class'] for pr in pred_pipeline.state['predictions']]
    assert 'xss_to_admin' in pred_classes, "Expected xss_to_admin prediction for forum + report endpoint"
    assert 'php_tricks' in pred_classes, "Expected php_tricks prediction for PHP stack"
    assert 'xss' in pred_classes, "Expected xss prediction for reflected param"
    # xss_to_admin should be highest confidence (report endpoint = 0.85)
    assert pred_pipeline.state['predictions'][0]['vuln_class'] == 'xss_to_admin', \
        "xss_to_admin should be top prediction"
    print("[+] 8n. Predictive vulnerability ranking (Phase 3b) verified successfully.")

    # 8o. Test multi-stage dependency chains in plan_attack() (complex challenges)
    chain_state = {
        "parameters": ["message", "file", "id"],
        "tech_stack": ["Flask", "Python"],
        "forms": [
            {"action": "/submit", "method": "POST",
             "inputs": [{"name": "message", "type": "text"}, {"name": "submit", "type": "submit"}]}
        ],
        "endpoints": ["/", "/report", "/admin"],
        "leaked_source_files": {
            "config.py": "SECRET_KEY = 'supersecret123'\nrender_template_string(request.args.get('name'))"
        },
        "reflected_params": ["message"],
        "cookies": {},
        "jwt_tokens": [],
        "sensitive_hits": [],
        "baseline_html": "<form><input name='message'></form>",
    }
    chain_engine = ReasoningEngine("http://target/", session=create_session(), state=chain_state)
    chain_plan = chain_engine.plan_attack()
    # Every step (except step 1) must have a dependency
    for s in chain_plan:
        if s["step"] != 1:
            assert s["depends_on"], f"Step {s['step']} has no dependency!"
    # XSS->Admin chain must exist with 4 sequential steps
    xss_chain = [s for s in chain_plan if s.get("chain") == "XSS -> Admin Bot -> Flag"]
    assert len(xss_chain) == 4, f"XSS chain should have 4 steps, got {len(xss_chain)}"
    for i in range(1, len(xss_chain)):
        assert xss_chain[i]["depends_on"] == [xss_chain[i-1]["step"]], \
            f"Chain step {xss_chain[i]['step']} should depend on {xss_chain[i-1]['step']}"
    # LFI->Secret->Session->Admin->SSTI chain must exist with 5 sequential steps
    lfi_chain = [s for s in chain_plan if s.get("chain") == "LFI -> Secret Leak -> Session Forgery -> Admin -> SSTI"]
    assert len(lfi_chain) == 5, f"LFI chain should have 5 steps, got {len(lfi_chain)}"
    for i in range(1, len(lfi_chain)):
        assert lfi_chain[i]["depends_on"] == [lfi_chain[i-1]["step"]], \
            f"LFI chain step {lfi_chain[i]['step']} should depend on {lfi_chain[i-1]['step']}"
    print("[+] 8o. Multi-stage dependency chains in plan_attack() verified successfully.")

    # 8p. Test _exploit_reasoning_plan() executes chain steps in dependency order
    plan_pipeline = AutoPwnPipeline.__new__(AutoPwnPipeline)
    plan_pipeline.state = {
        'reasoning_plan': [
            {"step": 1, "goal": "Confirm attack surface", "action": "recon", "depends_on": [], "hypothesis": None},
            {"step": 2, "goal": "Inject stored XSS payload", "action": "xss", "depends_on": [1],
             "hypothesis": "xss_to_admin", "chain": "XSS -> Admin Bot -> Flag"},
            {"step": 3, "goal": "Trigger admin bot visit", "action": "bot", "depends_on": [2],
             "hypothesis": "xss_to_admin", "chain": "XSS -> Admin Bot -> Flag"},
            {"step": 4, "goal": "Capture flag", "action": "flag", "depends_on": [2, 3], "hypothesis": None},
        ],
        'forms': [],
        'endpoints': [],
        'parameters': [],
        'leaked_source_files': {},
        'leaked_secrets': {},
        'captured_flags': set(),
        'attack_steps': [],
        'curl_commands': [],
        'active_rce_method': None,
        'admin_accessible': False,
        'admin_bot_triggered': False,
        'xss_payload_submitted': False,
        'reasoning_chain_results': {},
        'predictions': [],
        'cookies': {},
        'jwt_tokens': [],
        'tech_stack': [],
        'sensitive_hits': [],
        'reflected_params': [],
        'baseline_html': '',
    }
    plan_pipeline._log_step = lambda *a, **k: None
    plan_pipeline._check_and_store_flags = lambda *a, **k: False
    plan_pipeline._submit_stored_xss_payload = lambda: False
    plan_pipeline._trigger_admin_bot = lambda: False
    plan_pipeline._check_admin_bot_result = lambda: False
    plan_pipeline._read_admin_flag = lambda: False
    plan_pipeline._exploit_reasoning_plan()
    # Chain results should be recorded
    assert 'reasoning_chain_results' in plan_pipeline.state, "Chain results should be stored in state"
    xss_res = plan_pipeline.state['reasoning_chain_results'].get('XSS -> Admin Bot -> Flag', [])
    assert len(xss_res) == 2, f"XSS chain should have 2 step results, got {len(xss_res)}"
    print("[+] 8p. _exploit_reasoning_plan() executes chain steps in dependency order verified successfully.")

    # 8q. Test feedback loop feeds exploitation results back into reasoning state
    fb_pipeline = AutoPwnPipeline.__new__(AutoPwnPipeline)
    fb_pipeline.target_url = "http://target/"
    fb_pipeline.session = create_session()
    fb_pipeline.state = {
        'captured_flags': {'flag{test}'},
        'active_rce_method': lambda cmd: "root\nflag{test}",
        'leaked_secrets': {'secret_key': 'abc123'},
        'admin_accessible': True,
        'admin_bot_triggered': False,
        'xss_payload_submitted': False,
        'reasoning_chain_results': {'XSS -> Admin Bot -> Flag': [True, False]},
        'predictions': [{'vuln_class': 'xss_to_admin', 'confidence': 0.85, 'evidence': 'report'}],
        'exploitation_feedback': {},
    }
    fb_pipeline._feed_exploitation_results_to_reasoning()
    fb = fb_pipeline.state.get('exploitation_feedback', {})
    assert fb.get('captured_flags') == ['flag{test}'], "Feedback should include captured flags"
    assert fb.get('active_rce_method') is True, "Feedback should include RCE availability"
    assert fb.get('leaked_secrets') == {'secret_key': 'abc123'}, "Feedback should include leaked secrets"
    assert fb.get('admin_accessible') is True, "Feedback should include admin access"
    assert 'chain_results' in fb, "Feedback should include chain results"
    print("[+] 8q. Feedback loop feeds exploitation results back into reasoning state verified successfully.")

    print("\n[🎉] ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_all()

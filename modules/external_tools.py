"""
External Tools Integration Module for WebCTF Suite.
Wraps Linux/Kali pentest tools (ffuf, sqlmap, nmap, gobuster, nikto, hydra, wfuzz)
with graceful fallback to pure-Python implementations when tools are unavailable.

Usage:
    from modules.external_tools import ExternalTools
    tools = ExternalTools()
    if tools.ffuf_available:
        results = tools.run_ffuf("http://target/", "/usr/share/dirb/wordlists/common.txt")
"""

import os
import re
import json
import shutil
import subprocess
import tempfile
from typing import List, Dict, Optional, Any, Tuple

from core.ui import print_info, print_success, print_warning, print_error, print_flag
from core.utils import find_flags


class ExternalTools:
    """Wrapper around external pentest tools with Python fallbacks."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self._cache = {}

        # Detect available tools
        self.ffuf = shutil.which("ffuf")
        self.sqlmap = shutil.which("sqlmap")
        self.nmap = shutil.which("nmap")
        self.gobuster = shutil.which("gobuster")
        self.nikto = shutil.which("nikto")
        self.hydra = shutil.which("hydra")
        self.wfuzz = shutil.which("wfuzz")
        self.dirb = shutil.which("dirb")
        self.whatweb = shutil.which("whatweb")
        self.wpscan = shutil.which("wpscan")

        self.ffuf_available = self.ffuf is not None
        self.sqlmap_available = self.sqlmap is not None
        self.nmap_available = self.nmap is not None
        self.gobuster_available = self.gobuster is not None
        self.nikto_available = self.nikto is not None
        self.hydra_available = self.hydra is not None
        self.wfuzz_available = self.wfuzz is not None
        self.dirb_available = self.dirb is not None

    # ------------------------------------------------------------------
    # Generic command runner
    # ------------------------------------------------------------------
    def _run(self, cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Run a command, return (returncode, stdout, stderr)."""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                errors="ignore",
            )
            return proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return -2, "", f"Command timed out: {cmd[0]}"
        except Exception as e:
            return -3, "", str(e)

    # ------------------------------------------------------------------
    # ffuf - Fast Web Fuzzer (directory/content discovery)
    # ------------------------------------------------------------------
    def run_ffuf(
        self,
        base_url: str,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        threads: int = 40,
        max_time: int = 60,
    ) -> List[Dict[str, Any]]:
        """Run ffuf for directory/content discovery. Returns list of hits."""
        if not self.ffuf_available:
            print_warning("ffuf not available, using Python fallback...")
            return self._python_dir_scan(base_url, wordlist)

        wordlist = wordlist or self._find_wordlist([
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ])
        if not wordlist:
            print_warning("No wordlist found for ffuf, using Python fallback...")
            return self._python_dir_scan(base_url)

        cmd = [
            "ffuf",
            "-u", f"{base_url.rstrip('/')}/FUZZ",
            "-w", wordlist,
            "-t", str(threads),
            "-mc", "200,301,302,307,403",
            "-o", "/tmp/ffuf_out.json",
            "-of", "json",
            "-s",
        ]
        if extensions:
            cmd += ["-e", ",".join(extensions)]

        print_info(f"Running ffuf against [bold cyan]{base_url}[/bold cyan] with {wordlist}...")
        rc, stdout, stderr = self._run(cmd, timeout=max_time)

        results = []
        try:
            if os.path.isfile("/tmp/ffuf_out.json"):
                with open("/tmp/ffuf_out.json", "r") as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    results.append({
                        "path": r.get("input", {}).get("FUZZ", ""),
                        "url": r.get("url", ""),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                        "tool": "ffuf",
                    })
                os.remove("/tmp/ffuf_out.json")
        except Exception:
            pass

        if not results:
            # Parse text output as fallback
            for line in stdout.splitlines():
                m = re.search(r"Status:\s*(\d+).*?Size:\s*(\d+).*?(\S+)$", line)
                if m:
                    results.append({
                        "path": m.group(3),
                        "url": m.group(3),
                        "status": int(m.group(1)),
                        "length": int(m.group(2)),
                        "tool": "ffuf",
                    })

        print_success(f"ffuf found {len(results)} hits.")
        return results

    # ------------------------------------------------------------------
    # gobuster - Directory/File brute forcing
    # ------------------------------------------------------------------
    def run_gobuster(
        self,
        base_url: str,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        threads: int = 20,
        max_time: int = 60,
    ) -> List[Dict[str, Any]]:
        """Run gobuster dir mode. Returns list of hits."""
        if not self.gobuster_available:
            print_warning("gobuster not available, using Python fallback...")
            return self._python_dir_scan(base_url, wordlist)

        wordlist = wordlist or self._find_wordlist([
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ])
        if not wordlist:
            return self._python_dir_scan(base_url)

        cmd = [
            "gobuster", "dir",
            "-u", base_url.rstrip("/"),
            "-w", wordlist,
            "-t", str(threads),
            "-q",
            "-s", "200,301,302,307,403",
            "-b", "",
        ]
        if extensions:
            cmd += ["-x", ",".join(extensions)]

        print_info(f"Running gobuster against [bold cyan]{base_url}[/bold cyan]...")
        rc, stdout, stderr = self._run(cmd, timeout=max_time)

        results = []
        for line in stdout.splitlines():
            # gobuster output: /path (Status: 200) [Size: 1234]
            m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
            if m:
                results.append({
                    "path": m.group(1).lstrip("/"),
                    "url": f"{base_url.rstrip('/')}/{m.group(1).lstrip('/')}",
                    "status": int(m.group(2)),
                    "length": int(m.group(3)),
                    "tool": "gobuster",
                })

        print_success(f"gobuster found {len(results)} hits.")
        return results

    # ------------------------------------------------------------------
    # nmap - Port/service scanning
    # ------------------------------------------------------------------
    def run_nmap(
        self,
        host: str,
        ports: str = "1-10000",
        scripts: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Run nmap port scan. Returns list of open ports."""
        if not self.nmap_available:
            print_warning("nmap not available, skipping port scan.")
            return []

        cmd = [
            "nmap",
            "-sV",
            "-p", ports,
            "--open",
            "-oX", "/tmp/nmap_out.xml",
            host,
        ]
        if scripts:
            cmd += ["--script", ",".join(scripts)]

        print_info(f"Running nmap against [bold cyan]{host}[/bold cyan]...")
        rc, stdout, stderr = self._run(cmd, timeout=120)

        results = []
        # Parse XML output
        try:
            if os.path.isfile("/tmp/nmap_out.xml"):
                with open("/tmp/nmap_out.xml", "r") as f:
                    content = f.read()
                for m in re.finditer(
                    r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?<service name="(\w+)"',
                    content,
                    re.DOTALL,
                ):
                    results.append({
                        "protocol": m.group(1),
                        "port": int(m.group(2)),
                        "state": m.group(3),
                        "service": m.group(4),
                        "tool": "nmap",
                    })
                os.remove("/tmp/nmap_out.xml")
        except Exception:
            pass

        if not results:
            # Parse text output
            for line in stdout.splitlines():
                m = re.match(r"^(\d+)/(\w+)\s+(\w+)\s+(\S+)", line)
                if m:
                    results.append({
                        "port": int(m.group(1)),
                        "protocol": m.group(2),
                        "state": m.group(3),
                        "service": m.group(4),
                        "tool": "nmap",
                    })

        print_success(f"nmap found {len(results)} open ports.")
        return results

    # ------------------------------------------------------------------
    # sqlmap - SQL injection automation
    # ------------------------------------------------------------------
    def run_sqlmap(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        level: int = 2,
        risk: int = 1,
        batch: bool = True,
        dump: bool = False,
        max_time: int = 120,
    ) -> Dict[str, Any]:
        """Run sqlmap against a URL. Returns dict with findings."""
        if not self.sqlmap_available:
            print_warning("sqlmap not available, skipping SQLi automation.")
            return {"available": False, "vulnerable": False, "dbs": [], "tables": [], "data": []}

        cmd = [
            "sqlmap",
            "-u", url,
            "--level", str(level),
            "--risk", str(risk),
            "--batch",
            "--output-dir=/tmp/sqlmap_out",
            "--flush-session",
        ]
        if method.upper() == "POST" and data:
            cmd += ["--data", data]
        if cookie:
            cmd += ["--cookie", cookie]
        if dump:
            cmd += ["--dump-all"]

        print_info(f"Running sqlmap against [bold cyan]{url}[/bold cyan]...")
        rc, stdout, stderr = self._run(cmd, timeout=max_time)

        result = {
            "available": True,
            "vulnerable": False,
            "dbs": [],
            "tables": [],
            "data": [],
            "output": stdout[-2000:] if stdout else "",
        }

        # Detect vulnerability
        if re.search(r"is vulnerable|Parameter.*is vulnerable|injectable", stdout, re.IGNORECASE):
            result["vulnerable"] = True

        # Extract databases
        for m in re.finditer(r"available databases.*?\[\*\]\s+(\S+)", stdout, re.IGNORECASE):
            result["dbs"].append(m.group(1))

        # Extract tables
        for m in re.finditer(r"Database:\s*(\S+).*?Table:\s*(\S+)", stdout, re.IGNORECASE):
            result["tables"].append({"db": m.group(1), "table": m.group(2)})

        if result["vulnerable"]:
            print_success(f"sqlmap confirmed SQL injection at {url}")
        else:
            print_info("sqlmap did not find SQL injection.")

        return result

    # ------------------------------------------------------------------
    # nikto - Web server scanner
    # ------------------------------------------------------------------
    def run_nikto(
        self,
        base_url: str,
        max_time: int = 90,
    ) -> List[Dict[str, Any]]:
        """Run nikto web server scan. Returns list of findings."""
        if not self.nikto_available:
            print_warning("nikto not available, skipping web server scan.")
            return []

        cmd = [
            "nikto",
            "-h", base_url,
            "-nointeractive",
            "-Format", "txt",
        ]

        print_info(f"Running nikto against [bold cyan]{base_url}[/bold cyan]...")
        rc, stdout, stderr = self._run(cmd, timeout=max_time)

        findings = []
        for line in stdout.splitlines():
            if re.match(r"^\+\s", line):
                findings.append({
                    "finding": line.strip("+ ").strip(),
                    "tool": "nikto",
                })

        print_success(f"nikto found {len(findings)} findings.")
        return findings

    # ------------------------------------------------------------------
    # hydra - Login brute forcing
    # ------------------------------------------------------------------
    def run_hydra(
        self,
        host: str,
        service: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        passlist: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
        max_time: int = 120,
    ) -> List[Dict[str, Any]]:
        """Run hydra brute force. Returns list of credentials."""
        if not self.hydra_available:
            print_warning("hydra not available, skipping brute force.")
            return []

        passlist = passlist or self._find_wordlist([
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt",
        ])
        if not passlist:
            print_warning("No password list found for hydra.")
            return []

        cmd = ["hydra", "-t", "4", "-f"]
        if username:
            cmd += ["-l", username]
        if userlist:
            cmd += ["-L", userlist]
        cmd += ["-P", passlist]
        if port:
            cmd += ["-s", str(port)]
        if extra_args:
            cmd += extra_args
        cmd += [host, service]

        print_info(f"Running hydra against [bold cyan]{host}[/bold cyan] ({service})...")
        rc, stdout, stderr = self._run(cmd, timeout=max_time)

        creds = []
        for line in stdout.splitlines():
            m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
            if m:
                creds.append({"username": m.group(1), "password": m.group(2), "tool": "hydra"})

        if creds:
            print_success(f"hydra found {len(creds)} credentials.")
        return creds

    # ------------------------------------------------------------------
    # wfuzz - Web fuzzer
    # ------------------------------------------------------------------
    def run_wfuzz(
        self,
        base_url: str,
        wordlist: Optional[str] = None,
        max_time: int = 60,
    ) -> List[Dict[str, Any]]:
        """Run wfuzz fuzzer. Returns list of hits."""
        if not self.wfuzz_available:
            print_warning("wfuzz not available, using Python fallback...")
            return self._python_dir_scan(base_url, wordlist)

        wordlist = wordlist or self._find_wordlist([
            "/usr/share/wfuzz/wordlist/general/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ])
        if not wordlist:
            return self._python_dir_scan(base_url)

        cmd = [
            "wfuzz",
            "-w", wordlist,
            "--hc", "404",
            "-t", "20",
            f"{base_url.rstrip('/')}/FUZZ",
        ]

        print_info(f"Running wfuzz against [bold cyan]{base_url}[/bold cyan]...")
        rc, stdout, stderr = self._run(cmd, timeout=max_time)

        results = []
        for line in stdout.splitlines():
            m = re.match(r"^\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)", line)
            if m:
                results.append({
                    "path": m.group(2),
                    "url": f"{base_url.rstrip('/')}/{m.group(2)}",
                    "status": int(m.group(1)),
                    "length": 0,
                    "tool": "wfuzz",
                })

        print_success(f"wfuzz found {len(results)} hits.")
        return results

    # ------------------------------------------------------------------
    # Python fallback: directory scan
    # ------------------------------------------------------------------
    def _python_dir_scan(
        self,
        base_url: str,
        wordlist: Optional[str] = None,
        max_workers: int = 20,
    ) -> List[Dict[str, Any]]:
        """Pure-Python directory scan fallback."""
        import concurrent.futures
        import requests

        wordlist = wordlist or self._find_wordlist([
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ])
        if not wordlist:
            return []

        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception:
            return []

        def _check(path):
            url = f"{base_url.rstrip('/')}/{path}"
            try:
                r = requests.get(url, timeout=5, allow_redirects=False, verify=False)
                if r.status_code in [200, 301, 302, 403]:
                    return {
                        "path": path,
                        "url": url,
                        "status": r.status_code,
                        "length": len(r.content),
                        "tool": "python",
                    }
            except Exception:
                pass
            return None

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_check, w): w for w in words}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    results.append(res)

        print_success(f"Python fallback found {len(results)} hits.")
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _find_wordlist(self, candidates: List[str]) -> Optional[str]:
        """Return first existing wordlist path."""
        for c in candidates:
            if os.path.isfile(c):
                return c
        return None

    def summary(self) -> Dict[str, bool]:
        """Return dict of available tools."""
        return {
            "ffuf": self.ffuf_available,
            "sqlmap": self.sqlmap_available,
            "nmap": self.nmap_available,
            "gobuster": self.gobuster_available,
            "nikto": self.nikto_available,
            "hydra": self.hydra_available,
            "wfuzz": self.wfuzz_available,
            "dirb": self.dirb_available,
        }

    def print_summary(self):
        """Print available tools summary."""
        print_info("External tools status:")
        for name, avail in self.summary().items():
            status = "✅" if avail else "❌"
            print_info(f"  {status} {name}")

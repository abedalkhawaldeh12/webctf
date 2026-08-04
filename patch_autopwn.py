import re

path = '/home/kali/Desktop/abed/webctf/modules/autopwn.py'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# 1. Add import for ExternalTools after existing imports
if 'from modules.external_tools import ExternalTools' not in content:
    content = content.replace(
        'from modules.reasoning_engine import ReasoningEngine',
        'from modules.reasoning_engine import ReasoningEngine\nfrom modules.external_tools import ExternalTools'
    )
    print('Added ExternalTools import')

# 2. Add external tools integration in phase1_reconnaissance
marker = '                        self._check_and_store_flags(content, h["path"])\n                    except Exception:\n                        pass'
addition = '''                        self._check_and_store_flags(content, h["path"])
                    except Exception:
                        pass

        # 4b. External Tools Integration (ffuf, gobuster, nmap, nikto)
        try:
            ext = ExternalTools()
            self.state["external_tools"] = ext.summary()
            
            # Run ffuf/gobuster for deeper directory discovery
            if ext.ffuf_available or ext.gobuster_available:
                print_info("Running external directory discovery (ffuf/gobuster)...")
                ext_hits = []
                if ext.ffuf_available:
                    ext_hits.extend(ext.run_ffuf(self.target_url, max_time=45))
                elif ext.gobuster_available:
                    ext_hits.extend(ext.run_gobuster(self.target_url))
                
                # Merge external hits
                seen = {h["path"] for h in hits}
                for eh in ext_hits:
                    if eh["path"] not in seen:
                        seen.add(eh["path"])
                        self.state["sensitive_hits"].append(eh)
                        if eh["status"] == 200:
                            print_success(f"External Tool Found: [bold yellow]{eh['path']}[/bold yellow] (Size: {eh['length']} bytes)")
                            self._log_step("Phase 1: Recon", f"External tool discovered: {eh['path']}")
                            # Check for flags
                            try:
                                resp = self.session.get(eh["url"], timeout=5)
                                self._check_and_store_flags(resp.text, eh["path"])
                            except Exception:
                                pass

            # Run nikto for web server scan
            if ext.nikto_available:
                print_info("Running nikto web server scan...")
                nikto_findings = ext.run_nikto(self.target_url, max_time=60)
                for nf in nikto_findings:
                    self._log_step("Phase 1: Recon", f"nikto: {nf['finding']}")
        except Exception as e:
            print_warning(f"External tools integration skipped: {e}")'''

if marker in content:
    content = content.replace(marker, addition)
    print('Added external tools integration to phase1')
else:
    print('WARNING: phase1 marker not found, trying alternative...')
    alt_marker = '    # =========================================================================\n    # PHASE 2:'
    if alt_marker in content:
        content = content.replace(alt_marker, addition + '\n\n' + alt_marker, 1)
        print('Added external tools integration via alternative marker')

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print('Done patching autopwn.py')

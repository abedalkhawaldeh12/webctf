import sys
with open('d:/webpentest/modules/ctf_reasoner.py', 'r', encoding='utf-8') as f:
    content = f.read()
    
# Replace hypothesize
target1 = "        # ── Hypothesis: PHP"
repl1 = """        # ── Hypothesis: WAF/Filter bypass needed for LFI ─────────────────
        if self.state.get("leaked_source_files") and "services" in self.state["leaked_source_files"]:
            self.hypotheses.append(Hypothesis(
                title="LFI Filter Bypass for config.php",
                logic="services.php requires CONFIG constant, usually defined in config.php. WAF blocks 'config' and 'index'. We must bypass the string filter or find a hidden parameter.",
                test="Test PHP wrapper case sensitivity, URL encoding, path traversal, or param pollution to read config.php",
                confidence=0.95,
                observations=["LFI blocked on 'config'", "services.php contains defined('CONFIG')"]
            ))

        # ── Hypothesis: PHP"""
content = content.replace(target1, repl1)

with open('d:/webpentest/modules/ctf_reasoner.py', 'w', encoding='utf-8') as f:
    f.write(content)

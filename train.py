#!/usr/bin/env python3
"""
WebCTF Suite - Automated CTF Training Script
============================================
Runs the AutoPwn pipeline against a list of CTF challenges from multiple
platforms (picoCTF, Root-Me, HackTheBox, TryHackMe) and aggregates results.

Usage:
    python train.py                          # Run all challenges
    python train.py --challenge picoctf_ssti # Run specific challenge
    python train.py --platform picoCTF       # Run challenges from a platform
    python train.py --vuln ssti              # Run challenges of a vuln type
    python train.py --dry-run                # Show challenges without running
    python train.py --report                 # Generate training report only
    python train.py --timeout 60             # Per-challenge timeout in seconds
"""

import sys
import os
import json
import time
import argparse
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional

# Ensure local module directory is in python search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.ui import (
    console, print_banner, print_header, print_success, print_error,
    print_info, print_warning, print_flag, print_table
)
from core.memory import LearningEngine, LootManager, SessionStorage

CHALLENGES_FILE = os.path.join(os.path.dirname(__file__), "challenges.json")
TRAINING_REPORT_DIR = os.path.join(os.path.dirname(__file__), "storage", "training_reports")


def load_challenges() -> List[Dict[str, Any]]:
    """Load challenge list from challenges.json."""
    if not os.path.isfile(CHALLENGES_FILE):
        print_error(f"Challenges file not found: {CHALLENGES_FILE}")
        return []
    try:
        with open(CHALLENGES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("challenges", [])
    except Exception as e:
        print_error(f"Failed to load challenges: {e}")
        return []


def filter_challenges(
    challenges: List[Dict[str, Any]],
    challenge_id: Optional[str] = None,
    platform: Optional[str] = None,
    vuln_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Filter challenges by criteria."""
    result = challenges
    if challenge_id:
        result = [c for c in result if challenge_id.lower() in c.get("id", "").lower()]
    if platform:
        result = [c for c in result if platform.lower() in c.get("platform", "").lower()]
    if vuln_type:
        result = [c for c in result if vuln_type.lower() in c.get("vuln_types", [])]
    return result


def run_single_challenge(challenge: Dict[str, Any], timeout: int = 120) -> Dict[str, Any]:
    """
    Run AutoPwn pipeline on a single challenge.
    Returns a result dict with success/failure info.
    """
    url = challenge.get("url", "")
    cid = challenge.get("id", "unknown")
    prefix = challenge.get("flag_prefix", "")

    print_header(
        f"Training Challenge: {challenge.get('name', cid)}",
        f"{challenge.get('platform', 'Unknown')} | {', '.join(challenge.get('vuln_types', []))} | Difficulty: {challenge.get('difficulty', 'unknown')}"
    )
    print_info(f"Target: [bold cyan]{url}[/bold cyan]")
    if challenge.get("notes"):
        print_info(f"Notes: {challenge['notes']}")

    start_time = time.time()
    result = {
        "id": cid,
        "name": challenge.get("name", cid),
        "platform": challenge.get("platform", "Unknown"),
        "url": url,
        "vuln_types": challenge.get("vuln_types", []),
        "difficulty": challenge.get("difficulty", "unknown"),
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": 0,
        "flags_captured": [],
        "success": False,
        "error": None,
        "steps_count": 0
    }

    try:
        # Build command
        cmd = [sys.executable, "webctf.py", "autopwn", url]
        if prefix:
            cmd.extend(["--prefix", prefix])

        # Run the pipeline
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.path.dirname(__file__)
        )

        output = proc.stdout + proc.stderr

        # Extract flags from output (strip ANSI color codes first)
        import re
        # Remove ANSI escape sequences
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_output = ansi_escape.sub('', output)

        flag_patterns = [
            r'(picoCTF\{[^}]+\})',
            r'(flag\{[^}]+\})',
            r'(FLAG\{[^}]+\})',
            r'(CTF\{[^}]+\})',
            r'([a-zA-Z0-9_]+\{[^}]+\})'
        ]
        for pattern in flag_patterns:
            matches = re.findall(pattern, clean_output)
            for m in matches:
                if m not in result["flags_captured"]:
                    result["flags_captured"].append(m)

        # Count attack steps
        result["steps_count"] = output.count("Phase")

        # Determine success
        result["success"] = len(result["flags_captured"]) > 0

        if result["success"]:
            print_success(f"Challenge solved! Captured {len(result['flags_captured'])} flag(s)")
            for f in result["flags_captured"]:
                print_flag(f)
        else:
            print_warning("No flags captured in this run.")

    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
        print_error(f"Challenge timed out after {timeout}s")
    except Exception as e:
        result["error"] = str(e)
        print_error(f"Failed to run challenge: {e}")

    result["duration_seconds"] = round(time.time() - start_time, 2)
    print_info(f"Duration: {result['duration_seconds']}s | Steps: {result['steps_count']}")

    # Record result in learning engine
    le = LearningEngine()
    vuln_types = challenge.get("vuln_types", [])
    if result["success"]:
        le.record_platform_result(
            challenge.get("platform", "Unknown"),
            True,
            vuln_types
        )
    else:
        le.record_failure(
            url,
            [],
            vuln_types,
            reason=result.get("error") or "No flags captured"
        )
        le.record_platform_result(
            challenge.get("platform", "Unknown"),
            False,
            vuln_types
        )

    return result


def generate_training_report(results: List[Dict[str, Any]]) -> str:
    """Generate a markdown training report."""
    os.makedirs(TRAINING_REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(TRAINING_REPORT_DIR, f"training_report_{timestamp}.md")

    solved = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]

    lines = []
    lines.append("# 🚩 WebCTF Suite - Training Report")
    lines.append("")
    lines.append(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## 📊 Summary")
    lines.append("")
    lines.append(f"- **Total Challenges**: {len(results)}")
    lines.append(f"- **Solved**: {len(solved)}")
    lines.append(f"- **Failed**: {len(failed)}")
    lines.append(f"- **Success Rate**: {round(len(solved)/len(results)*100, 1) if results else 0}%")
    lines.append(f"- **Total Flags Captured**: {sum(len(r['flags_captured']) for r in results)}")
    lines.append(f"- **Total Time**: {round(sum(r['duration_seconds'] for r in results), 1)}s")
    lines.append("")

    # Per-platform breakdown
    platforms = {}
    for r in results:
        p = r["platform"]
        if p not in platforms:
            platforms[p] = {"total": 0, "solved": 0, "flags": 0}
        platforms[p]["total"] += 1
        platforms[p]["solved"] += 1 if r["success"] else 0
        platforms[p]["flags"] += len(r["flags_captured"])

    lines.append("## 🏢 Per-Platform Breakdown")
    lines.append("")
    lines.append("| Platform | Total | Solved | Flags |")
    lines.append("|----------|-------|--------|-------|")
    for p, stats in sorted(platforms.items()):
        lines.append(f"| {p} | {stats['total']} | {stats['solved']} | {stats['flags']} |")
    lines.append("")

    # Per-vuln-type breakdown
    vuln_stats = {}
    for r in results:
        for v in r["vuln_types"]:
            if v not in vuln_stats:
                vuln_stats[v] = {"total": 0, "solved": 0}
            vuln_stats[v]["total"] += 1
            vuln_stats[v]["solved"] += 1 if r["success"] else 0

    lines.append("## 🎯 Per-Vulnerability-Type Breakdown")
    lines.append("")
    lines.append("| Vulnerability | Total | Solved |")
    lines.append("|---------------|-------|--------|")
    for v, stats in sorted(vuln_stats.items()):
        lines.append(f"| {v} | {stats['total']} | {stats['solved']} |")
    lines.append("")

    # Detailed results
    lines.append("## 📋 Detailed Results")
    lines.append("")
    for r in results:
        status = "✅" if r["success"] else "❌"
        lines.append(f"### {status} {r['name']} ({r['platform']})")
        lines.append("")
        lines.append(f"- **ID**: `{r['id']}`")
        lines.append(f"- **URL**: `{r['url']}`")
        lines.append(f"- **Vuln Types**: {', '.join(r['vuln_types'])}")
        lines.append(f"- **Difficulty**: {r['difficulty']}")
        lines.append(f"- **Duration**: {r['duration_seconds']}s")
        lines.append(f"- **Steps**: {r['steps_count']}")
        if r["flags_captured"]:
            lines.append(f"- **Flags**: {', '.join(r['flags_captured'])}")
        if r["error"]:
            lines.append(f"- **Error**: {r['error']}")
        lines.append("")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return report_path


def print_summary(results: List[Dict[str, Any]]):
    """Print a summary table of training results."""
    print_header("Training Summary", f"Total: {len(results)} challenges")
    rows = []
    for r in results:
        status = "✅" if r["success"] else "❌"
        rows.append([
            status,
            r["name"],
            r["platform"],
            ", ".join(r["vuln_types"]),
            str(len(r["flags_captured"])),
            f"{r['duration_seconds']}s"
        ])
    print_table(
        ["Status", "Challenge", "Platform", "Vuln Types", "Flags", "Duration"],
        rows,
        title="Training Results"
    )

    solved = [r for r in results if r["success"]]
    print_success(f"Solved: {len(solved)}/{len(results)} challenges")
    total_flags = sum(len(r["flags_captured"]) for r in results)
    print_info(f"Total flags captured: [bold yellow]{total_flags}[/bold yellow]")


def main():
    parser = argparse.ArgumentParser(
        prog="train",
        description="WebCTF Suite - Automated CTF Training Script"
    )
    parser.add_argument("--challenge", help="Run specific challenge by ID (substring match)")
    parser.add_argument("--platform", help="Filter by platform (picoCTF, Root-Me, etc.)")
    parser.add_argument("--vuln", help="Filter by vulnerability type (ssti, sqli, lfi, etc.)")
    parser.add_argument("--dry-run", action="store_true", help="Show challenges without running")
    parser.add_argument("--report", action="store_true", help="Generate report from existing results")
    parser.add_argument("--timeout", type=int, default=120, help="Per-challenge timeout in seconds")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")

    args = parser.parse_args()

    print_banner()
    print_header("WebCTF Suite - Automated CTF Training", "Multi-platform challenge training")

    challenges = load_challenges()
    if not challenges:
        print_error("No challenges found. Check challenges.json")
        return

    filtered = filter_challenges(
        challenges,
        challenge_id=args.challenge,
        platform=args.platform,
        vuln_type=args.vuln
    )

    if not filtered:
        print_warning("No challenges match the given filters.")
        return

    print_info(f"Loaded [bold green]{len(filtered)}[/bold green] challenges from [bold cyan]{len(set(c['platform'] for c in filtered))}[/bold cyan] platform(s)")

    # Show challenge list
    rows = [[c["id"], c["name"], c["platform"], ", ".join(c["vuln_types"]), c["difficulty"]] for c in filtered]
    print_table(["ID", "Name", "Platform", "Vuln Types", "Difficulty"], rows, title="Challenge List")

    if args.dry_run:
        print_info("Dry run mode - not executing challenges.")
        return

    # Run challenges
    results = []
    for i, challenge in enumerate(filtered, 1):
        print_info(f"\n[bold]Challenge {i}/{len(filtered)}[/bold]")
        result = run_single_challenge(challenge, timeout=args.timeout)
        results.append(result)

    # Print summary
    print_summary(results)

    # Generate report
    if not args.no_report and results:
        report_path = generate_training_report(results)
        print_success(f"Training report saved to: [bold cyan]{report_path}[/bold cyan]")

    # Show learning stats
    le = LearningEngine()
    stats = le.get_enhanced_stats()
    print_header("Updated Learning Memory", "Adaptive Learning Engine")
    print_info(f"Total Solved Challenges: [bold green]{stats['stats'].get('total_solved_challenges', 0)}[/bold green]")
    print_info(f"Total Flags Captured: [bold yellow]{stats['stats'].get('total_captured_flags', 0)}[/bold yellow]")
    print_info(f"Successful Exploits: [bold cyan]{stats['stats'].get('successful_exploits', 0)}[/bold cyan]")
    print_info(f"Failed Attempts: [bold red]{stats['stats'].get('failed_attempts', 0)}[/bold red]")
    print_info(f"Learned Technologies: [bold magenta]{stats.get('learned_technologies_count', 0)}[/bold magenta]")
    print_info(f"Weighted Payloads: [bold white]{stats.get('learned_payloads_count', 0)}[/bold white]")

    # Show platform stats
    if stats.get("platform_stats"):
        print_header("Platform Performance", "Per-platform success rates")
        p_rows = []
        for pkey, pdata in sorted(stats["platform_stats"].items()):
            total = pdata.get("total", 0)
            succ = pdata.get("successes", 0)
            rate = round(succ / total * 100, 1) if total else 0
            p_rows.append([pkey, str(total), str(succ), str(pdata.get("failures", 0)), f"{rate}%"])
        print_table(["Platform", "Total", "Successes", "Failures", "Success Rate"], p_rows, title="Platform Stats")

    # Show vuln type stats
    if stats.get("vuln_type_stats"):
        print_header("Vulnerability Type Performance", "Per-vuln-type success rates")
        v_rows = []
        for vkey, vdata in sorted(stats["vuln_type_stats"].items()):
            succ = vdata.get("successes", 0)
            fail = vdata.get("failures", 0)
            total = succ + fail
            rate = round(succ / total * 100, 1) if total else 0
            v_rows.append([vkey, str(succ), str(fail), f"{rate}%"])
        print_table(["Vuln Type", "Successes", "Failures", "Success Rate"], v_rows, title="Vuln Type Stats")

    # Show recommendations
    if results:
        all_vulns = set()
        for r in results:
            all_vulns.update(r["vuln_types"])
        recs = le.get_recommendations([], list(all_vulns))
        if recs:
            print_header("Learning Recommendations", "Based on training results")
            for rec in recs:
                if rec["priority"] == "high":
                    print_success(f"[{rec['vuln_type']}] {rec['message']}")
                    for p in rec.get("payloads", []):
                        print_info(f"  → {p['name']} (weight: {p['weight']})")
                elif rec["priority"] == "medium":
                    print_info(f"[{rec['vuln_type']}] {rec['message']}")
                else:
                    print_warning(f"[{rec['vuln_type']}] {rec['message']}")


if __name__ == "__main__":
    main()

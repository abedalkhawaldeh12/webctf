"""
Test script for the Intelligence Engine.
Creates a mock state with various findings and verifies the engine
correctly prioritizes important things and ignores noise.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.intelligence_engine import IntelligenceEngine


def create_mock_state():
    """Create a mock state with a mix of important and noise findings."""
    return {
        "target_url": "http://test-target.com/",
        "flag_prefix": "picoCTF",
        "tech_stack": ["python", "flask", "jinja2"],
        "parameters": [
            "id", "username", "password", "file", "url", "cmd",
            "utm_source", "gclid", "ref", "search", "page",
        ],
        "sensitive_hits": [
            {"path": "/admin", "url": "http://test-target.com/admin", "status": 200, "length": 1500},
            {"path": "/login", "url": "http://test-target.com/login", "status": 200, "length": 800},
            {"path": "/flag.txt", "url": "http://test-target.com/flag.txt", "status": 200, "length": 50},
            {"path": "/api/users", "url": "http://test-target.com/api/users", "status": 200, "length": 3000},
            {"path": "/upload", "url": "http://test-target.com/upload", "status": 200, "length": 1200},
            {"path": "/favicon.ico", "url": "http://test-target.com/favicon.ico", "status": 200, "length": 100},
            {"path": "/css/style.css", "url": "http://test-target.com/css/style.css", "status": 200, "length": 500},
            {"path": "/robots.txt", "url": "http://test-target.com/robots.txt", "status": 200, "length": 200},
            {"path": "/backup.zip", "url": "http://test-target.com/backup.zip", "status": 200, "length": 50000},
            {"path": "/debug", "url": "http://test-target.com/debug", "status": 200, "length": 900},
            {"path": "/config.php", "url": "http://test-target.com/config.php", "status": 200, "length": 700},
            {"path": "/index.html", "url": "http://test-target.com/index.html", "status": 200, "length": 3000},
        ],
        "vulnerabilities": [
            {"type": "sqli", "confidence": 0.9, "evidence": ["SQL syntax error in id param", "mysql_fetch_array"]},
            {"type": "ssti", "confidence": 0.8, "evidence": ["TemplateSyntaxError", "jinja2.exceptions"]},
            {"type": "xss", "confidence": 0.3, "evidence": []},
            {"type": "lfi", "confidence": 0.7, "evidence": ["etc/passwd", "php://filter"]},
        ],
        "endpoints": ["/admin", "/login", "/api", "/css", "/js"],
    }


def main():
    print("=" * 60)
    print("TEST: Intelligence Engine")
    print("=" * 60)

    state = create_mock_state()
    engine = IntelligenceEngine(state)

    # Test 1: analyze()
    print("\n[TEST 1] Running analyze()...")
    report = engine.analyze()
    assert "endpoint_scores" in report, "Missing endpoint_scores"
    assert "param_scores" in report, "Missing param_scores"
    assert "vuln_scores" in report, "Missing vuln_scores"
    assert "attack_priority" in report, "Missing attack_priority"
    print("  PASS: analyze() returned all sections")

    # Test 2: High-value endpoints should be scored high
    print("\n[TEST 2] Checking high-value endpoint scoring...")
    high_value = [e for e in report["endpoint_scores"] if e["score"] >= 70]
    high_paths = [e["endpoint"] for e in high_value]
    print(f"  High-value endpoints: {high_paths}")
    assert "/admin" in high_paths, "admin should be high-value"
    assert "/flag.txt" in high_paths, "flag.txt should be high-value"
    assert "/config.php" in high_paths, "config.php should be high-value"
    print("  PASS: Important endpoints correctly scored high")

    # Test 3: Noise endpoints should be scored low
    print("\n[TEST 3] Checking noise endpoint filtering...")
    ignore = [e for e in report["endpoint_scores"] if e["score"] < 30]
    ignore_paths = [e["endpoint"] for e in ignore]
    print(f"  Ignored endpoints: {ignore_paths}")
    assert "/favicon.ico" in ignore_paths, "favicon should be ignored"
    assert "/css/style.css" in ignore_paths, "css should be ignored"
    print("  PASS: Noise endpoints correctly filtered")

    # Test 4: should_attack / should_ignore
    print("\n[TEST 4] Checking should_attack / should_ignore...")
    assert engine.should_attack("/admin") == True, "admin should be attacked"
    assert engine.should_attack("/flag.txt") == True, "flag.txt should be attacked"
    assert engine.should_ignore("/favicon.ico") == True, "favicon should be ignored"
    assert engine.should_ignore("/css/style.css") == True, "css should be ignored"
    print("  PASS: should_attack/should_ignore work correctly")

    # Test 5: Parameter scoring
    print("\n[TEST 5] Checking parameter scoring...")
    high_params = [p for p in report["param_scores"] if p["score"] >= 40]
    high_param_names = [p["param"] for p in high_params]
    print(f"  High-value params: {high_param_names}")
    assert "id" in high_param_names, "id should be high-value"
    assert "cmd" in high_param_names, "cmd should be high-value"
    assert "file" in high_param_names, "file should be high-value"
    assert "utm_source" not in high_param_names, "utm_source should NOT be high-value"
    print("  PASS: Important params correctly scored high")

    # Test 6: Vulnerability scoring
    print("\n[TEST 6] Checking vulnerability scoring...")
    high_vulns = [v for v in report["vuln_scores"] if v["score"] >= 60]
    high_vuln_types = [v["type"] for v in high_vulns]
    print(f"  High-value vulns: {high_vuln_types}")
    assert "sqli" in high_vuln_types, "sqli should be high-value"
    assert "ssti" in high_vuln_types, "ssti should be high-value"
    print("  PASS: Important vulns correctly scored high")

    # Test 7: Attack priority
    print("\n[TEST 7] Checking attack priority...")
    priority = report["attack_priority"]
    print(f"  Attack priority ({len(priority)} items):")
    for i, item in enumerate(priority[:5]):
        print(f"    {i+1}. {item['target']} ({item['vuln_class']}) - {item['priority']}/100")
    assert len(priority) > 0, "Should have attack priority items"
    assert priority[0]["priority"] >= priority[-1]["priority"], "Should be sorted descending"
    print("  PASS: Attack priority correctly ordered")

    # Test 8: decide_next_action
    print("\n[TEST 8] Checking decide_next_action...")
    next_action = engine.decide_next_action()
    assert next_action is not None, "Should have a next action"
    print(f"  Next action: {next_action['target']} ({next_action['vuln_class']})")
    print("  PASS: decide_next_action works")

    # Test 9: summarize
    print("\n[TEST 9] Checking summarize...")
    summary = engine.summarize()
    print(f"  Summary: {summary}")
    assert summary["high_value_endpoints"] >= 4, "Should have at least 4 high-value endpoints"
    assert summary["ignored_endpoints"] >= 2, "Should have at least 2 ignored endpoints"
    print("  PASS: summarize works")

    # Print the full priority report
    print("\n" + "=" * 60)
    print("FULL PRIORITY REPORT:")
    print("=" * 60)
    engine.print_priority_report()

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED ✅")
    print("=" * 60)


if __name__ == "__main__":
    main()

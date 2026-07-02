#!/usr/bin/env python3
"""Overnight supervisor script for fgcheck project.
Checks git state and produces a status report for the next cron tick."""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path("C:/git/fortigatecheck")

def run(cmd):
    r = subprocess.run(cmd, shell=True, cwd=REPO, capture_output=True, text=True, timeout=60)
    return r.stdout.strip()

def main():
    report = {}
    
    # Git state
    report["log"] = run("git log --oneline -10")
    report["status"] = run("git status --short")
    report["branch"] = run("git branch --show-current")
    
    # Test state
    test_result = run("python -m pytest tests/ -q --tb=line 2>&1 | tail -5")
    report["tests"] = test_result
    
    # Count source and test lines
    src_lines = run("wc -l src/fgcheck/*.py 2>/dev/null | tail -1")
    test_lines = run("wc -l tests/*.py 2>/dev/null | tail -1")
    report["src_lines"] = src_lines
    report["test_lines"] = test_lines
    
    # Count rules
    rules = run("ls rules/builtin/*.yaml 2>/dev/null | wc -l")
    report["rule_count"] = rules.strip()
    
    # Schema versions
    schemas = run("ls -d docs/derived/schema/*/ 2>/dev/null")
    report["schema_versions"] = schemas
    
    # Uncommitted work
    diff_stat = run("git diff --stat HEAD")
    report["uncommitted"] = diff_stat
    
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()

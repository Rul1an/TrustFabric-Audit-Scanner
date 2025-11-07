#!/usr/bin/env python3
"""Bandit Python Security Scanner"""

import subprocess
import json
from pathlib import Path

class BanditScanner:
    def __init__(self, target_dir: str, output_dir: str = "audit_results/week1"):
        self.target_dir = Path(target_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scan(self) -> dict:
        """Run Bandit scan"""
        print("🔍 Running Bandit scan...")

        cmd = [
            "bandit", "-r", str(self.target_dir),
            "-f", "json",
            "-o", str(self.output_dir / "bandit.json"),
            "-ll"  # Low confidence or higher
        ]

        try:
            subprocess.run(cmd, capture_output=True, timeout=180)

            with open(self.output_dir / "bandit.json") as f:
                data = json.load(f)

            findings = data.get("results", [])
            high = [f for f in findings if f.get("issue_severity") == "HIGH"]
            medium = [f for f in findings if f.get("issue_severity") == "MEDIUM"]

            print(f"   ✓ Findings: {len(findings)} (HIGH: {len(high)}, MEDIUM: {len(medium)})")

            return {"tool": "bandit", "findings": findings, "summary": {"total": len(findings), "high": len(high), "medium": len(medium)}}

        except Exception as e:
            print(f"   ✗ Failed: {e}")
            return {"tool": "bandit", "error": str(e)}

if __name__ == "__main__":
    import sys
    scanner = BanditScanner(sys.argv[1] if len(sys.argv) > 1 else "../TrustFabric")
    results = scanner.scan()
    print(f"\nResults: {results.get('summary', {})}")


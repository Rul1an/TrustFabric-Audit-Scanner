#!/usr/bin/env python3
"""pip-audit CVE Scanner"""

import subprocess
import json
from pathlib import Path

class PipAuditScanner:
    def __init__(self, requirements_file: str, output_dir: str = "audit_results/week1"):
        self.requirements_file = Path(requirements_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def scan(self) -> dict:
        """Run pip-audit scan"""
        print("🔍 Running pip-audit scan...")
        
        cmd = [
            "pip-audit",
            "-r", str(self.requirements_file),
            "--format", "json",
            "--output", str(self.output_dir / "pip_audit.json")
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            
            with open(self.output_dir / "pip_audit.json") as f:
                data = json.load(f)
            
            dependencies = data.get("dependencies", [])
            vulns = []
            for dep in dependencies:
                vulns.extend(dep.get("vulns", []))
            
            critical = [v for v in vulns if "CRITICAL" in v.get("id", "")]
            high = [v for v in vulns if "HIGH" in v.get("id", "")]
            
            print(f"   ✓ Vulnerabilities: {len(vulns)} (CRITICAL: {len(critical)}, HIGH: {len(high)})")
            
            return {"tool": "pip-audit", "vulnerabilities": vulns, "summary": {"total": len(vulns), "critical": len(critical), "high": len(high)}}
        
        except Exception as e:
            print(f"   ✗ Failed: {e}")
            return {"tool": "pip-audit", "error": str(e)}

if __name__ == "__main__":
    import sys
    scanner = PipAuditScanner(sys.argv[1] if len(sys.argv) > 1 else "../TrustFabric/requirements_v5.txt")
    results = scanner.scan()
    print(f"\nResults: {results.get('summary', {})}")


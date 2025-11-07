#!/usr/bin/env python3
"""
Semgrep Security Scanner
Scans TrustFabric codebase for security vulnerabilities
"""

import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

class SemgrepScanner:
    """Semgrep SAST scanner wrapper"""
    
    def __init__(self, target_dir: str, output_dir: str = "audit_results/week1"):
        self.target_dir = Path(target_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def scan(self, custom_rules: str = None) -> Dict[str, Any]:
        """
        Run Semgrep scan with standard + custom rules.
        
        Args:
            custom_rules: Path to custom rules YAML
        
        Returns:
            Scan results dict
        """
        print("🔍 Running Semgrep scan...")
        print(f"   Target: {self.target_dir}")
        
        # Build command
        cmd = [
            "semgrep",
            "--config=p/python",           # Python security rules
            "--config=p/security-audit",   # Security audit rules
            "--config=p/secrets",          # Secret detection rules
            "--json",
            "--output", str(self.output_dir / "semgrep.json"),
            str(self.target_dir)
        ]
        
        # Add custom rules if provided
        if custom_rules:
            cmd.insert(1, f"--config={custom_rules}")
            print(f"   Custom rules: {custom_rules}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 min timeout
            )
            
            # Semgrep returns exit code 1 if findings, 0 if clean
            # This is expected behavior
            
            # Load results
            output_file = self.output_dir / "semgrep.json"
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                
                findings = data.get("results", [])
                errors = data.get("errors", [])
                
                print(f"   ✓ Scan complete")
                print(f"   Findings: {len(findings)}")
                print(f"   Errors: {len(errors)}")
                
                # Categorize by severity
                critical = [f for f in findings if f.get("extra", {}).get("severity") == "ERROR"]
                warning = [f for f in findings if f.get("extra", {}).get("severity") == "WARNING"]
                
                print(f"   - Critical: {len(critical)}")
                print(f"   - Warning: {len(warning)}")
                
                return {
                    "tool": "semgrep",
                    "findings": findings,
                    "errors": errors,
                    "summary": {
                        "total": len(findings),
                        "critical": len(critical),
                        "warning": len(warning)
                    }
                }
            else:
                print(f"   ✗ Output file not found: {output_file}")
                return {"tool": "semgrep", "error": "No output file"}
        
        except subprocess.TimeoutExpired:
            print("   ✗ Scan timeout (>5 min)")
            return {"tool": "semgrep", "error": "Timeout"}
        
        except Exception as e:
            print(f"   ✗ Scan failed: {e}")
            return {"tool": "semgrep", "error": str(e)}


def main():
    """Run Semgrep scan on TrustFabric"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Semgrep security scanner")
    parser.add_argument("--target", required=True, help="Target directory to scan")
    parser.add_argument("--custom-rules", help="Custom Semgrep rules YAML")
    parser.add_argument("--output-dir", default="audit_results/week1", help="Output directory")
    args = parser.parse_args()
    
    scanner = SemgrepScanner(args.target, args.output_dir)
    results = scanner.scan(custom_rules=args.custom_rules)
    
    # Print summary
    if "error" in results:
        print(f"\n✗ Scan failed: {results['error']}")
        return 1
    
    summary = results.get("summary", {})
    print(f"\n{'='*60}")
    print(f"Semgrep Scan Complete")
    print(f"{'='*60}")
    print(f"Total findings: {summary.get('total', 0)}")
    print(f"  Critical: {summary.get('critical', 0)}")
    print(f"  Warning: {summary.get('warning', 0)}")
    print(f"\nResults: {args.output_dir}/semgrep.json")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())


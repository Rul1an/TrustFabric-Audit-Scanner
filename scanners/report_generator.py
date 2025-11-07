#!/usr/bin/env python3
"""
Security Assessment Report Generator
"""

import json
from pathlib import Path
from datetime import datetime

class ReportGenerator:
    def __init__(self, results_dir: str = "audit_results/week1"):
        self.results_dir = Path(results_dir)
    
    def generate(self, output_file: str = "SECURITY_ASSESSMENT_REPORT.md") -> str:
        """Generate markdown security report"""
        print("📝 Generating security assessment report...")
        
        # Load consolidated results
        consolidated_file = self.results_dir / "consolidated.json"
        if not consolidated_file.exists():
            print("   ✗ Run consolidator first: python3 scanners/consolidator.py")
            return ""
        
        with open(consolidated_file) as f:
            data = json.load(f)
        
        # Generate report
        report = f"""# TrustFabric Security Assessment Report

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Audit Period:** Week 1 (Automated Scanning)  
**Scope:** Cryptographic modules, attestation, PHI safety, dependencies

---

## Executive Summary

**Total Findings:** {data['total_findings']}

**By Tool:**
"""
        
        for scan in data['scans']:
            report += f"- **{scan['tool']}:** {scan['findings_count']} findings\n"
        
        report += """

---

## Scan Results

### SAST (Static Application Security Testing)
- **Semgrep:** Pattern-based security rules (Python, crypto, AI-specific)
- **Bandit:** Python security linter

### SCA (Software Composition Analysis)
- **pip-audit:** PyPI vulnerability database

### Custom Scans
- **PHI Detection:** Medical data pattern scanning

---

## Findings Summary

See individual tool reports in `audit_results/week1/`:
- `semgrep.json` - SAST findings
- `bandit.json` - Python security issues
- `pip_audit.json` - Dependency vulnerabilities
- `phi_detection.json` - PHI pattern matches

---

## Recommendations

1. **Review all findings** in detail (check JSON files)
2. **Triage by severity** (CRITICAL → HIGH → MEDIUM → LOW)
3. **Fix CRITICAL findings** within 24 hours
4. **Fix HIGH findings** within 1 week
5. **Document MEDIUM/LOW** (accept risk or schedule fix)

---

## Next Steps

**Week 2:** External security audit (penetration test + code review)  
**Week 3:** Remediation (fix findings, re-test)  
**Week 4:** Sign-off (security assessment, Go/No-Go decision)

---

**Status:** Automated scanning complete  
**Next:** Manual review + external audit
"""
        
        # Save report
        with open(output_file, 'w') as f:
            f.write(report)
        
        print(f"   ✓ Report generated: {output_file}")
        
        return output_file

if __name__ == "__main__":
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else "SECURITY_ASSESSMENT_REPORT.md"
    generator = ReportGenerator()
    generator.generate(output)


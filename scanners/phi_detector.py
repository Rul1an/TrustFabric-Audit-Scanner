#!/usr/bin/env python3
"""
PHI Detection Scanner
Scans for Protected Health Information in code/logs
"""

import re
from pathlib import Path
import json

# PHI Patterns (regex) - Refined for medical context
PHI_PATTERNS = {
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',  # Social Security Number
    "mrn": r'\b(mrn|medical.?record|patient.?id)[\s:=]+["\']?\w{5,}',  # Medical Record Number
    "patient_name": r'(patient.?name|patientName)[\s:=]+["\'][A-Za-z\s]{3,}["\']',  # Actual names
    "date_of_birth": r'(dob|date.?of.?birth|birthdate)[\s:=]+["\']?\d{1,2}[-/]\d{1,2}[-/]\d{2,4}',  # Dates
    "patient_in_fstring": r'f["\'].*\{patient_?(name|id|mrn)\}',  # f-strings with patient vars
}

# Safe patterns to exclude (not PHI)
SAFE_PATTERNS = [
    r'demo@trustfabric\.io',
    r'support@trustfabric\.io',
    r'@example\.com',
    r'@test\.com',
    r'patient_count',  # Aggregate, not individual patient
    r'total_patients',
]

class PHIDetector:
    def __init__(self, target_dir: str, output_dir: str = "audit_results/week1"):
        self.target_dir = Path(target_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scan(self) -> dict:
        """Scan for PHI patterns in code"""
        print("🔍 Running PHI detection scan...")

        findings = []

        for py_file in self.target_dir.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')

                # Scan each line
                for line_num, line in enumerate(lines, 1):
                    # Skip test files and examples
                    if '/tests/' in str(py_file) or '/test_' in str(py_file) or '/examples/' in str(py_file):
                        continue

                    for pattern_name, pattern in PHI_PATTERNS.items():
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            # Check if it's a safe pattern
                            is_safe = any(re.search(safe, line, re.IGNORECASE) for safe in SAFE_PATTERNS)
                            if not is_safe:
                                findings.append({
                                    "file": str(py_file.relative_to(self.target_dir)),
                                    "line": line_num,
                                    "pattern": pattern_name,
                                    "content": line.strip()[:100],
                                    "severity": "CRITICAL"
                                })

            except Exception as e:
                print(f"   Warning: Couldn't scan {py_file}: {e}")

        # Save results
        with open(self.output_dir / "phi_detection.json", 'w') as f:
            json.dump({"findings": findings, "summary": {"total": len(findings)}}, f, indent=2)

        print(f"   ✓ PHI patterns found: {len(findings)}")

        return {"tool": "phi-detector", "findings": findings, "summary": {"total": len(findings)}}

if __name__ == "__main__":
    import sys
    scanner = PHIDetector(sys.argv[1] if len(sys.argv) > 1 else "../TrustFabric")
    results = scanner.scan()

    if results["summary"]["total"] > 0:
        print(f"\n⚠️  WARNING: {results['summary']['total']} potential PHI patterns detected!")
        print("Review: audit_results/week1/phi_detection.json")
    else:
        print("\n✓ No PHI patterns detected (good!)")


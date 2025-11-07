#!/usr/bin/env python3
"""
PHI Detection Scanner
Scans for Protected Health Information in code/logs
"""

import re
from pathlib import Path
import json

# PHI Patterns (regex)
PHI_PATTERNS = {
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "mrn": r'\b(mrn|medical.record|patient.id)[\s:=]+\w+',
    "patient_name": r'(patient.name|patient_name|patientName)[\s:=]+',
    "date_of_birth": r'(dob|date.of.birth|birthdate)[\s:=]+',
}

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
                    for pattern_name, pattern in PHI_PATTERNS.items():
                        if re.search(pattern, line, re.IGNORECASE):
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


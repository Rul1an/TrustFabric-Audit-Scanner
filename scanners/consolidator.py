#!/usr/bin/env python3
"""
Consolidate all scan results into single report
"""

import json
from pathlib import Path
from typing import List, Dict, Any

class ScanConsolidator:
    def __init__(self, results_dir: str = "audit_results/week1"):
        self.results_dir = Path(results_dir)
    
    def consolidate(self) -> Dict[str, Any]:
        """Consolidate all scan results"""
        print("📊 Consolidating scan results...")
        
        consolidated = {
            "scans": [],
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_category": {}
        }
        
        # Load all JSON results
        for json_file in self.results_dir.glob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                
                tool_name = json_file.stem
                findings = data.get("findings", []) or data.get("results", []) or data.get("vulnerabilities", [])
                
                consolidated["scans"].append({
                    "tool": tool_name,
                    "findings_count": len(findings),
                    "summary": data.get("summary", {})
                })
                
                consolidated["total_findings"] += len(findings)
                
                print(f"   {tool_name}: {len(findings)} findings")
                
            except Exception as e:
                print(f"   Warning: Couldn't load {json_file}: {e}")
        
        # Save consolidated
        output_file = self.results_dir / "consolidated.json"
        with open(output_file, 'w') as f:
            json.dump(consolidated, f, indent=2)
        
        print(f"\n   ✓ Consolidated: {consolidated['total_findings']} total findings")
        print(f"   Output: {output_file}")
        
        return consolidated

if __name__ == "__main__":
    consolidator = ScanConsolidator()
    results = consolidator.consolidate()
    print(f"\nSummary: {results['total_findings']} findings across {len(results['scans'])} scans")


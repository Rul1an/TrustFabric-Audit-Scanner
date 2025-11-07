#!/usr/bin/env python3
"""
SBOM (Software Bill of Materials) Generator
Uses CycloneDX standard for medical device compliance
"""

import subprocess
import json
from pathlib import Path

class SBOMGenerator:
    """Generate CycloneDX SBOM for dependency tracking"""

    def __init__(self, output_dir: str = "audit_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, requirements_file: str) -> dict:
        """Generate SBOM from requirements.txt"""
        print("📦 Generating SBOM (CycloneDX)...")

        output_file = self.output_dir / "sbom.json"

        cmd = [
            "cyclonedx-py",
            "-r", requirements_file,
            "-o", str(output_file),
            "--format", "json"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                print(f"   ✗ SBOM generation failed: {result.stderr}")
                return {"tool": "sbom", "error": result.stderr}

            # Load and analyze SBOM
            with open(output_file) as f:
                sbom = json.load(f)

            components = sbom.get("components", [])
            vulnerabilities = sbom.get("vulnerabilities", [])

            print(f"   ✓ SBOM generated")
            print(f"   Components: {len(components)}")
            print(f"   Format: {sbom.get('bomFormat')} v{sbom.get('specVersion')}")
            print(f"   Output: {output_file}")

            return {
                "tool": "sbom",
                "components": components,
                "vulnerabilities": vulnerabilities,
                "summary": {
                    "total_components": len(components),
                    "total_vulnerabilities": len(vulnerabilities)
                }
            }

        except subprocess.TimeoutExpired:
            print("   ✗ SBOM generation timeout")
            return {"tool": "sbom", "error": "Timeout"}

        except Exception as e:
            print(f"   ✗ SBOM generation failed: {e}")
            return {"tool": "sbom", "error": str(e)}

if __name__ == "__main__":
    import sys

    req_file = sys.argv[1] if len(sys.argv) > 1 else "../TrustFabric/requirements_v5.txt"

    generator = SBOMGenerator()
    result = generator.generate(req_file)

    if "error" in result:
        print(f"\n✗ Failed: {result['error']}")
        sys.exit(1)

    summary = result.get("summary", {})
    print(f"\nSummary:")
    print(f"  Components: {summary.get('total_components', 0)}")
    print(f"  Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")


#!/bin/bash
# Audit Scanner - Master Orchestrator
# Runs all security scans on TrustFabric codebase

set -e

# Configuration
TRUSTFABRIC_DIR=${1:-"../TrustFabric"}
OUTPUT_DIR="audit_results/week1"

echo "======================================"
echo "  TrustFabric Security Audit Scanner"
echo "======================================"
echo ""
echo "Target: $TRUSTFABRIC_DIR"
echo "Output: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p $OUTPUT_DIR

# Task 1: Semgrep (SAST)
echo "→ Running Semgrep (SAST)..."
python3 scanners/semgrep_scanner.py \
  --target "$TRUSTFABRIC_DIR" \
  --custom-rules configs/custom_ai_security_rules.yaml \
  --output-dir "$OUTPUT_DIR"

# Task 2: Bandit (Python Security)
echo ""
echo "→ Running Bandit (Python Security)..."
python3 scanners/bandit_scanner.py --target "$TRUSTFABRIC_DIR"

# Task 3: pip-audit (Dependency CVEs)
echo ""
echo "→ Running pip-audit (Dependency CVEs)..."
python3 scanners/pip_audit_scanner.py "$TRUSTFABRIC_DIR/requirements_v5.txt"

# Task 4: PHI Detection
echo ""
echo "→ Running PHI detection..."
python3 scanners/phi_detector.py "$TRUSTFABRIC_DIR"

# Task 5: Gitleaks (if installed)
if command -v gitleaks &> /dev/null; then
    echo ""
    echo "→ Running Gitleaks (Secret Detection)..."
    cd "$TRUSTFABRIC_DIR" && gitleaks detect \
      --report-path "../TrustFabric-Audit-Scanner/$OUTPUT_DIR/gitleaks.json" \
      --no-git || echo "  (no secrets found or not a git repo)"
    cd - > /dev/null
else
    echo ""
    echo "  (Skipping Gitleaks - not installed)"
fi

# Summary
echo ""
echo "======================================"
echo "✓ All scans complete!"
echo "======================================"
echo ""
echo "Results in: $OUTPUT_DIR/"
ls -lh $OUTPUT_DIR/*.json 2>/dev/null || echo "  No results files"
echo ""
echo "Next: Review findings and triage"
echo "  cat $OUTPUT_DIR/semgrep.json | jq '.results | length'"
echo ""


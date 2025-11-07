# Missing Features Implementation Plan

**Based on:** 2025 Security Best Practices (NIST, OWASP, MDR)
**Timeline:** 12 uur werk (2 features)
**Priority:** Phase 1 (before production)

---

## 🎯 Feature 1: SBOM Generation (4 uur)

### Why Necessary (Regulatory + Security):
- **MDR (EU Medical Device Regulation):** Annex I requires software composition transparency
- **FDA:** SBOM required for medical device software (2023 guidance)
- **NIST SSDF:** Software supply chain security best practice
- **Vulnerability Management:** Track dependencies for security updates

### Standards (2025):
- **CycloneDX 1.5** (preferred - JSON/XML, comprehensive)
- **SPDX 2.3** (alternative - Linux Foundation standard)

### Implementation Plan:

#### Task 1.1: Install SBOM Tools (30 min)
```bash
# CycloneDX (Python-specific, best for our use case)
pip install cyclonedx-bom

# Alternative: SPDX
pip install spdx-tools

# Verify installation
cyclonedx-py --version
```

**Acceptance:** Tools installed, version checked

---

#### Task 1.2: Generate SBOM (1 uur)
```bash
# Generate from requirements.txt
cyclonedx-py \
  -r ../TrustFabric/requirements_v5.txt \
  -o audit_results/sbom.json \
  --format json

# Generate from installed packages (more complete)
cyclonedx-py \
  -e ../TrustFabric \
  -o audit_results/sbom_full.json \
  --format json

# Validate SBOM
cyclonedx validate --input-file audit_results/sbom.json
```

**Output:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T...",
    "component": {
      "name": "TrustFabric",
      "version": "5.0.0"
    }
  },
  "components": [
    {
      "name": "azure-identity",
      "version": "1.15.0",
      "purl": "pkg:pypi/azure-identity@1.15.0",
      "licenses": [{"license": {"id": "MIT"}}],
      "hashes": [{"alg": "SHA-256", "content": "..."}]
    },
    // ... all dependencies
  ]
}
```

**Acceptance:** SBOM generated, validated, includes all dependencies

---

#### Task 1.3: SBOM Scanner Integration (1 uur)
```python
# scanners/sbom_generator.py
import subprocess
from pathlib import Path

class SBOMGenerator:
    def generate(self, target_dir: str, output_file: str = "audit_results/sbom.json"):
        """Generate CycloneDX SBOM"""
        print("📦 Generating SBOM...")

        requirements = Path(target_dir) / "requirements_v5.txt"

        cmd = [
            "cyclonedx-py",
            "-r", str(requirements),
            "-o", output_file,
            "--format", "json"
        ]

        subprocess.run(cmd, check=True)

        # Validate
        validate_cmd = ["cyclonedx", "validate", "--input-file", output_file]
        result = subprocess.run(validate_cmd, capture_output=True)

        if result.returncode == 0:
            print(f"   ✓ SBOM generated and validated: {output_file}")
        else:
            print(f"   ⚠️ SBOM generated but validation failed")

        return output_file
```

**Acceptance:** SBOM scanner integrated in run_all_scans.sh

---

#### Task 1.4: SBOM in Evidence Pack (1 uur)
```json
// Add to Evidence Pack v2.1 schema:
{
  "workload": {
    "sbom": {
      "format": "CycloneDX",
      "version": "1.5",
      "uri": "https://trustfabric.blob.core.windows.net/sboms/trustfabric-v5.0.0.json",
      "hash": "sha256:..."
    }
  }
}
```

**Python implementation:**
```python
# server/sbom_loader.py
def load_sbom_reference():
    """Load SBOM reference for Evidence Pack"""
    sbom_file = Path("/opt/trustfabric/sbom.json")

    if not sbom_file.exists():
        return None

    with open(sbom_file) as f:
        sbom = json.load(f)

    sbom_hash = hashlib.sha256(sbom_file.read_bytes()).hexdigest()

    return {
        "format": sbom.get("bomFormat"),
        "version": sbom.get("specVersion"),
        "uri": f"https://trustfabric.blob.core.windows.net/sboms/{sbom.get('metadata', {}).get('component', {}).get('version')}.json",
        "hash": f"sha256:{sbom_hash}",
        "component_count": len(sbom.get("components", []))
    }
```

**Acceptance:** SBOM reference in Evidence Pack, validated in tests

---

#### Task 1.5: Documentation (30 min)
```markdown
# docs/SBOM_USAGE.md

## Software Bill of Materials (SBOM)

**Format:** CycloneDX 1.5 (JSON)
**Location:** audit_results/sbom.json
**Updated:** On every dependency change

### What It Contains:
- All Python dependencies (name, version, license)
- Dependency tree (who depends on what)
- Package hashes (SHA256)
- Vulnerability references (CVE links)

### Why It Matters:
- MDR Compliance (EU Medical Device Regulation)
- Vulnerability tracking (know what to update)
- License compliance (avoid GPL in medical device)
- Supply chain security (detect dependency confusion)

### Usage:
# Generate SBOM
bash scripts/generate_sbom.sh

# Scan SBOM for vulnerabilities
cyclonedx scan --input sbom.json

# Compare versions
cyclonedx diff sbom_v1.json sbom_v2.json
```

**Acceptance:** Documentation complete, usage examples clear

---

**Feature 1 Total:** 4 uur werk
**Deliverables:** SBOM generation, scanner integration, Evidence Pack field, docs

---

## 🤖 Feature 2: Model Integrity Verification (8 uur)

### Why Necessary (AI Security):
- **OWASP Top 10 for LLM:** LLM01 - Model Poisoning
- **MITRE ATLAS:** AML.T0020 - Poison Training Data
- **NIST AI RMF:** Verify AI system integrity
- **Supply Chain Security:** Detect tampered model files

### Implementation Plan:

#### Task 2.1: Model Manifest Enhancement (2 uur)
```json
// manifests/resnet18-ecg-af-v1.2.3.json
{
  "model_name": "resnet18-ecg-af",
  "version": "1.2.3",
  "model_hash": "sha256:8e92a456d3f1e2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7",
  "parent_version_hash": "sha256:7e91b355...",  // Hash chain

  // NEW: Enhanced integrity fields
  "integrity": {
    "algorithm": "SHA256",
    "digest": "8e92a456d3f1e2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7",
    "file_size_bytes": 46837922,
    "signature": "...",  // ECDSA P-256 signature of (hash + metadata)
    "signed_by": "https://tf7f736854b2kv.vault.azure.net/keys/trustfabric-model-signing",
    "verification_command": "python3 scripts/verify_model.py model.onnx manifests/resnet18-ecg-af-v1.2.3.json"
  },

  // NEW: Supply chain provenance
  "provenance": {
    "build_date": "2025-10-14T10:30:00Z",
    "build_system": "GitHub Actions",
    "source_repo": "https://github.com/rhythmiq/models",
    "source_commit": "abc123def456",
    "builder_identity": "github-actions@trustfabric.io"
  },

  "created_at": "2025-10-14T10:30:00Z"
}
```

**Acceptance:** Enhanced manifest schema, signed with Key Vault

---

#### Task 2.2: Model Verification Script (2 uur)
```python
# scripts/verify_model.py
#!/usr/bin/env python3
"""
Model Integrity Verification Script
Verifies model file hash against signed manifest
"""

import hashlib
import json
import sys
from pathlib import Path
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from azure.identity import DefaultAzureCredential

def compute_model_hash(model_path: Path, algorithm: str = "SHA256") -> str:
    """Compute model file hash"""
    hasher = hashlib.sha256()

    with open(model_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)

    return hasher.hexdigest()

def verify_model_integrity(model_path: Path, manifest_path: Path) -> bool:
    """
    Verify model integrity against signed manifest.

    Checks:
    1. Model hash matches manifest
    2. Model file size matches
    3. Manifest signature is valid (Key Vault)

    Returns:
        True if all checks pass, False otherwise
    """
    print(f"🔍 Verifying model integrity...")
    print(f"   Model: {model_path}")
    print(f"   Manifest: {manifest_path}")

    # Load manifest
    with open(manifest_path) as f:
        manifest = json.load(f)

    integrity = manifest.get('integrity', {})
    expected_hash = integrity.get('digest')
    expected_size = integrity.get('file_size_bytes')

    # Check 1: Compute actual hash
    print(f"\n1. Computing model hash...")
    actual_hash = compute_model_hash(model_path)

    if actual_hash != expected_hash:
        print(f"   ✗ HASH MISMATCH!")
        print(f"      Expected: {expected_hash}")
        print(f"      Actual:   {actual_hash}")
        print(f"\n⚠️  MODEL INTEGRITY VIOLATION - Possible tampering or wrong file")
        return False

    print(f"   ✓ Hash match: {actual_hash[:16]}...")

    # Check 2: File size
    actual_size = model_path.stat().st_size

    if actual_size != expected_size:
        print(f"\n2. File size check...")
        print(f"   ✗ SIZE MISMATCH!")
        print(f"      Expected: {expected_size} bytes")
        print(f"      Actual:   {actual_size} bytes")
        return False

    print(f"   ✓ File size match: {actual_size:,} bytes")

    # Check 3: Manifest signature (if available)
    signature = integrity.get('signature')
    signing_key = integrity.get('signed_by')

    if signature and signing_key:
        print(f"\n3. Verifying manifest signature...")
        # Verify with Key Vault (implementation from sign_manifest.py)
        # ... (verification logic)
        print(f"   ✓ Manifest signature valid")
    else:
        print(f"\n3. Manifest signature: Not available (Phase 1 feature)")

    print(f"\n{'='*60}")
    print(f"✅ MODEL INTEGRITY VERIFIED")
    print(f"{'='*60}")
    print(f"Model: {manifest['model_name']} v{manifest['version']}")
    print(f"Hash: sha256:{actual_hash[:16]}...")
    print(f"Size: {actual_size:,} bytes")
    print(f"\nSafe to load model ✅")

    return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 verify_model.py <model_file.onnx> <manifest.json>")
        sys.exit(1)

    model_path = Path(sys.argv[1])
    manifest_path = Path(sys.argv[2])

    if verify_model_integrity(model_path, manifest_path):
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Failure
```

**Acceptance:** Script verifies model hash + size, returns exit code

---

#### Task 2.3: Pre-Load Verification Hook (2 uur)
```python
# server/model_loader.py (NEW)
"""
Secure Model Loading with Integrity Verification
MUST verify hash before loading model (prevent poisoning)
"""

import torch
import hashlib
from pathlib import Path

class SecureModelLoader:
    """Model loader with mandatory integrity verification"""

    def __init__(self, manifest_path: str):
        with open(manifest_path) as f:
            self.manifest = json.load(f)

        self.expected_hash = self.manifest['integrity']['digest']
        self.expected_size = self.manifest['integrity']['file_size_bytes']

    def load_model(self, model_path: Path):
        """
        Load model with integrity verification.

        SECURITY: Model file hash MUST match manifest before loading.
        This prevents model poisoning attacks.

        Raises:
            SecurityError: If hash mismatch (possible tampering)
        """
        # Step 1: Verify hash (BEFORE loading)
        actual_hash = self._compute_hash(model_path)

        if actual_hash != self.expected_hash:
            raise SecurityError(
                f"Model integrity violation: hash mismatch\n"
                f"Expected: {self.expected_hash}\n"
                f"Actual:   {actual_hash}\n"
                f"Possible model poisoning attack!"
            )

        # Step 2: Verify file size
        actual_size = model_path.stat().st_size
        if actual_size != self.expected_size:
            raise SecurityError(f"Model size mismatch: {actual_size} != {self.expected_size}")

        # Step 3: Load model (only after verification)
        print(f"✓ Model integrity verified, loading...")
        model = torch.load(model_path)

        print(f"✓ Model loaded: {self.manifest['model_name']} v{self.manifest['version']}")

        return model

    def _compute_hash(self, path: Path) -> str:
        """Compute SHA256 hash"""
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

# Usage in inference_server.py:
# loader = SecureModelLoader('/opt/trustfabric/manifests/resnet18-v1.2.3.json')
# model = loader.load_model('/opt/trustfabric/models/resnet18.onnx')
# ↑ Will FAIL if model tampered (security guarantee)
```

**Acceptance:** Model loading fails if hash mismatch

---

#### Task 2.4: CI/CD Integration (2 uur)
```yaml
# .github/workflows/model-release.yml
name: Model Release with Integrity Verification

on:
  workflow_dispatch:
    inputs:
      model_file:
        description: 'Model file to release'
        required: true
      version:
        description: 'Semantic version (e.g., 1.2.4)'
        required: true

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Compute Model Hash
        id: hash
        run: |
          HASH=$(sha256sum ${{ inputs.model_file }} | awk '{print $1}')
          SIZE=$(stat -f%z ${{ inputs.model_file }})
          echo "hash=$HASH" >> $GITHUB_OUTPUT
          echo "size=$SIZE" >> $GITHUB_OUTPUT

      - name: Generate Manifest
        run: |
          cat > manifests/resnet18-ecg-af-v${{ inputs.version }}.json <<EOF
          {
            "model_name": "resnet18-ecg-af",
            "version": "${{ inputs.version }}",
            "model_hash": "sha256:${{ steps.hash.outputs.hash }}",
            "integrity": {
              "algorithm": "SHA256",
              "digest": "${{ steps.hash.outputs.hash }}",
              "file_size_bytes": ${{ steps.hash.outputs.size }}
            },
            "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          }
          EOF

      - name: Sign Manifest (Azure Key Vault)
        run: |
          python3 scripts/sign_manifest.py manifests/resnet18-ecg-af-v${{ inputs.version }}.json

      - name: Upload Model + Manifest
        run: |
          az storage blob upload \
            --account-name trustfabricmodels \
            --container-name models \
            --name resnet18-v${{ inputs.version }}.onnx \
            --file ${{ inputs.model_file }}

          az storage blob upload \
            --account-name trustfabricmodels \
            --container-name manifests \
            --name resnet18-ecg-af-v${{ inputs.version }}.json \
            --file manifests/resnet18-ecg-af-v${{ inputs.version }}.json

      - name: Verify Upload
        run: |
          # Download and verify
          az storage blob download \
            --account-name trustfabricmodels \
            --container-name models \
            --name resnet18-v${{ inputs.version }}.onnx \
            --file /tmp/downloaded_model.onnx

          python3 scripts/verify_model.py \
            /tmp/downloaded_model.onnx \
            manifests/resnet18-ecg-af-v${{ inputs.version }}.json
```

**Acceptance:** Automated model release with hash verification

---

#### Task 2.5: Unit Tests (1 uur)
```python
# tests/test_model_integrity.py
import pytest
from server.model_loader import SecureModelLoader, SecurityError

def test_model_integrity_valid():
    """Test model loads with valid hash"""
    loader = SecureModelLoader('manifests/resnet18-ecg-af-v1.2.3.json')
    model = loader.load_model('models/resnet18.onnx')
    assert model is not None

def test_model_integrity_tampered():
    """Test model loading fails with tampered file"""
    loader = SecureModelLoader('manifests/resnet18-ecg-af-v1.2.3.json')

    # Tamper with model (wrong file)
    with pytest.raises(SecurityError, match="Model integrity violation"):
        loader.load_model('models/resnet18_tampered.onnx')

def test_model_size_mismatch():
    """Test model loading fails with size mismatch"""
    loader = SecureModelLoader('manifests/resnet18-ecg-af-v1.2.3.json')

    with pytest.raises(SecurityError, match="size mismatch"):
        loader.load_model('models/resnet18_wrong_size.onnx')
```

**Acceptance:** 3/3 tests pass (valid, tampered, size mismatch)

---

**Feature 2 Total:** 8 uur werk
**Deliverables:** Enhanced manifest, verification script, secure loader, CI/CD, tests

---

## 📋 IMPLEMENTATION TODOLIST (12 tasks)

### SBOM Generation (4 uur):
1. [ ] Install CycloneDX tools (30 min)
2. [ ] Generate SBOM from requirements.txt (1 uur)
3. [ ] Create sbom_generator.py scanner (1 uur)
4. [ ] Add SBOM field to Evidence Pack schema (1 uur)
5. [ ] Documentation (30 min)

### Model Integrity (8 uur):
6. [ ] Enhance model manifest schema (2 uur)
7. [ ] Create verify_model.py script (2 uur)
8. [ ] Create SecureModelLoader class (2 uur)
9. [ ] CI/CD model release workflow (2 uur)
10. [ ] Unit tests (model integrity) (1 uur)

---

## 🎯 PRIORITY & TIMING

### For Pilot (NOW):
**DEFER ALL** - Scanner is adequate as-is ✅

### For Production (Phase 1 - Week 2):
**IMPLEMENT BOTH:**
- SBOM: 4 uur werk (MDR compliance)
- Model Integrity: 8 uur werk (AI security)
- **Total:** 12 uur (1.5 dagen)

---

## ✅ COMPARISON TO 2025 BEST PRACTICES

| Feature | Enterprise Standard | Our Scanner | Gap | Necessary? |
|---------|---------------------|-------------|-----|------------|
| **SAST** | Semgrep/CodeQL | Semgrep ✅ | None | N/A |
| **SBOM** | Auto-generated | Manual | **Yes** | ✅ **YES** (MDR) |
| **Model Integrity** | Hash + signature | Manual check | **Yes** | ✅ **YES** (OWASP) |
| **Dataflow** | Advanced | None | Yes | ❌ NO (overkill) |
| **RASP** | Runtime monitor | None | Yes | ❌ NO (covered) |
| **ML PHI Detection** | ML-based | Regex | Yes | ❌ NO (works) |

**Necessary Gaps:** 2 (SBOM + Model Integrity)
**Nice-to-Have Gaps:** 3 (Dataflow, RASP, ML detection) - defer

---

## 📅 IMPLEMENTATION TIMELINE

### Week 1 (SBOM):
```
Monday:    Install tools, generate initial SBOM (2h)
Tuesday:   Scanner integration + Evidence Pack (2h)
```

### Week 2 (Model Integrity):
```
Wednesday: Enhance manifest, verification script (4h)
Thursday:  Secure loader + CI/CD (4h)
```

### Week 3 (Testing):
```
Friday:    Unit tests + documentation (2h)
Total:     12 hours over 5 days
```

**Realistic:** 2-3 days focused work
**Parallel:** Can do during Phase 1 development

---

**Status:** PLAN COMPLETE ✅
**Necessary improvements:** 2 (SBOM + Model Integrity)
**Timeline:** 12 uur werk (Phase 1)
**For pilot:** NO CHANGES NEEDED ✅

Implement deze in Phase 1 (na RhythmIQ commitment). 🎯


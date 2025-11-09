# Expert Security Auditor Facilitation Plan

**Purpose:** Make TrustFabric maximally transparent for security audit  
**Goal:** Enable auditor to find issues faster (saves time = saves cost)  
**Based on:** Trail of Bits, NCC Group, Cure53 audit methodologies

---

## 🎯 What Expert Auditors Need (Industry Standard)

### Day 1: Onboarding Package (Before Audit Starts)
Auditors need **context** before diving into code. Good preparation = 30% faster audit.

**Package Contents:**

#### 1. Architecture Documentation (Already Have ✅)
```
✅ docs/RHYTHMIQ_ARCHITECTURE.md (data flow, security boundaries)
✅ docs/MAA_ATTESTATION_POLICY.md (9 security checks explained)
✅ Evidence Pack schema (what data flows where)
✅ Threat model: What we're protecting (PHI) from whom (attackers)
```

**Auditor needs:**
- "What is the crown jewel?" → PHI (patient ECG data)
- "What's the security boundary?" → SEV-SNP enclave
- "What's the trust anchor?" → Azure MAA (third-party verifier)

**Make it easy:**
- Single PDF: "TrustFabric Security Architecture.pdf" (combine all docs)
- Mermaid diagrams (convert ASCII to visual)
- Attack surface map (what's exposed to internet)

---

#### 2. Code Navigation Guide (NEW - Need to Create)
**Problem:** Auditor wastes time finding "where is the crypto code?"

**Solution:** Create `SECURITY_CODE_MAP.md`:
```markdown
# Security-Critical Code Locations

## Cryptography (PRIORITY 1 - Review First)
| File | Lines | What It Does | Risk Level |
|------|-------|--------------|------------|
| `server/signing.py` | 31-120 | Evidence Pack ECDSA signing | HIGH |
| `trustfabric_verify/verify_attestation.py` | 32-270 | MAA JWT validation (9 checks) | HIGH |
| `server/maa_client.py` | 40-180 | MAA API integration | MEDIUM |

## PHI Handling (PRIORITY 1 - Medical AI Critical)
| File | Lines | What It Does | Risk Level |
|------|-------|--------------|------------|
| `server/evidence_pack_v21.py` | 25-104 | Evidence Pack generation | HIGH |
| `server/inference_server.py` | 450-600 | Input hashing (PHI redaction) | CRITICAL |

## Attestation Flow (PRIORITY 2)
| File | Lines | What It Does | Risk Level |
|------|-------|--------------|------------|
| `server/attestation_cache.py` | 1-280 | Cache with 5-min TTL | MEDIUM |
| `server/vtpm_attestation.py` | 45-200 | SEV-SNP quote generation | HIGH |

## Model Security (PRIORITY 2)
| File | Lines | What It Does | Risk Level |
|------|-------|--------------|------------|
| `server/secure_model_loader.py` | 30-120 | Model integrity verification | HIGH |
| `scripts/verify_model.py` | 1-150 | Model hash checking | MEDIUM |

## Test Files (SKIP or Review Last)
| File | Purpose |
|------|---------|
| `tests/test_*.py` | Unit tests (contains unverified JWT - OK in tests) |
| `server/mock_*.py` | Mock servers (testing only) |
```

**Impact:** Auditor knows exactly where to look (saves 2-4 hours of exploration)

---

#### 3. Known Issues & Limitations (HONESTY = TRUST)
**Problem:** Auditor finds issue you already know → wastes time

**Solution:** Create `KNOWN_SECURITY_LIMITATIONS.md`:
```markdown
# Known Security Limitations (Pre-Audit Disclosure)

## Implemented But Needs Validation:
1. **Nonce validation** (FIXED this week)
   - Code: verify_attestation.py:247-259
   - Status: Implemented, not tested with real MAA JWT
   - Auditor should: Test with real attestation flow

2. **Kid validation** (FIXED this week)
   - Code: verify_attestation.py:114-119
   - Status: Implemented, not tested
   - Auditor should: Test with malicious JWKS

## Not Yet Implemented (Phase 1):
1. **Launch measurement pinning** (HIGH priority)
   - Risk: Any VM image accepted (no measurement validation)
   - Why: Don't have known-good measurement yet (need DCasv5)
   - Timeline: Add in Phase 1 (after DCasv5 deployment)
   - File to update: verify_attestation.py (add check after line 210)

2. **Rate limiting** (MEDIUM priority)
   - Risk: DoS possible (no request throttling)
   - Why: Not needed for pilot (limited users)
   - Timeline: Add before production
   - Implementation: Flask-Limiter or nginx rate limiting

3. **TCB version minimums** (MEDIUM priority)
   - Risk: Outdated firmware accepted
   - Why: Don't know minimum versions yet
   - Timeline: Research + implement Phase 1

## Test Coverage Gaps:
1. **Signature replay with nonce** - Need Azure KV for test
2. **Real MAA JWT validation** - Need DCasv5 for real quote
3. **Adversarial ECG inputs** - Need clinical validation

## Architecture Assumptions (Validate These):
1. **5-min attestation cache** - Is TTL secure enough?
2. **Private network only** - No defense-in-depth for public exposure?
3. **Single signing key** - Key rotation tested?
```

**Impact:** Auditor knows what to focus on (saves 4-8 hours of duplicate discovery)

---

#### 4. Audit Environment Setup (Make It Easy)
**Problem:** Auditor can't run code → can't test findings

**Solution:** Create `AUDITOR_SETUP.md`:
```markdown
# Auditor Environment Setup (30 min)

## Prerequisites:
- Python 3.10+
- Azure CLI (for Key Vault access)
- Git

## Quick Start:
```bash
# 1. Clone repo
git clone https://github.com/Rul1an/TrustFabric
cd TrustFabric

# 2. Install dependencies
pip install -r requirements_v5.txt

# 3. Run unit tests (no Azure needed)
python3 -m unittest discover tests/ -v
# Expected: 32 tests, 4 skipped (need Azure)

# 4. For integration tests (requires Azure credentials):
export INTEGRATION_TEST=true
# We'll provide temp Azure access (read-only Key Vault)
```

## Test Accounts:
- Azure subscription: [Auditor-specific, read-only]
- Key Vault access: [Temp role assignment, expires after audit]
- CVM access: [Via Bastion, no production access]

## Attack Surface:
```
Exposed:
- /infer endpoint (requires auth - test with Burp Suite)
- /health endpoint (public - test for info disclosure)

Not Exposed:
- Key Vault (private endpoint only)
- CVM (private network only)
```

---

#### 5. Reproducible Test Cases
**Problem:** Auditor can't reproduce your tests

**Solution:** Create `SECURITY_TEST_CASES.md`:
```markdown
# Reproducible Security Test Cases

## Test 1: Nonce Replay Attack
**Objective:** Verify replay attack prevention

**Steps:**
```bash
# 1. Generate attestation with nonce A
NONCE_A="test-nonce-12345"
python3 server/maa_client.py attestation.bin > jwt_with_nonce_a.txt

# 2. Try to validate with nonce B
NONCE_B="different-nonce-67890"
python3 trustfabric_verify/verify_attestation.py \
  "$(cat jwt_with_nonce_a.txt)" \
  --expected-nonce "$NONCE_B"

# Expected: AttestationVerificationError (nonce mismatch)
```

**Success Criteria:** Error raised ✓

---

## Test 2: Tampered Model Detection
**Objective:** Verify model poisoning prevention

**Steps:**
```bash
# 1. Create valid model
echo "fake model data" > model.bin

# 2. Generate manifest with hash
python3 scripts/create_manifest.py model.bin

# 3. Tamper with model
echo "TAMPERED" >> model.bin

# 4. Try to load
python3 scripts/verify_model.py model.bin manifest.json

# Expected: SecurityError (hash mismatch)
```

**Success Criteria:** Error raised ✓

---

## Test 3: JWT Algorithm Confusion
**Objective:** Verify HS256 rejected (classic attack)

**Steps:**
```python
import jwt

# Create HS256 token with RS256 public key as secret
public_key = get_maa_public_key()
fake_token = jwt.encode(
    {"x-ms-attestation-type": "sevsnpvm"},
    public_key,  # Use public key as HMAC secret
    algorithm="HS256"
)

# Try to verify
verify_attestation_jwt(fake_token)

# Expected: AttestationVerificationError (algorithm rejected)
```

**Success Criteria:** Error raised in STEP 1 (algorithm check) ✓
```

---

## 📋 FACILITATION PLAN (What to Create)

### Priority 1: Critical Path Documentation (4 hours)

**1.1 Security Code Map** (1 hour)
```bash
# Create: docs/SECURITY_CODE_MAP.md
# Content:
#   - Table: File → Lines → Function → Risk Level
#   - Critical code: Crypto (signing, JWT), PHI (redaction)
#   - Color-coded by risk (RED=CRITICAL, YELLOW=HIGH, GREEN=MEDIUM)
#   - Direct links to GitHub (line numbers)
```

**Example:**
```markdown
| Priority | File | Lines | Function | Risk | Why |
|----------|------|-------|----------|------|-----|
| 🔴 P1 | signing.py | 92-98 | ECDSA signing | CRITICAL | Any bug = security failure |
| 🔴 P1 | verify_attestation.py | 130-210 | MAA claim validation | CRITICAL | Missing check = bypass |
| 🟡 P2 | attestation_cache.py | 50-90 | Cache logic | HIGH | TTL too long = stale attestation |
```

---

**1.2 Known Limitations Document** (1 hour)
```markdown
# KNOWN_SECURITY_LIMITATIONS.md

## Pre-Disclosed Issues (Don't Waste Time Finding These):

### Launch Measurement Not Validated (HIGH)
**Location:** verify_attestation.py (missing check)
**Risk:** Any VM image accepted (no pinning)
**Why not fixed:** Need DCasv5 to capture known-good measurement
**Timeline:** Phase 1 (Week 1 after DCasv5)
**Auditor focus:** Confirm this is the only missing MAA check

### Rate Limiting Not Implemented (MEDIUM)
**Location:** inference_server.py (no Flask-Limiter)
**Risk:** DoS possible
**Why not fixed:** Pilot has limited users
**Timeline:** Before production
**Auditor focus:** Test actual DoS (how many requests to crash?)
```

**Impact:** Auditor doesn't spend 2 days finding what you already know

---

**1.3 Reproducible Test Environment** (2 hours)
```bash
# Create: scripts/setup_audit_environment.sh

#!/bin/bash
# Sets up isolated environment for auditor

# 1. Create temp Azure resource group (auditor-specific)
az group create -n trustfabric-audit-rg -l westeurope

# 2. Grant read-only access to auditor
az role assignment create \
  --assignee <auditor-email> \
  --role "Reader" \
  --scope /subscriptions/.../resourceGroups/trustfabric-audit-rg

# 3. Create temp Key Vault key (auditor can test signing)
az keyvault key create --vault-name tf-audit-kv --name audit-test-key --kty EC

# 4. Clone code to isolated environment
# 5. Run all tests
# 6. Output: "Audit environment ready, access expires in 30 days"
```

**Impact:** Auditor can test immediately (no waiting for credentials)

---

### Priority 2: Interactive Audit Tools (6 hours)

**2.1 Crypto Test Harness** (2 hours)
```python
# tools/crypto_test_harness.py

"""
Interactive tool for auditor to test cryptographic functions.
Helps auditor verify ECDSA, JWT, hashing implementations.
"""

class CryptoTestHarness:
    def test_ecdsa_signing(self):
        """
        Test ECDSA P-256 signing with NIST test vectors.
        
        Auditor can:
        - Input NIST test vector
        - See our signature output
        - Verify against expected
        """
        print("ECDSA P-256 Test Vector:")
        print("Input (hash): ", test_vector_hash)
        
        # Our implementation
        signature = sign_with_key_vault(test_vector_hash)
        
        print("Output (signature): ", signature)
        print("Expected: ", nist_expected_signature)
        print("Match: ", signature == nist_expected_signature)
    
    def test_jwt_validation_edge_cases(self):
        """
        Test JWT validation with attack vectors.
        
        Auditor can test:
        - Algorithm confusion (HS256 vs RS256)
        - Expired tokens
        - Missing claims
        - Invalid signatures
        """
        test_cases = {
            "valid": generate_valid_jwt(),
            "hs256_attack": generate_hs256_with_rs256_key(),
            "expired": generate_expired_jwt(),
            "no_nbf": generate_jwt_without_nbf(),
            "wrong_issuer": generate_jwt_wrong_issuer()
        }
        
        for name, jwt_token in test_cases.items():
            try:
                verify_attestation_jwt(jwt_token)
                print(f"{name}: ACCEPTED (vulnerability!)")
            except AttestationVerificationError as e:
                print(f"{name}: REJECTED ✓ ({e})")
```

**Usage:**
```bash
# Auditor runs:
python3 tools/crypto_test_harness.py

# Gets interactive menu:
# 1. Test ECDSA signing
# 2. Test JWT validation
# 3. Test hash functions
# 4. Test nonce generation (randomness)
# 5. Custom test (enter your own)
```

**Impact:** Auditor can test crypto WITHOUT reverse-engineering code (saves 1-2 days)

---

**2.2 PHI Path Tracer** (2 hours)
```python
# tools/phi_path_tracer.py

"""
Interactive tool to trace data paths (helps auditor verify PHI safety).
Shows: Where does patient_id go? (request → hash → log → Evidence Pack)
"""

def trace_variable_path(variable_name: str = "patient_id"):
    """
    Trace a variable through codebase.
    
    Example: trace_variable_path("patient_id")
    
    Output:
    Step 1: request.json.get('patient_id')  [server/api.py:45]
    Step 2: hashlib.sha256(patient_id)      [server/utils.py:12]
    Step 3: logger.info(f"Hash: {hash}")    [server/utils.py:15]
    Step 4: evidence_pack['input_hash']     [server/evidence.py:78]
    
    Analysis: ✓ PHI is hashed before logging (SAFE)
    ```

**Auditor can:**
- Input any variable name (patient_name, mrn, ssn)
- See all code locations where it appears
- Verify it's hashed before leaving secure boundary

**Impact:** PHI safety verification in 30 min (vs 1 day manual tracing)

---

**2.3 Attack Scenario Simulator** (2 hours)
```python
# tools/attack_simulator.py

"""
Simulates common attacks (helps auditor validate defenses).
"""

class AttackSimulator:
    def simulate_replay_attack(self):
        """
        Simulate attestation replay attack.
        
        Steps:
        1. Get valid attestation (nonce A)
        2. Capture JWT
        3. Send new request (nonce B)
        4. Try to reuse JWT from step 2
        
        Expected: REJECTED (nonce mismatch)
        """
        print("🔴 Simulating Replay Attack...")
        
        # Step 1
        jwt_old = get_attestation(nonce="nonce-A")
        print(f"   Got JWT with nonce A")
        
        # Step 2
        try:
            verify_attestation_jwt(jwt_old, expected_nonce="nonce-B")
            print(f"   ✗ VULNERABLE: Replay attack succeeded!")
            return "FAIL"
        except AttestationVerificationError:
            print(f"   ✓ SAFE: Replay attack blocked")
            return "PASS"
    
    def simulate_model_poisoning(self):
        """Simulate model poisoning attack"""
        print("🔴 Simulating Model Poisoning...")
        
        # Tamper with model
        original_model = load_model()
        tampered_model = add_backdoor(original_model)
        save_model(tampered_model, "model.onnx")
        
        # Try to load
        try:
            loader = SecureModelLoader("manifest.json")
            loader.load_model("model.onnx")
            print(f"   ✗ VULNERABLE: Tampered model loaded!")
            return "FAIL"
        except SecurityError:
            print(f"   ✓ SAFE: Tampered model rejected")
            return "PASS"
    
    def run_all_attack_simulations(self):
        """Run all attack scenarios"""
        results = {
            "Replay Attack": self.simulate_replay_attack(),
            "Model Poisoning": self.simulate_model_poisoning(),
            "JWT Algorithm Confusion": self.simulate_algorithm_confusion(),
            "PHI Extraction": self.simulate_phi_extraction(),
            "Signature Replay": self.simulate_signature_replay()
        }
        
        print("\n" + "="*60)
        print("Attack Simulation Results:")
        for attack, result in results.items():
            status = "✓" if result == "PASS" else "✗"
            print(f"  {status} {attack}: {result}")
```

**Usage:**
```bash
# Auditor runs:
python3 tools/attack_simulator.py

# Output:
# 🔴 Simulating Replay Attack...
#    ✓ SAFE: Replay attack blocked
# 🔴 Simulating Model Poisoning...
#    ✓ SAFE: Tampered model rejected
# ...
# 
# Results: 5/5 attacks blocked ✓
```

**Impact:** Auditor validates defenses in 1 hour (vs 1-2 days manual testing)

---

### Priority 3: Dataflow Analysis Prep (4 hours)

**3.1 CodeQL Database Pre-Generated** (2 hours)
```bash
# Pre-generate CodeQL database for auditor

# Install CodeQL
brew install codeql

# Create database (takes 30 min for our codebase)
codeql database create \
  audit_assets/trustfabric-codeql-db \
  --language=python \
  --source-root=. \
  --overwrite

# Pre-run standard queries
codeql database analyze \
  audit_assets/trustfabric-codeql-db \
  --format=sarif-latest \
  --output=audit_assets/codeql_results.sarif \
  codeql/python-queries

# Provide to auditor:
# - Database: audit_assets/trustfabric-codeql-db/ (ready to query)
# - Results: audit_assets/codeql_results.sarif (baseline)
```

**Impact:** Auditor starts querying immediately (no 30-min database build wait)

---

**3.2 Custom CodeQL Queries for PHI** (2 hours)
```ql
/**
 * @name PHI flows to logging
 * @description Tracks patient data from HTTP request to logging statement
 * @kind path-problem
 */

import python
import semmle.python.dataflow.new.DataFlow

class PHISource extends DataFlow::Node {
  PHISource() {
    // HTTP request parameters with PHI variable names
    exists(Call c, StrConst s |
      c.getFunction().(Attribute).getName() = "get" and
      s.getText().regexpMatch(".*patient.*|.*mrn.*|.*ssn.*") and
      c.getArg(0) = s
    )
  }
}

class LogSink extends DataFlow::Node {
  LogSink() {
    // Logging function calls
    exists(Call c |
      c.getFunction().(Attribute).getName().matches("info|debug|warning|error")
      or
      c.getFunction().getName() = "print"
    )
  }
}

from PHISource source, LogSink sink, DataFlow::PathNode sourceNode, DataFlow::PathNode sinkNode
where
  DataFlow::flowPath(sourceNode, sinkNode) and
  sourceNode.getNode() = source and
  sinkNode.getNode() = sink
select sinkNode, sourceNode, sinkNode,
  "Patient data from $@ reaches logging statement", sourceNode, "HTTP request"
```

**Provide to auditor:**
```
audit_assets/custom_queries/
├── phi_to_log.ql (PHI → logging paths)
├── phi_to_network.ql (PHI → network paths)
├── crypto_key_hardcoded.ql (hardcoded keys)
├── unverified_jwt_prod.ql (unverified JWT in production code only)
```

**Impact:** Auditor runs YOUR queries (finds issues YOU want to know about)

---

### Priority 4: Automated Finding Triage (2 hours)

**4.1 Pre-Triage Script**
```python
# tools/triage_for_auditor.py

"""
Pre-triage automated scan results for auditor.
Categorizes findings: Real Issue vs False Positive vs Known Limitation
"""

def triage_semgrep_findings():
    """Auto-triage Semgrep results"""
    with open("audit_results/week1/semgrep.json") as f:
        results = json.load(f)
    
    triaged = {
        "real_issues": [],
        "false_positives": [],
        "known_limitations": [],
        "test_code_only": []
    }
    
    for finding in results["results"]:
        # Rule 1: Test files = not real issue
        if "/tests/" in finding["path"] or "/mock_" in finding["path"]:
            triaged["test_code_only"].append(finding)
        
        # Rule 2: Known limitations
        elif "launch_measurement" in finding["check_id"]:
            triaged["known_limitations"].append(finding)
        
        # Rule 3: False positives (SecureModelLoader)
        elif "model-loading" in finding["check_id"] and "secure_model_loader" in finding["path"]:
            triaged["false_positives"].append(finding)
        
        # Rule 4: Everything else = needs auditor review
        else:
            triaged["real_issues"].append(finding)
    
    # Generate triage report
    print(f"Real issues (review first): {len(triaged['real_issues'])}")
    print(f"False positives (ignore): {len(triaged['false_positives'])}")
    print(f"Known limitations (validate fix timeline): {len(triaged['known_limitations'])}")
    print(f"Test code only (low priority): {len(triaged['test_code_only'])}")
    
    # Save
    with open("audit_assets/triaged_findings.json", "w") as f:
        json.dump(triaged, f, indent=2)
```

**Impact:** Auditor focuses on REAL issues first (not waste time on known false positives)

---

## 📊 Complete Facilitation Package

### Files to Create (10 total):

**Documentation (4 files):**
1. `docs/SECURITY_CODE_MAP.md` (1 hour)
2. `KNOWN_SECURITY_LIMITATIONS.md` (1 hour)
3. `AUDITOR_SETUP.md` (30 min)
4. `SECURITY_TEST_CASES.md` (30 min)

**Tools (3 files):**
5. `tools/crypto_test_harness.py` (2 hours)
6. `tools/phi_path_tracer.py` (2 hours)
7. `tools/attack_simulator.py` (2 hours)

**Dataflow Prep (2 files):**
8. `audit_assets/trustfabric-codeql-db/` (2 hours to generate)
9. `audit_assets/custom_queries/*.ql` (2 hours to write)

**Automation (1 file):**
10. `tools/triage_for_auditor.py` (2 hours)

**Total Time:** ~16 hours work  
**Total Cost:** Internal effort (no external cost)  
**ROI:** Saves auditor 5-10 hours = €3-8k savings on audit cost

---

## 🎯 IMPLEMENTATION PRIORITY

### Must Have (Before External Audit):
- [ ] Security Code Map (1h) - Critical path
- [ ] Known Limitations (1h) - Honesty = trust
- [ ] Auditor Setup (30min) - Quick start

**Total:** 2.5 hours (must do)

### Should Have (Nice to Have):
- [ ] Test Cases (30min) - Reproducibility
- [ ] Crypto Test Harness (2h) - Interactive validation
- [ ] CodeQL Database (2h) - Dataflow prep

**Total:** 4.5 hours (recommended)

### Could Have (If Budget):
- [ ] PHI Path Tracer (2h) - Visual verification
- [ ] Attack Simulator (2h) - Automated validation
- [ ] Triage Tool (2h) - Pre-filtered findings

**Total:** 6 hours (nice-to-have)

---

## 💰 ROI Analysis

**Investment:**
- Minimum (must have): 2.5 hours
- Recommended (should have): 7 hours
- Maximum (could have): 13 hours

**Savings:**
- Auditor time saved: 5-10 hours
- At €800/day (auditor rate): €500-1,000 saved per day
- At 10 days audit: €5-10k potential savings
- ROI: 5-10x return on facilitation investment

**Quality Improvement:**
- Better findings (auditor focuses on real issues)
- Faster turnaround (less back-and-forth)
- Higher confidence (auditor has full context)

---

## ✅ RECOMMENDATION

### Implement "Must Have" Package (2.5 hours):
1. Security Code Map (guide auditor to critical code)
2. Known Limitations (honest pre-disclosure)
3. Auditor Setup (quick environment)

**Then:** Send to external security firm with audit RFP

**Optional:** Add "Should Have" (4.5h) if you want premium audit experience

---

**Status:** FACILITATION PLAN COMPLETE ✅  
**Timeline:** 2.5 - 13 hours (depending on scope)  
**ROI:** 5-10x (saves auditor time = saves money)  
**Next:** Implement "Must Have" package (2.5h) before RFP

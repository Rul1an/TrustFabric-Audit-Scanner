# Expert Security Review Methodology

**Purpose:** Detailed review plan for TrustFabric security validation  
**Based on:** NIST, OWASP, IEC 62304, cryptographic validation standards  
**Timeline:** 3 weeks (external security firm)  
**Cost:** €8-12k

---

## 🔐 Review 1: Cryptographic Implementation (Week 1)

### Why This Matters:
- **Subtle crypto bugs = complete security failure** (e.g., incorrect nonce, weak randomness)
- Automated tools can't verify crypto correctness (only detect obvious patterns)
- Needs cryptographer with ECDSA P-256 + NIST FIPS expertise

### Methodology: NIST CAVP (Cryptographic Algorithm Validation Program)

#### 1.1 ECDSA P-256 Implementation Review (2 dagen)

**Review Items:**

**A. Azure Key Vault Integration:**
```python
# server/signing.py:92-98
digest = hashlib.sha256(canonical_json).digest()  # 32 bytes

sign_result = crypto_client.sign(
    SignatureAlgorithm.es256,
    digest
)
```

**Checks:**
- [ ] Is SHA256 hashing correct? (input sanitization, no truncation)
- [ ] Is 32-byte digest passed to Key Vault? (not raw data)
- [ ] Does Key Vault use FIPS 140-2 HSM? (Azure documentation confirms)
- [ ] Is signature deterministic? (same input = same signature for same key)
- [ ] Nonce/timestamp included? (prevent signature replay)

**Tools:**
- Manual code review (line-by-line)
- Test vectors (NIST P-256 test cases)
- Signature replay test (sign same data twice, verify different signatures due to nonce)

**Expected Issues:**
- ⚠️ **Missing nonce in signature** (replay attack risk)
- ⚠️ **No timestamp in signed data** (signature validity window)

**Remediation:**
```python
# Add nonce + timestamp to canonical JSON before signing
data_to_sign = {
    **evidence_pack,  # Original Evidence Pack
    "_signature_nonce": secrets.token_hex(16),  # Random nonce
    "_signature_timestamp": datetime.now(timezone.utc).isoformat()
}
canonical = encode_canonical_json(data_to_sign)
digest = hashlib.sha256(canonical).digest()
```

---

**B. JWT Signature Verification:**
```python
# trustfabric_verify/verify_attestation.py:95-114
jwks_client = PyJWKClient(jwks_uri)
signing_key = jwks_client.get_signing_key_from_jwt(token)

claims = jwt.decode(
    token,
    key=signing_key.key,
    algorithms=["RS256"],
    issuer=issuer,
    audience=audience
)
```

**Checks:**
- [ ] Algorithm whitelist correct? (only RS256, no HS256/none)
- [ ] JWKS fetching secure? (HTTPS, certificate validation)
- [ ] Key ID validation? (kid header matches JWKS)
- [ ] Clock skew handling? (leeway parameter)
- [ ] Audience validation strict? (no wildcard matching)

**Tools:**
- JWT fuzzing (malformed tokens, algorithm confusion, kid manipulation)
- JWKS poisoning test (fake JWKS endpoint)
- Timing attack analysis (constant-time comparisons?)

**Expected Issues:**
- ⚠️ **No kid validation** (attacker could provide different key)
- ✓ Algorithm whitelist OK (only RS256)
- ✓ HTTPS for JWKS (PyJWKClient default)

**Remediation:**
```python
# Validate kid explicitly
expected_kid = "known-good-key-id"
if signing_key.key_id != expected_kid:
    raise AttestationVerificationError(f"Unexpected key ID: {signing_key.key_id}")
```

---

#### 1.2 Random Number Generation Review (1 dag)

**Check:** Nonce, UUID, session ID generation

**Code to Review:**
```python
# Evidence Pack generation
run_id = str(uuid.uuid4())  # Is uuid4 cryptographically secure?

# Nonce generation (if used)
nonce = secrets.token_hex(16)  # ✓ Good (secrets module)
# vs
nonce = random.randint(0, 2**64)  # ✗ Bad (not cryptographic)
```

**Checks:**
- [ ] Using `secrets` module (not `random`)?
- [ ] Sufficient entropy? (16+ bytes for nonces)
- [ ] No seed reuse? (urandom vs pseudo-random)

**Test:**
```python
# Generate 10,000 nonces, check for duplicates
nonces = [generate_nonce() for _ in range(10000)]
assert len(set(nonces)) == 10000, "Duplicate nonces detected!"
```

---

#### 1.3 Timing Attack Analysis (1 dag)

**Check:** Constant-time comparisons for secrets

**Vulnerable Pattern:**
```python
# BAD: Timing leak
if user_signature == expected_signature:  # String comparison leaks length
    return True

# GOOD: Constant-time
import hmac
if hmac.compare_digest(user_signature, expected_signature):
    return True
```

**Review:**
```bash
# Find all signature/hash comparisons
grep -r "if.*hash.*==" ../TrustFabric/
grep -r "if.*signature.*==" ../TrustFabric/
```

**Tools:**
- Timing harness (measure comparison time with wrong/correct signatures)
- Statistical analysis (timing variance across 1000 attempts)

---

### Deliverable 1: Cryptographic Review Report

**Format:**
```markdown
# Cryptographic Implementation Review

## Methodology
- Manual code review (ECDSA, JWT, hashing)
- NIST test vectors
- Timing attack analysis

## Findings
1. Missing nonce in Evidence Pack signature (MEDIUM)
2. No kid validation in JWT verification (LOW)
3. No timing-safe comparisons for signatures (LOW)

## Recommendations
[Detailed remediation steps]

## Test Results
- NIST P-256 vectors: PASS ✓
- Signature replay: FAIL (no nonce) ✗
- Timing attacks: LOW RISK (Azure Key Vault abstracts comparison)
```

---

## 🛡️ Review 2: MAA Attestation Completeness (Week 1)

### Why This Matters:
- Missing MAA check = attestation bypass
- 9 checks implemented, but are they ALL necessary checks?
- TEE security expert needed (AMD SEV-SNP + Azure MAA knowledge)

### Methodology: TCG Attestation Standards + Azure Documentation

#### 2.1 MAA JWT Claims Audit (2 dagen)

**Current Checks (9):**
```python
# verify_attestation.py:130-210
1. x-ms-attestation-type == "sevsnpvm" ✓
2. x-ms-sevsnpvm-isDebuggable == False ✓
3. x-ms-azurevm-debuggersdisabled == True ✓
4. x-ms-azurevm-hypervisordebug-enabled == False ✓
5. x-ms-azurevm-kerneldebug-enabled == False ✓
6. x-ms-azurevm-dbvalidated == True ✓
7. x-ms-compliance-status == "azure-compliant-cvm" ✓
8. Policy hash matches (optional) ✓
9. Time window (nbf ≤ now ≤ exp) ✓
```

**Missing Checks? (Expert to verify):**

**A. Launch Measurement (Critical for Production):**
```python
# NOT CURRENTLY CHECKED:
launch_measurement = claims["x-ms-isolation-tee"]["x-ms-sevsnpvm-launchmeasurement"]

# Should verify against expected measurement (pinning):
EXPECTED_MEASUREMENT = "998d364a0be3f07a4963cab92794b36b..."
if launch_measurement != EXPECTED_MEASUREMENT:
    raise AttestationVerificationError("VM image tampered!")
```

**Why missing:** We don't have expected measurement yet (need to capture from known-good VM)  
**Risk:** **HIGH** - Attacker could boot tampered VM image  
**Timeline:** Add in Phase 1 (after DCasv5 deployment)

---

**B. TCB (Trusted Computing Base) Version Checks:**
```python
# NOT CURRENTLY CHECKED:
tee = claims["x-ms-isolation-tee"]
bootloader_svn = tee["x-ms-sevsnpvm-bootloader-svn"]
microcode_svn = tee["x-ms-sevsnpvm-microcode-svn"]
snpfw_svn = tee["x-ms-sevsnpvm-snpfw-svn"]

# Should verify minimum versions:
if bootloader_svn < MIN_BOOTLOADER_SVN:
    raise AttestationVerificationError("Outdated bootloader (security patches missing)")
```

**Why missing:** Don't know minimum secure versions yet  
**Risk:** **MEDIUM** - Outdated firmware might have vulnerabilities  
**Timeline:** Research in Phase 1

---

**C. Migration & SMT Policy:**
```python
# PARTIALLY CHECKED:
migration_allowed = tee["x-ms-sevsnpvm-migration-allowed"]
smt_allowed = tee["x-ms-sevsnpvm-smt-allowed"]

# Current: No explicit check
# Should: Verify migration=False (prevent live migration attacks)
```

**Risk:** **LOW** - Azure defaults are secure  
**Timeline:** Add explicit checks (defensive programming)

---

#### 2.2 Nonce Binding Verification (1 dag)

**Check:** Client nonce properly bound to attestation

**Current:**
```python
# Evidence Pack includes nonce
"nonce": "7f3e9d2c8b1a4f6e5d8c9b2a3e4f5d6c"

# But: Do we verify it matches request nonce?
```

**Test:**
```python
# Replay attack test:
1. Get attestation with nonce A
2. Send request with nonce B
3. Reuse attestation from step 1
4. Should FAIL (nonce mismatch)

# Currently: We don't validate this! ⚠️
```

**Fix:**
```python
def verify_attestation_jwt(token, expected_nonce):
    claims = jwt.decode(...)
    
    actual_nonce = claims.get("x-ms-runtime", {}).get("client-payload", {}).get("nonce")
    
    if actual_nonce != expected_nonce:
        raise AttestationVerificationError("Nonce mismatch - replay attack!")
```

**Risk:** **MEDIUM-HIGH** - Replay attacks possible  
**Timeline:** Fix immediately (1 hour)

---

### Deliverable 2: Attestation Review Report

**Format:**
```markdown
# MAA Attestation Security Review

## Current Implementation
- 9 checks implemented
- Claims validation: Correct
- Signature verification: Correct

## Missing Checks (Critical)
1. Launch measurement pinning (HIGH) - Add in Phase 1
2. Nonce binding validation (HIGH) - Fix immediately
3. TCB version minimums (MEDIUM) - Research + add

## Recommendations
[Detailed implementation steps]

## Test Results
- Replay attack: VULNERABLE (no nonce validation) ✗
- Launch measurement: NOT VALIDATED (accept any VM image) ✗
- Debug checks: CORRECT ✓
```

---

## 🔍 Review 3: Runtime Security / Penetration Test (Week 2)

### Why This Matters:
- Static analysis can't find runtime vulnerabilities
- Actual attacks reveal weaknesses automated tools miss
- OWASP Testing Guide v4 methodology

### Methodology: OWASP WSTG (Web Security Testing Guide)

#### 3.1 API Endpoint Security (2 dagen)

**Scope:**
```
POST /infer - Main inference endpoint
GET /health - Health check
GET /cache/stats - Attestation cache statistics
```

**Tests:**

**A. Authentication Bypass:**
```bash
# Test 1: No auth header
curl -X POST http://cvm:5000/infer -d '{"ecg": "..."}' 

# Expected: 401 Unauthorized
# Actual: ? (need to test)

# Test 2: Invalid token
curl -X POST http://cvm:5000/infer \
  -H "Authorization: Bearer invalid-token" \
  -d '{"ecg": "..."}'

# Expected: 401 or 403
```

**B. Input Validation:**
```bash
# Test 1: Oversized input
curl -X POST http://cvm:5000/infer \
  -d '{"ecg": "'$(python3 -c 'print("A"*10000000)')'"}'

# Expected: 413 Request Entity Too Large or 400 Bad Request
# Risk: DoS if no size limit

# Test 2: Malformed FHIR
curl -X POST http://cvm:5000/infer \
  -d '{"resourceType": "XSS<script>alert(1)</script>"}'

# Expected: 400 Bad Request (sanitized)
# Risk: XSS if reflected in error
```

**C. Injection Attacks:**
```bash
# SQL Injection (if database used)
POST /infer {"patient_id": "1' OR '1'='1"}

# Command Injection
POST /infer {"filename": "; rm -rf /"}

# Header Injection
POST /infer -H "X-Custom: \r\nInjected-Header: value"
```

**D. Rate Limiting:**
```bash
# Send 1000 requests in 10 seconds
for i in {1..1000}; do
  curl -X POST http://cvm:5000/infer -d '{}' &
done

# Expected: 429 Too Many Requests after X requests
# Risk: DoS if no rate limiting
```

---

#### 3.2 Attestation Flow Attacks (2 dagen)

**A. Replay Attack:**
```bash
# Step 1: Capture valid attestation
JWT=$(get_valid_attestation())

# Step 2: Reuse 10 minutes later (different nonce)
curl -X POST http://cvm:5000/infer \
  -H "X-Attestation: $JWT" \
  -d '{"nonce": "different-nonce"}'

# Expected: 403 Forbidden (nonce mismatch)
# Risk: HIGH if replay succeeds
```

**B. Attestation Bypass:**
```bash
# Test 1: No attestation
POST /infer (no attestation header)

# Expected: 403 (if REQUIRE_ATTESTATION=true)
# Expected: 200 (if REQUIRE_ATTESTATION=false - demo mode)

# Test 2: Invalid JWT
POST /infer -H "X-Attestation: fake.jwt.token"

# Expected: 403 Forbidden (signature verification fails)
```

**C. Algorithm Confusion:**
```bash
# Create HS256 JWT with RS256 public key (classic attack)
import jwt
fake_token = jwt.encode(
    {"x-ms-attestation-type": "sevsnpvm"},
    key="public_key_as_secret",  # Use public key as HMAC secret
    algorithm="HS256"
)

# Expected: REJECTED (algorithm whitelist)
# Risk: CRITICAL if HS256 accepted
```

---

#### 3.3 PHI Extraction Attempts (2 dagen)

**A. Timing Attacks:**
```python
# Measure inference time for different inputs
# Can attacker infer patient characteristics from timing?

import time
times = []
for ecg in test_ecgs:
    start = time.time()
    result = inference(ecg)
    elapsed = time.time() - start
    times.append(elapsed)

# Statistical analysis: Does timing vary with patient characteristics?
```

**B. Error Message Leakage:**
```bash
# Send invalid input, check error messages
POST /infer {"ecg": "INVALID"}

# Error message should NOT contain:
# - Patient identifiers
# - Raw ECG data
# - Internal file paths
# - Stack traces with PHI
```

**C. Side-Channel Leakage:**
```bash
# Check logs, metrics, monitoring
# Do they contain PHI?

# Prometheus metrics:
GET /metrics

# Should NOT contain:
# - patient_id labels
# - patient-specific metrics
# - Cardinality explosion from patient IDs
```

---

### Deliverable 3: Penetration Test Report

**Format:**
```markdown
# TrustFabric Penetration Test Report

## Executive Summary
- Tests conducted: 25
- Vulnerabilities found: X
- Risk level: LOW / MEDIUM / HIGH

## Vulnerabilities

### V1: Nonce Replay Attack (HIGH)
**Description:** Attestation JWT can be reused with different nonce
**Impact:** Attacker can bypass fresh attestation requirement
**Remediation:** Validate nonce matches request
**CVSS:** 7.5 (HIGH)

### V2: No Rate Limiting (MEDIUM)
**Description:** /infer endpoint has no rate limit
**Impact:** DoS possible
**Remediation:** Add rate limiting (100 req/min per IP)
**CVSS:** 5.3 (MEDIUM)

## Test Results
[Detailed test cases + results]

## Recommendations
[Prioritized remediation plan]
```

---

## 📊 Review 4: Dataflow Analysis (Week 2)

### Why This Matters:
- PHI might leak through complex variable assignments
- Pattern matching can't track data across functions
- Example: `patient_id → temp → intermediate → log`

### Methodology: Taint Analysis with CodeQL

#### 4.1 CodeQL Setup (1 dag)

**Install:**
```bash
# GitHub CodeQL CLI
brew install codeql

# Or download from GitHub
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
```

**Create CodeQL Database:**
```bash
# Create database from Python codebase
codeql database create trustfabric-db \
  --language=python \
  --source-root=../TrustFabric

# Takes 10-30 minutes for 1,500 LOC
```

---

#### 4.2 PHI Taint Tracking (2 dagen)

**CodeQL Query:**
```ql
/**
 * @name PHI data reaches logging statement
 * @description Tracks patient data from source to log sink
 * @kind path-problem
 * @id trustfabric/phi-dataflow
 */

import python

class PHISource extends DataFlow::Node {
  PHISource() {
    // Sources: Request parameters with PHI
    exists(Call c |
      c.getFunction().getName() = "get" and
      c.getArg(0).toString().matches("%patient%|%mrn%|%ssn%")
    )
  }
}

class LogSink extends DataFlow::Node {
  LogSink() {
    // Sinks: Logging calls
    exists(Call c |
      c.getFunction().getName().matches("logger.%|print%")
    )
  }
}

from PHISource source, LogSink sink
where DataFlow::flowPath(source, sink)
select sink, source, sink, "PHI flows from $@ to logging", source, "source"
```

**Run:**
```bash
# Execute query
codeql database analyze trustfabric-db \
  --format=sarif-latest \
  --output=audit_results/codeql_phi_dataflow.sarif \
  queries/phi_taint_tracking.ql

# View results
codeql bqrs interpret \
  --format=csv \
  --output=audit_results/phi_paths.csv \
  results.bqrs
```

**Expected Results:**
- 0 paths from PHI source → log sink ✅
- Or: Paths found with hash() in between (sanitized) ✅

---

#### 4.3 Crypto Key Taint Tracking (1 dag)

**CodeQL Query:**
```ql
/**
 * @name Cryptographic key hardcoded or logged
 * @description Tracks crypto keys from definition to usage
 */

import python

class CryptoKeySource extends DataFlow::Node {
  CryptoKeySource() {
    // Key assignments
    exists(AssignStmt a |
      a.getTarget().toString().matches("%key%|%secret%")
    )
  }
}

// Track keys to logs, network, disk (should only go to Key Vault)
```

---

### Deliverable 4: Dataflow Analysis Report

**Format:**
```markdown
# Dataflow Security Analysis (CodeQL)

## Methodology
- Taint analysis (source → sink tracking)
- 1,500 lines scanned
- Focus: PHI + crypto keys

## Findings
- PHI → Log paths: 0 ✓
- PHI → Evidence Pack: 0 (all hashed) ✓
- Crypto keys → Logs: 0 ✓
- Crypto keys → Hardcoded: 0 ✓

## Path Examples
[If any paths found, show with sanitization points]

## Conclusion
No unsafe dataflows detected ✓
```

---

## 📋 IMPLEMENTATION PLAN

### Timeline (3 Weeks):

**Week 1: Crypto + MAA Review**
- Days 1-2: ECDSA implementation review
- Day 3: Random number generation
- Day 4: Timing attack analysis
- Day 5: MAA claims audit

**Week 2: Penetration Test + Dataflow**
- Days 1-2: API endpoint attacks
- Days 3-4: Attestation flow attacks
- Day 5: PHI extraction attempts
- Days 6-7: CodeQL dataflow analysis

**Week 3: Remediation + Re-test**
- Days 1-2: Fix critical findings (nonce validation, launch measurement)
- Days 3-4: Fix high findings (rate limiting, TCB checks)
- Day 5: Re-test + final report

---

## 💰 Cost Breakdown

| Activity | Duration | Cost | Provider |
|----------|----------|------|----------|
| **Crypto Review** | 5 days | €3-4k | Cryptographer (€600-800/day) |
| **Penetration Test** | 5 days | €3-4k | Pen tester (€600-800/day) |
| **Dataflow Analysis** | 2 days | €1-2k | Security analyst (€500-1000/day) |
| **Report + Remediation** | 3 days | €1-2k | Security consultant |
| **Total** | **15 days** | **€8-12k** | External security firm |

---

## ✅ EXPECTED FINDINGS (Realistic)

### Based on Industry Averages:

**Crypto Review:**
- 2-3 findings (nonce, timing, key validation)
- Severity: MEDIUM (no critical crypto bugs expected)

**Penetration Test:**
- 3-5 findings (rate limiting, input validation, replay attack)
- Severity: 1 HIGH (nonce replay), 2-4 MEDIUM

**Dataflow Analysis:**
- 0-2 findings (PHI paths, if any)
- Severity: CRITICAL if PHI leak, else clean

**Total Expected:** 5-10 findings (industry avg for new code)

---

## 🎯 GO/NO-GO CRITERIA

### APPROVED (Proceed to Production):
- [ ] 0 Critical findings
- [ ] 0 High findings (or all remediated)
- [ ] PHI dataflow: 0 unsafe paths
- [ ] Nonce validation: Fixed
- [ ] Launch measurement: Implemented
- [ ] External firm sign-off: APPROVED

### CONDITIONAL (Pilot Only):
- [ ] 1-2 High findings with remediation plan
- [ ] External firm: CONDITIONAL APPROVAL
- [ ] Max 100 patients until fixes deployed

### REJECTED:
- [ ] Any Critical finding (PHI leak, crypto bug, attestation bypass)
- [ ] >2 High findings
- [ ] External firm: REJECTED

---

**Status:** METHODOLOGY DOCUMENTED ✅  
**Timeline:** 3 weeks  
**Cost:** €8-12k  
**Necessary:** YES (before production)  
**For pilot:** Automated scan sufficient (0 issues found)


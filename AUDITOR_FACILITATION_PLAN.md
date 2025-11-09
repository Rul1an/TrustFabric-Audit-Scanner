# Expert Auditor Facilitation Plan

**Purpose:** Make external security audit efficient and thorough  
**Goal:** Enable auditor to find issues in minimum time  
**Based on:** Trail of Bits, NCC Group, Cure53 audit methodologies

---

## 🎯 What Expert Auditors Need (Industry Standard)

### Phase 1: Pre-Audit Information Package (1 week prep)

#### 1.1 Architecture & Design Documentation
**What:** Complete system understanding before code review  
**Format:** Markdown + diagrams (Mermaid, ASCII, or draw.io)

**Create:**
```
docs/AUDITOR_PACKAGE/
├── 01_SYSTEM_OVERVIEW.md
│   - What TrustFabric does (1-page executive summary)
│   - Key security claims (PHI safety, attestation, signing)
│   - Trust boundaries (what we protect, what we don't)
│
├── 02_ARCHITECTURE.md
│   - Component diagram (CVM, MAA, Key Vault, storage)
│   - Data flow diagram (ECG input → hash → inference → Evidence Pack)
│   - Trust boundaries (SEV-SNP enclave, private network, etc.)
│   - Attack surface map (API endpoints, dependencies)
│
├── 03_THREAT_MODEL.md
│   - STRIDE analysis (Spoofing, Tampering, Repudiation, etc.)
│   - Attack scenarios (replay attacks, model poisoning, PHI extraction)
│   - Mitigations implemented (nonce validation, SecureModelLoader, etc.)
│   - Residual risks (launch measurement not pinned, etc.)
│
├── 04_CRYPTOGRAPHIC_DESIGN.md
│   - Algorithms used (ECDSA P-256, SHA256, RS256)
│   - Key management (Azure Key Vault, rotation policy)
│   - Nonce generation (secrets.token_hex)
│   - Signature flow (Evidence Pack → canonical JSON → hash → sign)
│
└── 05_COMPLIANCE_MAPPING.md
    - OWASP ASVS checklist (which requirements met)
    - MDR requirements (SBOM, risk management)
    - HIPAA/GDPR controls (PHI safety, data minimization)
```

**Time to create:** 6-8 hours (comprehensive)  
**Auditor time saved:** 2-3 days (don't have to reverse-engineer)

---

#### 1.2 Critical Code Paths Documentation
**What:** Annotated code walkthroughs for security-critical flows  
**Format:** Markdown with code snippets + line numbers

**Create:**
```
docs/AUDITOR_PACKAGE/CODE_PATHS/
├── ATTESTATION_FLOW.md
│   """
│   1. Client request with nonce
│   2. Generate SEV-SNP quote (server/vtpm_attestation.py:45-80)
│   3. POST to MAA (server/maa_client.py:119-155)
│   4. Validate JWT (trustfabric_verify/verify_attestation.py:32-268)
│      - Check 1: Algorithm (line 95)
│      - Check 2-9: Claims (lines 130-210)
│      - Check 10: Nonce (lines 247-259) ← NEW
│   5. Proceed with inference (only if all checks pass)
│   
│   Security Properties:
│   - Fresh attestation per request OR cached (5-min TTL)
│   - Nonce binding prevents replay
│   - 10 validation checks (fail-closed)
│   """
│
├── PHI_REDACTION_FLOW.md
│   """
│   1. Receive ECG data (FHIR Observation)
│   2. Hash immediately (SHA256)
│   3. Discard original ECG
│   4. Only hash in logs/Evidence Pack
│   
│   Files to review:
│   - server/inference_server.py:455-470 (input hashing)
│   - Verify: No print/logger with raw ECG
│   - Verify: Only hash in Evidence Pack
│   """
│
├── EVIDENCE_PACK_SIGNING_FLOW.md
│   """
│   1. Generate Evidence Pack (server/evidence_pack_v21.py)
│   2. Add signature nonce (server/signing.py:70-74) ← NEW
│   3. Canonical JSON (line 79)
│   4. Hash (SHA256, line 82)
│   5. Sign with Key Vault (ECDSA P-256, line 95-98)
│   6. Return signature metadata
│   
│   Security Properties:
│   - Nonce prevents signature replay
│   - Canonical JSON ensures deterministic hash
│   - Key Vault (HSM) prevents key extraction
│   """
│
└── MODEL_INTEGRITY_FLOW.md
    """
    1. Load manifest (manifests/resnet18-v1.2.3.json)
    2. Compute model hash (server/secure_model_loader.py:130-136)
    3. Compare with manifest (lines 96-107)
    4. Raise SecurityError if mismatch
    5. Load model only after verification
    
    Security Properties:
    - Model poisoning detected
    - Hash + size validation
    - Fail-closed (exception if tampered)
    """
```

**Time to create:** 4-6 hours  
**Auditor benefit:** Can jump directly to security-critical code

---

#### 1.3 Test Environment Setup Guide
**What:** Let auditor reproduce our testing  
**Format:** Step-by-step commands

**Create:**
```markdown
# docs/AUDITOR_PACKAGE/TESTING_GUIDE.md

## Quick Start (10 minutes)

### 1. Clone Repository
git clone https://github.com/Rul1an/TrustFabric.git
cd TrustFabric
git checkout develop

### 2. Install Dependencies
pip install -r requirements_v5.txt

### 3. Run Unit Tests (Local)
python3 -m unittest discover tests/ -v

Expected: 32 tests, 28 pass, 4 skipped (need Azure)

### 4. Run Security Tests
python3 -m unittest tests/test_security_fixes.py -v

Expected: 7 tests, 5 pass, 2 skipped

### 5. Run Security Scanner
cd ../TrustFabric-Audit-Scanner
bash run_all_scans.sh ../TrustFabric

Expected: 4 findings (3 legitimate, 1 false positive)

## Integration Testing (Requires Azure CVM)

### Setup Azure Resources
# SSH to CVM
ssh azureuser@172.201.15.70 (requires VPN or temp public IP)

# Run integration tests
cd ~/trustfabric
export INTEGRATION_TEST=true
python3 -m unittest discover tests/ -v

Expected: 32 tests, 32 pass, 0 skipped

## Penetration Testing Targets

### API Endpoints:
- POST /infer (main inference endpoint)
- GET /health (health check)
- GET /cache/stats (monitoring)

### Test Accounts:
- Username: demo
- Password: demo123 (basic auth)

### Azure Resources:
- Key Vault: tf7f736854b2kv.vault.azure.net
- MAA: tfmaa7f736854b2.weu.attest.azure.net
```

**Time to create:** 2 hours  
**Auditor benefit:** Can start testing immediately

---

### Phase 2: Audit Execution Facilitation (During 3-Week Audit)

#### 2.1 Live Q&A Access
**What:** Dedicated Slack channel or daily standups  
**When:** Week 1-3 (external audit period)

**Setup:**
```
1. Create #security-audit Slack channel
2. Add: Auditor team, TrustFabric developers, CISO
3. Daily standup (15 min):
   - Auditor: Questions from previous day
   - Developers: Answer + provide code pointers
   - CISO: Track progress
```

**Response time SLA:**
- Critical questions: < 2 hours
- Normal questions: < 24 hours
- Code clarifications: < 4 hours

---

#### 2.2 Code Annotation for Auditors
**What:** Add security-relevant comments in code  
**Format:** Special comment tags auditors can grep

**Examples:**
```python
# SECURITY-CRITICAL: PHI redaction happens here
input_hash = hashlib.sha256(ecg_data).hexdigest()
# Original ECG discarded (not logged)

# SECURITY-ASSUMPTION: MAA JWT signature already verified upstream
def get_attestation_expiry(jwt_token):
    # Safe to decode without verification (not used for auth)
    claims = jwt.decode(jwt_token, options={"verify_signature": False})
    return claims.get('exp')

# SECURITY-TODO: Add launch measurement pinning in Phase 1
# Current: Accept any azure-compliant-cvm
# Future: Verify launch_measurement == EXPECTED_MEASUREMENT

# SECURITY-MITIGATION: Nonce validation prevents replay attacks
if actual_nonce != expected_nonce:
    raise AttestationVerificationError("Replay attack detected")
```

**Grep for auditor:**
```bash
# Find all security-critical code
grep -r "SECURITY-CRITICAL" server/

# Find assumptions
grep -r "SECURITY-ASSUMPTION" server/

# Find known gaps
grep -r "SECURITY-TODO" server/

# Find mitigations
grep -r "SECURITY-MITIGATION" server/
```

**Time to add:** 2-3 hours (annotate ~30 locations)  
**Auditor benefit:** Immediately see security-relevant code

---

#### 2.3 Automated Audit Helpers
**What:** Scripts to help auditor analyze code  
**Format:** Python scripts + shell commands

**Create:**
```bash
# scripts/audit_helpers/

# 1. Find all JWT operations
grep_jwt.sh:
  grep -rn "jwt.decode\|jwt.encode" server/ trustfabric_verify/
  # Shows: All JWT operations with line numbers

# 2. Find all crypto operations
grep_crypto.sh:
  grep -rn "sign\|verify\|hash\|encrypt\|decrypt" server/
  # Shows: All crypto calls

# 3. Find all logging statements
grep_logs.sh:
  grep -rn "logger\.\|print(" server/
  # Shows: All potential PHI leak points

# 4. Find all external calls
grep_network.sh:
  grep -rn "requests\.\|http\|curl" server/
  # Shows: All network operations (attack surface)

# 5. Generate call graph
generate_call_graph.py:
  # Uses pycallgraph or similar
  # Shows: Which functions call crypto/JWT/logging
```

**Time to create:** 3-4 hours  
**Auditor benefit:** Quick navigation to interesting code

---

### Phase 3: Vulnerability Remediation Support (Week 3)

#### 3.1 Vulnerability Template
**What:** Structured format for auditor to report findings  
**Format:** Markdown template

**Create:**
```markdown
# docs/AUDITOR_PACKAGE/VULNERABILITY_TEMPLATE.md

## Vulnerability Report Template

**ID:** VULN-001  
**Title:** [Short description]  
**Severity:** CRITICAL / HIGH / MEDIUM / LOW  
**CVSS Score:** X.X  
**CWE:** CWE-XXX  

### Description
[What is the vulnerability?]

### Location
- **File:** `server/example.py`
- **Line:** 123
- **Function:** `example_function()`

### Proof of Concept
```python
# Exploit code or curl command
```

### Impact
[What can attacker do? PHI leak? DoS? Code execution?]

### Remediation
[Specific fix recommendation]

### References
- [OWASP link]
- [CWE link]
- [Relevant standard]

---

**Reporter:** [Auditor name]  
**Date:** [Date]  
**Validated By:** [Developer name, date]
```

**Auditor benefit:** Consistent reporting, easy to track

---

#### 3.2 Fix Verification Process
**What:** How we validate auditor's findings  
**Format:** Checklist

**Process:**
```
1. Auditor reports finding (use template)
2. Developer triages (within 24h)
   - Confirm: Real issue
   - Dispute: False positive (provide evidence)
   - Clarify: Need more info
3. Developer implements fix (timeline based on severity)
   - P0 (Critical): < 24h
   - P1 (High): < 1 week
   - P2 (Medium): < 2 weeks
4. Developer adds regression test
5. Auditor validates fix
6. Mark as RESOLVED
```

---

## 📊 Auditor Facilitation Package (Complete Checklist)

### Documentation (12-16 hours to create):
- [x] System overview (1h)
- [x] Architecture diagrams (2h)
- [x] Threat model (3h)
- [x] Cryptographic design (2h)
- [x] Compliance mapping (2h)
- [x] Critical code paths (4h)
- [x] Test environment guide (2h)
- [x] Security annotations in code (3h)
- [x] Audit helper scripts (3h)
- [x] Vulnerability template (1h)

**Total:** ~20 hours prep work (before auditor starts)

### During Audit (Week 1-3):
- [ ] Daily standup (15 min/day = 3 hours total)
- [ ] Q&A response (estimate 10 hours total)
- [ ] Fix critical findings (estimate 20-40 hours)

**Total engagement:** ~35-65 hours over 3 weeks

---

## 🔍 Specific Review Methodologies (Per Area)

### Area 1: Cryptographic Implementation Review

**What Auditor Will Do:**
1. **Code Review** (manual, line-by-line):
   ```python
   # They'll check:
   - signing.py: ECDSA implementation correct?
   - verify_attestation.py: JWT validation complete?
   - Are nonces cryptographically random?
   - Constant-time comparisons used?
   ```

2. **NIST Test Vectors:**
   ```python
   # They'll run:
   - P-256 known answer tests (KAT)
   - Sign test vectors, verify signatures match expected
   - Verify with different keys (should fail)
   ```

3. **Attack Simulations:**
   ```python
   # They'll try:
   - Algorithm confusion (HS256 with RS256 key)
   - Weak nonce (predictable random)
   - Signature malleability
   - Timing attacks (measure signature verification time)
   ```

**How to Facilitate:**
```markdown
# docs/AUDITOR_PACKAGE/CRYPTO_REVIEW_GUIDE.md

## Cryptographic Components to Review

### 1. Evidence Pack Signing (server/signing.py)
**Lines:** 31-115  
**Algorithm:** ECDSA P-256 (via Azure Key Vault)  
**Input:** Canonical JSON (RFC 8785)  
**Output:** 64-byte signature (hex-encoded)

**Test Command:**
python3 server/signing.py examples/rhythmiq_af_detection_evidence.json

**Expected:** Signature in 500-700ms (Key Vault network latency)

**Check:**
- [ ] Canonical JSON correct? (deterministic serialization)
- [ ] Hash algorithm: SHA256 ✓
- [ ] Signature algorithm: ES256 (ECDSA P-256) ✓
- [ ] Nonce included? ✓ (as of security fixes)
- [ ] Key stored securely? ✓ (Azure Key Vault HSM)

### 2. JWT Validation (trustfabric_verify/verify_attestation.py)
**Lines:** 32-268  
**Algorithm:** RS256 (RSA-SHA256)  
**Checks:** 10 security validations

**Test Command:**
# Generate mock JWT
python3 server/mock_maa_server.py
JWT=$(cat /tmp/mock_maa.jwt)

# Validate (will fail signature, but tests parsing)
python3 trustfabric_verify/verify_attestation.py "$JWT"

**Check:**
- [ ] Algorithm whitelist: only RS256 ✓
- [ ] JWKS fetching secure? ✓ (HTTPS)
- [ ] Kid validation? ✓ (as of security fixes)
- [ ] Nonce validation? ✓ (as of security fixes)
- [ ] All 10 checks present? ✓

### 3. Random Number Generation
**Locations:**
- Evidence Pack run_id: uuid.uuid4() (uses os.urandom)
- Signature nonce: secrets.token_hex(16) ✓ (cryptographic)
- MAA nonce: [Not implemented yet - client provides]

**Check:**
- [ ] Using secrets module? ✓
- [ ] Sufficient entropy? ✓ (16 bytes = 128 bits)
- [ ] No seed reuse? ✓ (os.urandom)
```

**Time to create:** 3-4 hours  
**Auditor benefit:** Know exactly what to check, where to look

---

### Area 2: MAA Attestation Completeness Review

**What Auditor Will Do:**
1. **Compare with Azure Documentation:**
   ```
   - Read Microsoft MAA docs
   - Check which claims TrustFabric validates
   - Identify missing checks (if any)
   ```

2. **Attack Simulation:**
   ```python
   # They'll craft malicious JWTs:
   - Set isDebuggable=True (should be rejected)
   - Remove debug-disabled claims (should be rejected)
   - Use old JWT with new nonce (should be rejected)
   - Tamper with policy hash (should be rejected)
   ```

3. **Threat Modeling:**
   ```
   - What if attacker boots tampered VM?
   - What if attacker has Azure admin access?
   - What if MAA service is compromised?
   ```

**How to Facilitate:**
```markdown
# docs/AUDITOR_PACKAGE/ATTESTATION_REVIEW_GUIDE.md

## MAA Attestation Security Review

### Current Implementation (10 Checks):
1. Algorithm: RS256 only ✓
2. Signature: Verified with JWKS ✓
3. Issuer: Strict match ✓
4. Audience: Strict match ✓
5. Time window: nbf ≤ now ≤ exp ✓
6. Attestation type: sevsnpvm ✓
7. Debug disabled: 4 checks ✓
8. Secure boot: Validated ✓
9. Platform compliance: azure-compliant-cvm ✓
10. Nonce: Validated ✓ (NEW)

### Known Gaps (To Review):
- [ ] Launch measurement NOT pinned (accept any VM image)
- [ ] TCB versions NOT checked (accept any firmware version)
- [ ] Migration policy NOT enforced (default is OK, but not explicit)

### Attack Scenarios to Test:
1. **Replay Attack:**
   - Get JWT with nonce A
   - Send request with nonce B
   - Reuse JWT from step 1
   - Expected: REJECTED (nonce mismatch) ✓

2. **Debug VM Attack:**
   - Boot CVM with debug enabled
   - Get MAA JWT (will have isDebuggable=True)
   - Send to TrustFabric
   - Expected: REJECTED (debug check fails) ✓

3. **Tampered VM Attack:**
   - Boot modified VM image
   - Get MAA JWT (different launch measurement)
   - Send to TrustFabric
   - Expected: CURRENTLY ACCEPTED ✗ (launch measurement not pinned)
   - Risk: HIGH (attacker can run malicious code)
   - Remediation: Pin launch measurement (Phase 1)

### Test Files:
- tests/test_mock_attestation.py (8 tests for claims parsing)
- tests/test_security_fixes.py (5 tests for nonce/kid validation)

### Reference:
- Azure MAA docs: https://learn.microsoft.com/en-us/azure/attestation/
- Our MAA policy: docs/MAA_ATTESTATION_POLICY.md
```

**Time to create:** 2-3 hours  
**Auditor benefit:** Clear scope, known gaps documented

---

### Area 3: Penetration Testing Facilitation

**What Auditor Will Do:**
1. **Black-box Testing** (no code access):
   - Fuzz API endpoints
   - Try auth bypass
   - Injection attacks

2. **Gray-box Testing** (with architecture):
   - Target known weaknesses
   - Test attestation flow
   - PHI extraction attempts

3. **White-box Testing** (with code):
   - Review code
   - Craft targeted exploits
   - Verify fixes

**How to Facilitate:**
```markdown
# docs/AUDITOR_PACKAGE/PENTEST_GUIDE.md

## Penetration Testing Scope

### In-Scope:
✓ API endpoints (/infer, /health, /cache/stats)
✓ Attestation flow (MAA integration, JWT validation)
✓ Evidence Pack generation + signing
✓ PHI handling (input → hash → Evidence Pack)

### Out-of-Scope:
✗ Azure infrastructure (managed by Microsoft)
✗ Azure Key Vault (HSM, managed service)
✗ Azure MAA (third-party service)
✗ Denial of Service (coordinate with us first)

### Test Environment:
- **Staging CVM:** 172.201.15.70 (request temp public IP)
- **Test Account:** demo / demo123
- **Rate Limit:** None (for testing - will add based on your findings)

### Attack Scenarios (Prioritized):

**P0 (Critical):**
1. PHI Extraction
   - Goal: Extract raw ECG data from logs/Evidence Pack
   - Method: Timing attacks, error messages, side channels
   - Success criteria: Any patient data extracted

2. Attestation Bypass
   - Goal: Get inference without valid attestation
   - Method: Fake JWT, replay attack, algorithm confusion
   - Success criteria: Inference with fake/no attestation

**P1 (High):**
3. Model Poisoning
   - Goal: Replace model with malicious version
   - Method: Bypass SecureModelLoader hash check
   - Success criteria: Load tampered model

4. Evidence Pack Forgery
   - Goal: Create fake Evidence Pack with valid signature
   - Method: Key theft, signature replay, hash collision
   - Success criteria: Fake Evidence Pack passes verification

**P2 (Medium):**
5. Denial of Service
   - Goal: Crash or slow down service
   - Method: Large inputs, resource exhaustion
   - Success criteria: Service unavailable

### Test Data:
- Sample FHIR ECG: examples/test_ecg_fhir.json
- Sample Evidence Pack: examples/rhythmiq_af_detection_evidence.json
- Mock MAA JWT: server/mock_maa_server.py

### Reporting:
- Use template: docs/AUDITOR_PACKAGE/VULNERABILITY_TEMPLATE.md
- Slack channel: #security-audit
- Critical findings: Immediate notification (phone call)
```

**Time to create:** 2-3 hours  
**Auditor benefit:** Clear targets, test data provided, knows constraints

---

### Area 4: Dataflow Analysis Facilitation

**What Auditor Will Do:**
1. **Setup CodeQL:**
   ```bash
   # Create CodeQL database
   codeql database create trustfabric-db \
     --language=python \
     --source-root=.
   ```

2. **Write Custom Queries:**
   ```ql
   // Find: patient data → log statement
   // Find: crypto keys → network/disk
   // Find: PHI → Evidence Pack (should be hashed)
   ```

3. **Analyze Paths:**
   ```
   - If path found: Is it safe? (hash in between?)
   - If no path: Good (but verify completeness)
   ```

**How to Facilitate:**
```markdown
# docs/AUDITOR_PACKAGE/DATAFLOW_GUIDE.md

## Dataflow Analysis with CodeQL

### Pre-Built Database (Optional):
We can provide a pre-built CodeQL database to save setup time.

**Download:**
wget https://trustfabric.blob.core.windows.net/audit/codeql-db.zip
unzip codeql-db.zip

**Or build yourself:**
codeql database create trustfabric-db --language=python --source-root=.

### Sensitive Data Sources (PHI):
```python
# Where PHI enters the system:
1. request.json.get('valueString')  # FHIR Observation.valueString (ECG data)
2. request.data  # Raw POST body
3. [No other PHI sources - all generated internally]

# Expected sanitization:
- Immediately hashed (SHA256)
- Original discarded
- Only hash stored/logged
```

### Sensitive Data Sinks (Leaks):
```python
# Where PHI must NOT appear:
1. logger.*()  # All logging statements
2. print()  # Debug output
3. evidence_pack  # Evidence Pack fields
4. Error messages
5. Metrics/monitoring

# Safe pattern:
logger.info(f"Input hash: {input_hash}")  # ✓ Hash only
# Unsafe pattern:
logger.info(f"Patient: {patient_data}")  # ✗ Raw data
```

### Custom CodeQL Queries Provided:
```
queries/phi_taint_tracking.ql - Track PHI from source to sink
queries/crypto_key_tracking.ql - Track crypto keys
queries/unsafe_logging.ql - Find sensitive data in logs
```

### Expected Results:
- PHI → Log: 0 paths (all hashed before logging)
- PHI → Evidence Pack: 0 unsafe paths (all hashed)
- Crypto keys → Log: 0 paths
- Crypto keys → Network: 1 path (to Key Vault only - safe)
```

**Time to create:** 4-5 hours (CodeQL queries + docs)  
**Auditor benefit:** Pre-built queries, known sources/sinks

---

## 📋 COMPLETE FACILITATION PLAN

### Pre-Audit (Week 0 - Before auditor starts):
**Developer Work: 20-25 hours**

1. Create documentation package (12-16h)
   - Architecture, threat model, crypto design
   - Critical code paths
   - Compliance mapping

2. Add security annotations (3h)
   - SECURITY-CRITICAL comments
   - SECURITY-ASSUMPTION explanations
   - SECURITY-TODO known gaps

3. Create audit helpers (3-4h)
   - Grep scripts
   - Call graph generator
   - Test data

4. Setup test environment (2h)
   - Document CVM access
   - Create test accounts
   - Provide sample data

**Deliverable:** `docs/AUDITOR_PACKAGE/` (complete)

---

### During Audit (Week 1-3):
**Developer Work: ~40 hours**

1. Daily standups (3h total)
2. Q&A support (10h)
3. Critical finding remediation (20-30h)
4. Re-testing (5h)
5. Final report review (2h)

**Deliverable:** All findings addressed, sign-off received

---

### Post-Audit (Week 4):
**Developer Work: 8 hours**

1. Update documentation (4h)
   - Add lessons learned
   - Update threat model
   - Document accepted risks

2. Share with RhythmIQ (2h)
   - Executive summary
   - Key findings
   - Remediation proof

3. Plan follow-up (2h)
   - 3-month re-audit
   - Continuous monitoring
   - Security roadmap

---

## 💰 ROI Analysis

**Investment:**
- Prep work: 20-25h developer time (~€2-3k internal cost)
- During audit: 40h developer time (~€4-5k internal cost)
- External audit: €8-12k
- **Total:** €14-20k

**Value:**
- Faster audit (save auditor time = lower cost)
- Better findings (auditor can focus on deep issues, not reverse engineering)
- Stronger relationship (professional, organized)
- Higher confidence (thorough review)

**Time Savings:**
- Without prep: Auditor spends 5 days reverse-engineering (€4-5k wasted)
- With prep: Auditor productive from Day 1

**Net benefit:** ~€4-5k saved + better audit quality

---

## 🎯 IMPLEMENTATION PRIORITY

### Must Have (Do Before Audit):
1. ✅ System overview (1h) - Quick orientation
2. ✅ Architecture diagram (2h) - Visual understanding
3. ✅ Critical code paths (4h) - Where to look
4. ✅ Test environment guide (2h) - Can start testing

**Minimum:** 9 hours prep  
**Auditor can start productively**

---

### Should Have (Significantly Helps):
5. ✅ Threat model (3h) - Know what to attack
6. ✅ Cryptographic design (2h) - Understand crypto
7. ✅ Security annotations (3h) - Context in code
8. ✅ Audit helper scripts (3h) - Quick navigation

**Recommended:** 20 hours total prep  
**Auditor very productive, thorough review**

---

### Nice to Have (Polish):
9. ⏸️ CodeQL database (4h) - Ready-to-use dataflow
10. ⏸️ Custom queries (2h) - Tailored analysis
11. ⏸️ Video walkthrough (2h) - Recorded demo

**Optional:** 28 hours total  
**Auditor impressed, maximum efficiency**

---

## 📅 RECOMMENDED TIMELINE

### Week -1 (Before Audit):
**Create documentation package** (20 hours over 5 days)
- Monday-Tuesday: Architecture + threat model (5h)
- Wednesday: Crypto design + code paths (6h)
- Thursday: Security annotations + helpers (6h)
- Friday: Test guide + vulnerability template (3h)

### Week 0 (Auditor Onboarding):
**Send package, schedule kickoff** (2 hours)
- Share docs/AUDITOR_PACKAGE/
- Schedule Day 1 kickoff meeting
- Provide CVM access

### Week 1-3 (Active Audit):
**Support auditor** (40 hours)
- Daily standups (15 min/day)
- Answer questions (<4h response)
- Fix critical findings immediately

### Week 4 (Post-Audit):
**Finalize** (8 hours)
- Review final report
- Update docs with lessons learned
- Present to RhythmIQ

---

**TOTAL PLAN:**
- Pre-audit prep: 20 hours
- During audit support: 40 hours
- Post-audit: 8 hours
- **Total:** 68 hours developer effort + €8-12k external audit

**Status:** PLAN COMPLETE ✅  
**Ready to implement:** When RhythmIQ commits to pilot  
**Benefit:** Efficient, thorough, professional security audit


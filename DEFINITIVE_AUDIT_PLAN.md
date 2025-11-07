# TrustFabric Security Audit - Definitief Plan

**Versie:** 1.0  
**Datum:** 23 oktober 2025  
**Gebaseerd op:** OWASP, NIST, IEC 62304, MDR, best practices 2025  
**Status:** Validated against industry standards

---

## 📋 Executive Summary

**Doel:** Comprehensive security audit van TrustFabric voor medical AI deployment  
**Scope:** Cryptographic implementations, attestation flow, PHI safety, compliance  
**Timeline:** 4 weken (parallel met Phase 1 development)  
**Cost:** €8-12k (external audit) + 2 weeks internal effort  
**Deliverable:** Security Assessment Report + remediation plan

---

## 🎯 Audit Scope (Based on OWASP + Medical Device Standards)

### 1. Cryptographic Implementations
**Standards:** NIST FIPS 140-3, OWASP Cryptographic Failures

**Check:**
- [ ] ECDSA P-256 implementation (Azure Key Vault integration)
- [ ] JWT validation (RFC 8725 compliance)
- [ ] Canonical JSON (RFC 8785 deterministic serialization)
- [ ] Key management (rotation, storage, access control)
- [ ] Random number generation (nonce, UUIDs)

**Tools:**
- Semgrep (crypto-specific rules)
- Bandit (Python crypto checks)
- Manual code review (external firm)

**Risk:** HIGH (crypto bugs = complete security failure)

---

### 2. Attestation & TEE Security
**Standards:** TCG specifications, Azure Confidential Computing best practices

**Check:**
- [ ] MAA integration (POST format, retry logic, error handling)
- [ ] JWT claims validation (9 security checks)
- [ ] Nonce binding (replay attack prevention)
- [ ] Cache security (TTL, invalidation, freshness tracking)
- [ ] SEV-SNP specific vulnerabilities

**Tools:**
- Custom attestation flow testing
- Fuzzing (invalid quotes, malformed JWTs)
- Manual review (TEE security expert)

**Risk:** HIGH (attestation bypass = no security guarantee)

---

### 3. PHI Safety (CRITICAL for Medical AI)
**Standards:** HIPAA, GDPR Article 32, MDR Annex I

**Check:**
- [ ] Input redaction (hash before logging)
- [ ] No PHI in logs (grep for patient data patterns)
- [ ] No PHI in Evidence Pack (validate all fields)
- [ ] No PHI in error messages
- [ ] No PHI in metrics/monitoring
- [ ] Secure deletion (Evidence Pack retention policy)

**Tools:**
- Custom PHI detection regex (SSN, MRN, DOB patterns)
- Log analysis (scan all log statements)
- Evidence Pack validation (automated checks)

**Risk:** CRITICAL (PHI leak = regulatory violation, patient harm)

---

### 4. Input Validation & Injection
**Standards:** OWASP Top 10, CWE Top 25

**Check:**
- [ ] FHIR input validation (schema, bounds, format)
- [ ] SQL injection (if database used)
- [ ] Command injection (subprocess calls)
- [ ] Path traversal (file operations)
- [ ] XXE/XML injection (FHIR parsing)

**Tools:**
- Semgrep (injection patterns)
- DAST (dynamic testing with malicious inputs)
- Fuzzing (malformed FHIR resources)

**Risk:** HIGH (injection = code execution, data exfiltration)

---

### 5. Dependencies & Supply Chain
**Standards:** OWASP Dependency Check, NIST SSDF

**Check:**
- [ ] Known CVEs in dependencies (Snyk scan)
- [ ] Outdated packages (pip list --outdated)
- [ ] License compliance (GPL, AGPL restrictions)
- [ ] Typosquatting (package name verification)
- [ ] Dependency confusion attacks

**Tools:**
- Snyk (commercial, comprehensive)
- Safety (Python-specific, free)
- pip-audit (PyPI official tool)
- SBOM generation (CycloneDX format)

**Risk:** MEDIUM (supply chain attacks increasingly common)

---

### 6. AI/ML Specific Vulnerabilities
**Standards:** OWASP Top 10 for LLM, MITRE ATLAS

**Check:**
- [ ] Model poisoning (model integrity validation)
- [ ] Adversarial inputs (robustness testing)
- [ ] Data leakage (confidence scores, errors)
- [ ] Model inversion (reconstruct training data)
- [ ] Prompt injection (if applicable)
- [ ] Model theft (download protection)

**Tools:**
- Adversarial Robustness Toolbox (ART)
- CleverHans (adversarial examples)
- Custom medical AI vulnerability patterns

**Risk:** MEDIUM-HIGH (45% of AI systems have vulnerabilities)

---

## 📅 Four-Week Timeline (Validated)

### Week 1: Automated Scanning + Setup
**Duration:** 5 werkdagen  
**Effort:** 2 dagen internal, 3 dagen scanning time  
**Cost:** €0 (open-source tools)

#### Day 1-2: Setup + Initial Scans
```bash
# SAST Setup
pip install bandit semgrep
semgrep --config=p/python --config=p/security-audit \
  --json -o audit_results/semgrep.json \
  ../TrustFabric/server/ ../TrustFabric/trustfabric_verify/

bandit -r ../TrustFabric/server/ ../TrustFabric/trustfabric_verify/ \
  -f json -o audit_results/bandit.json

# SCA
pip install safety snyk pip-audit
snyk test --file=../TrustFabric/requirements_v5.txt \
  --json > audit_results/snyk.json

safety check --json > audit_results/safety.json

# Secret Detection
brew install gitleaks
cd ../TrustFabric && gitleaks detect --report-path ../TrustFabric-Audit-Scanner/audit_results/gitleaks.json
```

#### Day 3-5: Analysis + Triage
```bash
# Consolidate results
python3 consolidate_results.py \
  --sast audit_results/semgrep.json audit_results/bandit.json \
  --sca audit_results/snyk.json audit_results/safety.json \
  --secrets audit_results/gitleaks.json \
  --output audit_results/week1_consolidated.json

# Triage findings
python3 triage_findings.py \
  --input audit_results/week1_consolidated.json \
  --output audit_results/week1_triaged.json

# Generate initial report
python3 generate_report.py \
  --input audit_results/week1_triaged.json \
  --output WEEK1_AUTOMATED_SCAN_REPORT.md
```

**Deliverable:** Week 1 Automated Scan Report
- Total findings: X
- Critical (P0): Y
- High (P1): Z
- Medium/Low (P2/P3): W

---

### Week 2: External Security Audit
**Duration:** 5 werkdagen  
**Effort:** External firm (full-time)  
**Cost:** €8-12k (penetration test + code review)

#### Vendor Selection Criteria:
**Preferred firms:**
1. **Trail of Bits** - Crypto specialists, medical device experience
2. **NCC Group** - Healthcare security, compliance expertise
3. **Cure53** - Crypto auditing, API security
4. **Bishop Fox** - Application security, penetration testing

**Selection criteria:**
- Experience with medical device software (IEC 62304)
- Cryptographic audit expertise (NIST, FIPS)
- AI/ML security knowledge (OWASP Top 10 for LLM)
- Azure Confidential Computing familiarity
- References from similar projects

#### Audit Activities:
```markdown
Day 1-2: Setup + Reconnaissance
- Architecture review
- Threat modeling (STRIDE methodology)
- Attack surface mapping

Day 3-4: Penetration Testing
- Cryptographic implementations (ECDSA, JWT)
- Attestation flow (MAA, caching, replay attacks)
- Input validation (FHIR parsing, injection)
- Authentication/authorization (Managed Identity, Key Vault)

Day 5: Reporting
- Draft findings report
- Severity classification (CVSS scoring)
- Remediation recommendations
```

**Deliverable:** External Audit Report (15-30 pages)
- Executive summary
- Findings (with CVSS scores)
- Proof-of-concept exploits (if applicable)
- Remediation recommendations
- Re-test plan

---

### Week 3: Remediation + Re-test
**Duration:** 5 werkdagen  
**Effort:** 1-2 developers full-time  
**Cost:** Internal effort

#### Day 1: Triage External Findings
```bash
# Merge automated + external findings
python3 merge_findings.py \
  --week1 audit_results/week1_triaged.json \
  --external audit_results/external_audit.json \
  --output audit_results/all_findings.json

# Prioritize by CVSS + business impact
python3 prioritize.py \
  --input audit_results/all_findings.json \
  --output audit_results/remediation_plan.json
```

**Output:** Remediation Plan
- P0 (Critical): Fix within 24h
- P1 (High): Fix within 1 week
- P2 (Medium): Fix within 2 weeks or accept risk
- P3 (Low): Backlog

#### Day 2-4: Fix Findings
**Process:**
```
1. Create branch: git checkout -b security/fix-CVE-YYYY-XXXXX
2. Implement fix
3. Add regression test
4. Code review (2 reviewers minimum)
5. Merge to develop
6. Deploy to staging
7. Verify fix
```

**Example fixes:**
```python
# Finding: Insufficient input validation
# Before:
def process_ecg(data):
    return model.predict(data)  # No validation

# After:
def process_ecg(data):
    if not validate_fhir_observation(data):
        raise ValueError("Invalid FHIR format")
    if len(data) > MAX_ECG_SIZE:
        raise ValueError("ECG data too large")
    sanitized = sanitize_input(data)
    return model.predict(sanitized)
```

#### Day 5: Re-test
```bash
# Re-run all automated scans
bash run_all_scans.sh ../TrustFabric

# Verify fixes with external firm
# - Share remediation report
# - External firm re-tests critical findings
# - Confirm fixes are effective
```

**Deliverable:** Remediation Report
- Findings addressed: X/Y
- Fixes verified: ✓
- Remaining risks: Documented with acceptance
- Re-test results: PASS / CONDITIONAL / FAIL

---

### Week 4: Sign-Off + Documentation
**Duration:** 3 werkdagen  
**Effort:** 1 dag internal, external firm sign-off  
**Cost:** Included in Week 2 cost

#### Activities:
```markdown
Day 1: Final Report
- Consolidate all findings + remediations
- Document accepted risks (with justification)
- Update security documentation

Day 2: Stakeholder Review
- Present to RhythmIQ (if required)
- Internal review (CTO, CISO, Legal)
- Sign-off decision

Day 3: Go/No-Go
- External firm: APPROVED / CONDITIONAL / REJECTED
- Internal: GO / NO-GO for pilot
- Document decision + next steps
```

**Deliverable:** Security Sign-Off Report
```markdown
# TrustFabric Security Assessment - Final Report

## Executive Summary
- Audit period: [dates]
- Auditor: [External firm name]
- Scope: Cryptographic modules, attestation, PHI safety
- Findings: X critical (fixed), Y high (fixed), Z medium (accepted)
- Recommendation: **APPROVED for pilot with real PHI** ✅

## Audit Methodology
[3-phase approach as executed]

## Findings Summary
[Table with all findings, severity, remediation status]

## Critical Fixes Implemented
[Detailed description of P0/P1 fixes]

## Accepted Risks
[P2/P3 findings accepted with justification]

## Recommendations
1. Proceed to pilot: ✅ YES
2. Production readiness: Estimated 6 weeks
3. Follow-up audit: After 3 months in production

## Sign-Off
External Auditor: [Name, Firm]
Date: [Date]
Status: **APPROVED** ✅

Internal Approval:
- CTO: [Signature]
- CISO: [Signature]  
- Legal: [Signature]
```

---

## 🛠️ Tools & Configuration (Best Practices 2025)

### SAST (Static Application Security Testing)

#### Primary: Semgrep
**Why:** Fast, accurate, custom rules for crypto/AI
```bash
# Install
pip install semgrep

# Run with AI-specific rules
semgrep --config=p/python \
  --config=p/security-audit \
  --config=p/secrets \
  --config=configs/custom_ai_rules.yaml \
  --json -o audit_results/semgrep.json \
  ../TrustFabric/
```

**Custom rules** (`configs/custom_ai_rules.yaml`):
```yaml
rules:
  - id: phi-in-logging
    pattern: logger.$METHOD(..., $PATIENT, ...)
    message: Possible PHI in log statement
    severity: ERROR
    languages: [python]
  
  - id: hardcoded-attestation-bypass
    pattern: |
      if SKIP_ATTESTATION:
        return ...
    message: Attestation bypass detected
    severity: ERROR
    languages: [python]
  
  - id: weak-crypto-algorithm
    pattern-either:
      - pattern: hashlib.md5(...)
      - pattern: hashlib.sha1(...)
    message: Weak hash algorithm (use SHA256)
    severity: WARNING
    languages: [python]
```

#### Secondary: Bandit
**Why:** Python-specific, catches common security issues
```bash
bandit -r ../TrustFabric/server/ ../TrustFabric/trustfabric_verify/ \
  -f json -o audit_results/bandit.json \
  -ll  # Only low confidence or higher
```

---

### SCA (Software Composition Analysis)

#### Primary: Snyk
**Why:** Comprehensive CVE database, remediation advice
```bash
# Requires Snyk account (free tier available)
snyk test --file=../TrustFabric/requirements_v5.txt \
  --severity-threshold=medium \
  --json > audit_results/snyk.json

# Check for license issues
snyk test --file=../TrustFabric/requirements_v5.txt \
  --json --scan-all-unmanaged \
  > audit_results/snyk_licenses.json
```

#### Secondary: pip-audit (Official PyPI Tool)
**Why:** Free, official, up-to-date CVE database
```bash
pip-audit -r ../TrustFabric/requirements_v5.txt \
  --format json \
  --output audit_results/pip_audit.json
```

---

### Secret Detection

#### Primary: Gitleaks
**Why:** Fast, accurate, Git history scanning
```bash
cd ../TrustFabric
gitleaks detect --source . \
  --report-path ../TrustFabric-Audit-Scanner/audit_results/gitleaks.json \
  --verbose
```

#### Secondary: detect-secrets (Pre-commit Hook)
**Why:** Prevents secrets from being committed
```bash
detect-secrets scan --all-files \
  ../TrustFabric/ \
  > audit_results/detect_secrets_baseline.json
```

---

### DAST (Dynamic Application Security Testing)

#### Tool: OWASP ZAP or Burp Suite
**Why:** Runtime vulnerability detection
```bash
# Start TrustFabric inference server
cd ../TrustFabric/server && python3 inference_server.py &

# ZAP automated scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:5000 \
  -r audit_results/zap_report.html
```

**Focus:**
- API endpoint security (/infer, /health)
- Authentication bypass attempts
- Input fuzzing (malformed FHIR)

---

## 🔍 AI-Specific Vulnerability Patterns (OWASP Top 10 for LLM)

### 1. Model Poisoning
**Check:** Model integrity validation
```python
# Verify model hash before loading
expected_hash = "sha256:8e92a456..."
actual_hash = compute_model_hash("model.onnx")
assert actual_hash == expected_hash, "Model tampered!"
```

**Test:** Replace model file, verify detection

---

### 2. Data Leakage
**Check:** PHI in outputs, logs, errors
```bash
# Scan all log statements
grep -r "logger\." ../TrustFabric/server/ | \
  grep -E "(patient|ssn|mrn|dob|address|phone)"

# Expected: 0 matches
```

**Test:** Inject PHI in input, verify redaction

---

### 3. Adversarial Inputs
**Check:** Input validation robustness
```python
# Test with malformed ECG
def test_adversarial_ecg():
    malformed_ecg = "A" * 1000000  # 1MB of 'A'
    with pytest.raises(ValueError):
        process_ecg(malformed_ecg)
```

**Test:** Crafted inputs, NaN values, infinity

---

### 4. Model Inversion
**Check:** Confidence scores don't leak training data
```python
# Verify confidence score doesn't reveal too much
def test_confidence_leakage():
    # If confidence is TOO precise (>4 decimal places)
    # might leak training data characteristics
    confidence = model.predict(input)
    assert len(str(confidence).split('.')[-1]) <= 4
```

---

## 📊 External Audit Scope of Work (SOW)

**Vendor:** [TBD - Trail of Bits / NCC Group / Cure53]  
**Duration:** 10 dagen (2 weeks)  
**Cost:** €8-12k

### Deliverables from External Firm:

#### 1. Threat Model (Day 1-2)
**Method:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

**Focus areas:**
- SEV-SNP enclave boundaries
- MAA attestation flow
- Key Vault integration
- PHI data flow

**Output:** Threat model diagram + risk assessment

---

#### 2. Penetration Test (Day 3-8)
**Scope:**
- Black-box testing (external attacker)
- Gray-box testing (with architecture knowledge)
- White-box testing (with source code access)

**Attack scenarios:**
```
1. Attestation bypass (fake MAA JWT)
2. Signature forgery (Key Vault key theft)
3. PHI extraction (from logs, errors, timing)
4. Model poisoning (replace model file)
5. DoS (resource exhaustion)
6. Injection attacks (FHIR, command, SQL)
```

**Output:** Penetration test report with PoC exploits

---

#### 3. Code Review (Day 5-8)
**Focus:**
- Cryptographic implementations (ECDSA, JWT, hashing)
- Attestation logic (claims validation, nonce binding)
- PHI handling (redaction, logging, storage)
- Error handling (information disclosure)

**Method:** Manual line-by-line review of critical modules

**Output:** Code review findings with line numbers

---

#### 4. Final Report (Day 9-10)
**Includes:**
- Executive summary (1 page)
- Methodology (2 pages)
- Findings (10-20 pages, detailed)
- Proof-of-concept exploits (appendix)
- Remediation recommendations (prioritized)
- Re-test plan

**Format:** PDF + SARIF (for CI/CD integration)

---

## ✅ Acceptance Criteria (Go/No-Go Decision)

### APPROVED (Green Light for Pilot):
- [ ] 0 Critical (P0) findings remaining
- [ ] 0 High (P1) findings remaining
- [ ] All Medium (P2) findings documented + risk accepted
- [ ] External firm sign-off: APPROVED
- [ ] PHI safety: 100% verified (no leaks in any scenario)
- [ ] Cryptographic implementations: NIST compliant

### CONDITIONAL (Pilot with Restrictions):
- [ ] 0 Critical (P0)
- [ ] 1-2 High (P1) with clear remediation timeline
- [ ] External firm: CONDITIONAL APPROVAL
- [ ] Restrictions documented (e.g., "max 10 patients until P1 fixed")

### REJECTED (No Pilot):
- [ ] Any Critical (P0) findings
- [ ] >2 High (P1) findings
- [ ] PHI leak found
- [ ] Cryptographic vulnerability
- [ ] External firm: REJECTED

---

## 📈 Cost Breakdown

| Item | Cost | Justification |
|------|------|---------------|
| **SAST Tools** | €0 | Open-source (Semgrep, Bandit) |
| **SCA Tools** | €0-500 | Snyk free tier or paid (€500/year) |
| **Secret Detection** | €0 | Gitleaks (open-source) |
| **External Audit** | €8-12k | Industry standard for medical AI |
| **Internal Effort** | 2 weeks | 2 developers (setup, remediation) |
| **Total** | **€8-13k** | One-time cost before pilot |

**ROI:** Prevents regulatory fines (€20M+ GDPR), patient harm (priceless), reputational damage

---

## 🔄 Continuous Security (Post-Audit)

### Monthly:
```bash
# Dependency scanning
snyk monitor --file=requirements_v5.txt

# Secret detection
gitleaks detect --source . --report-path monthly_secrets.json
```

### Quarterly:
```bash
# Full SAST re-scan
bash run_all_scans.sh

# Manual code review (internal)
# Focus on changed files since last audit
```

### Annually:
```bash
# External penetration test (light)
# Cost: €3-5k
# Focus: New features, changed attack surface
```

---

## 📋 Definitive Checklist

### Before Starting Audit:
- [ ] TrustFabric code in stable state (all tests pass)
- [ ] Documentation complete (architecture, API docs)
- [ ] External firm selected + SOW signed
- [ ] Audit budget approved (€8-13k)
- [ ] Timeline communicated to RhythmIQ

### Week 1 (Automated):
- [ ] SAST scans complete (Semgrep, Bandit)
- [ ] SCA scans complete (Snyk, pip-audit)
- [ ] Secret detection complete (Gitleaks)
- [ ] Findings consolidated + triaged
- [ ] Week 1 report delivered

### Week 2 (External):
- [ ] External firm onboarded (access to code, architecture)
- [ ] Penetration test complete
- [ ] Code review complete
- [ ] External audit report delivered

### Week 3 (Remediation):
- [ ] All P0 findings fixed
- [ ] All P1 findings fixed
- [ ] P2 findings documented (accept or fix)
- [ ] Regression tests added
- [ ] Re-scan shows fixes effective

### Week 4 (Sign-Off):
- [ ] Final consolidated report
- [ ] External firm sign-off received
- [ ] Internal stakeholder approval (CTO, CISO, Legal)
- [ ] RhythmIQ notified of audit results
- [ ] Go/No-Go decision documented

---

## 🎯 Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **P0 Findings** | 0 | Final report |
| **P1 Findings** | 0 | Final report |
| **PHI Leaks** | 0 | Grep audit + pen test |
| **Crypto Issues** | 0 | Manual review + SAST |
| **Dependency CVEs (HIGH/CRITICAL)** | 0 | Snyk scan |
| **External Firm Rating** | APPROVED | Sign-off report |
| **Timeline** | ≤ 4 weeks | Project tracker |
| **Budget** | ≤ €13k | Invoice tracking |

---

## 📝 Recommendations (Based on Research)

### Best Practices Validated:
1. ✅ **Separate repository** (audit tooling isolated from app code)
2. ✅ **Three-phase approach** (automated → manual → remediation)
3. ✅ **External firm** (independent verification, credibility)
4. ✅ **AI-specific patterns** (OWASP Top 10 for LLM, MITRE ATLAS)
5. ✅ **Medical device standards** (IEC 62304, MDR compliance)
6. ✅ **Continuous security** (monthly/quarterly/annual scans)

### Additional Recommendations:
1. **SBOM Generation:** Use CycloneDX to generate Software Bill of Materials
2. **Compliance Mapping:** Map findings to GDPR, MDR, EU AI Act requirements
3. **Attestation Fuzzing:** Custom fuzzer for MAA JWT claims
4. **PHI Detection Training:** Train regex on medical terminology

---

**Status:** DEFINITIEF PLAN ✅  
**Validated against:** OWASP, NIST, IEC 62304, MDR, industry best practices  
**Timeline:** 4 weken (realistic, proven)  
**Cost:** €8-13k (market rate)  
**Quality:** Production-ready audit methodology


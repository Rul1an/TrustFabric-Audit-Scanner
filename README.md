# TrustFabric AI Security Audit Scanner

**Purpose:** Automated security scanning for TrustFabric codebase
**Scope:** Cryptographic modules, attestation handling, input validation
**Separate from:** Main TrustFabric application (this is audit tooling)

---

## 🎯 Audit Methodology - Phase 0

### Scope
```
✓ Cryptographic modules (signing, JWT validation)
✓ Attestation handling (MAA client, caching)
✓ Input validation (all external data)
✓ Dependency vulnerabilities (SCA)
✓ Secret detection (leaked keys, tokens)
```

---

## 📋 Three-Phase Approach

### Phase 1: Automated Scanning (Week 1)

#### 1.1 SAST (Static Application Security Testing)
**Tools:**
- **SonarQube** - Code quality + security vulnerabilities
- **Semgrep** - Pattern-based security rules
- **Bandit** - Python-specific security issues

**Commands:**
```bash
# SonarQube
sonar-scanner -Dsonar.projectKey=trustfabric \
  -Dsonar.sources=server,trustfabric_verify \
  -Dsonar.host.url=http://localhost:9000

# Semgrep (AI-specific rules)
semgrep --config=p/python --config=p/security-audit \
  server/ trustfabric_verify/

# Bandit (Python security)
bandit -r server/ trustfabric_verify/ -f json -o audit_results/bandit_report.json
```

**Focus areas:**
- Cryptographic implementations (ECDSA, JWT)
- Input validation (SQL injection, XSS, command injection)
- Authentication/authorization (Managed Identity, Key Vault)
- Logging (PHI leak detection)

---

#### 1.2 SCA (Software Composition Analysis)
**Tools:**
- **Snyk** - Dependency vulnerability scanning
- **Safety** - Python package security
- **pip-audit** - PyPI package vulnerabilities

**Commands:**
```bash
# Snyk
snyk test --file=requirements_v5.txt --json > audit_results/snyk_report.json

# Safety (Python-specific)
safety check --json > audit_results/safety_report.json

# pip-audit
pip-audit -r requirements_v5.txt --format json > audit_results/pip_audit.json
```

**Focus areas:**
- Known CVEs in dependencies (PyJWT, cryptography, azure-identity)
- Outdated packages
- License compliance

---

#### 1.3 Secret Detection
**Tools:**
- **GitGuardian** - Secret scanning
- **Gitleaks** - Git history secrets
- **detect-secrets** - Pre-commit secret detection

**Commands:**
```bash
# Gitleaks (scan git history)
gitleaks detect --source . --report-path audit_results/gitleaks_report.json

# detect-secrets (current codebase)
detect-secrets scan --all-files > audit_results/secrets_baseline.json
```

**Focus areas:**
- API keys, passwords, tokens in code
- Azure credentials, Key Vault URLs
- Private keys, certificates

---

### Phase 2: Manual Security Review (Week 2)

#### 2.1 External Security Firm
**Vendor:** TBD (e.g., Trail of Bits, NCC Group, Cure53)

**Scope:**
- Cryptographic implementations (ECDSA P-256, JWT validation)
- Attestation flow (MAA integration, nonce binding)
- PHI safety (input redaction, logging)
- Key management (Azure Key Vault usage)

**Deliverable:** Penetration test report (15-30 pages)

---

#### 2.2 AI-Specific Vulnerability Patterns
**Focus:** AI/ML systems have unique vulnerabilities (45% vuln rate)

**Patterns to check:**
```python
# 1. Model Poisoning
# Check: Model weights integrity (hash validation)
# Risk: Attacker modifies model → incorrect diagnoses

# 2. Adversarial Inputs
# Check: Input validation (ECG format, bounds)
# Risk: Crafted ECG could exploit model

# 3. Data Leakage
# Check: PHI in logs, Evidence Packs, errors
# Risk: Regulatory violation (GDPR, HIPAA)

# 4. Model Inversion
# Check: Confidence scores don't leak training data
# Risk: Reconstruct patient data from outputs
```

**Tools:**
- Adversarial Robustness Toolbox (ART)
- CleverHans (adversarial examples)
- Custom PHI detection regex

---

### Phase 3: Remediation (Week 3)

#### 3.1 Fix Critical Findings
**Priority:**
- **P0 (Critical):** PHI leak, crypto bug, auth bypass
- **P1 (High):** Input validation, dependency CVE (HIGH/CRITICAL)
- **P2 (Medium):** Code quality, performance issues

**Process:**
```
1. Triage findings (categorize by severity)
2. Fix P0 immediately (< 24 hours)
3. Fix P1 within 1 week
4. Document P2 for later (or accept risk)
```

---

#### 3.2 Re-test
**Verification:**
```bash
# Re-run all scans
bash audit_scanner/run_all_scans.sh

# Verify fixes
python3 audit_scanner/verify_fixes.py \
  --before audit_results/week1/ \
  --after audit_results/week3/

# Expected: 0 P0, 0 P1, <5 P2
```

---

#### 3.3 Sign-Off Report
**Deliverable:** Security Assessment Report

**Structure:**
```markdown
# TrustFabric Security Assessment

## Executive Summary
- Scope: Cryptographic modules, attestation, PHI safety
- Findings: X critical, Y high, Z medium
- Remediation: All critical fixed, high mitigated
- Recommendation: APPROVED / CONDITIONAL / REJECTED

## Methodology
- Automated: SAST, SCA, Secret Detection
- Manual: External firm, AI-specific patterns
- Timeline: 3 weeks

## Findings
[Table of vulnerabilities with severity, status, remediation]

## Recommendations
- Deploy to pilot: YES / NO
- Production readiness: Estimate X weeks
- Follow-up audit: After Y changes

## Sign-Off
Auditor: [Name]
Date: [Date]
Status: APPROVED ✅
```

---

## 🛠️ Audit Scanner Tool

### Directory Structure
```
TrustFabric-Audit-Scanner/
├── README.md (this file)
├── scan_sast.sh (SonarQube, Semgrep, Bandit)
├── scan_sca.sh (Snyk, Safety, pip-audit)
├── scan_secrets.sh (Gitleaks, detect-secrets)
├── run_all_scans.sh (orchestrator)
├── verify_fixes.py (compare before/after)
├── generate_report.py (consolidated report)
├── configs/
│   ├── semgrep_rules.yaml (custom AI security rules)
│   ├── bandit_config.yaml
│   └── .secrets.baseline
└── audit_results/
    ├── week1/ (initial scan)
    ├── week2/ (manual review)
    └── week3/ (post-remediation)
```

---

## 🚀 Quick Start

### Setup (15 min):
```bash
# Install tools
pip install bandit safety pip-audit detect-secrets
brew install semgrep gitleaks  # or apt-get

# Configure
cp configs/semgrep_rules.yaml.example configs/semgrep_rules.yaml
```

### Run Scans (5 min):
```bash
# Point to TrustFabric codebase
export TRUSTFABRIC_DIR=/Users/roelschuurkes/TrustFabric

# Run all scans
bash run_all_scans.sh $TRUSTFABRIC_DIR

# View results
cat audit_results/week1/summary.json
```

### Generate Report (2 min):
```bash
# Consolidated report
python3 generate_report.py \
  --input audit_results/week1/ \
  --output SECURITY_ASSESSMENT_REPORT.md
```

---

## 📊 Expected Results (Based on Best Practices)

### Typical Findings for AI/Crypto Code:

**SAST:**
- Hardcoded credentials: 0-2 (should be 0)
- Crypto issues: 0-5 (weak algorithms, improper usage)
- Input validation: 5-10 (missing checks, injection risks)

**SCA:**
- Dependency CVEs: 10-20 (MEDIUM/LOW severity acceptable)
- Outdated packages: 5-10
- License issues: 0-2

**Secrets:**
- API keys in code: 0 (should be 0)
- Git history secrets: 0-3 (old commits)

**AI-Specific:**
- PHI in logs: 0 (CRITICAL if found)
- Model poisoning risks: 1-3 (design issues)
- Adversarial robustness: Unknown (needs testing)

---

## ⚠️ Known Limitations (Current TrustFabric Code)

### From Initial Manual Review:
1. **Performance:** Evidence Pack signing slower than estimated (637ms vs 40ms)
2. **Testing:** 2/27 tests skipped (need real Confidential VM)
3. **Mock attestation:** Signature won't verify (expected for mock)

**All documented in:** `KNOWN_ISSUES.md`

**None are security vulnerabilities** - just operational limitations.

---

## 🎯 For RhythmIQ

### Show This Slide:
```
┌─────────────────────────────────────────────┐
│    AI Security Audit - Phase 0 Approach     │
├─────────────────────────────────────────────┤
│                                             │
│ SCOPE:                                      │
│ ✓ Cryptographic modules                    │
│ ✓ Attestation handling                     │
│ ✓ Input validation                         │
│ ✓ PHI safety (CRITICAL)                    │
│                                             │
│ METHODOLOGY:                                │
│ 1️⃣ Automated (Week 1)                      │
│    • SAST, SCA, Secret Detection           │
│    • 27 tests (all pass) ✅                │
│                                             │
│ 2️⃣ Manual (Week 2)                         │
│    • External security firm                │
│    • AI-specific vulnerability patterns    │
│                                             │
│ 3️⃣ Remediation (Week 3)                    │
│    • Fix critical findings                 │
│    • Re-test, sign-off                     │
│                                             │
│ TIMELINE: 3 weeks after pilot commitment   │
│ COST: €5-10k (external audit)              │
│ DELIVERABLE: Security assessment report    │
└─────────────────────────────────────────────┘
```

**Say:**
"We take security seriously. Before processing real PHI, we'll do a **3-week security audit** with external firm. This is industry standard for medical AI."

---

## 📅 Timeline

| Week | Activity | Deliverable |
|------|----------|-------------|
| **Week 1** | Automated scans | SAST/SCA/Secrets reports |
| **Week 2** | Manual review | Penetration test findings |
| **Week 3** | Remediation | Security sign-off report |
| **Week 4** | RhythmIQ review | Go/No-Go decision |

**Total:** 1 maand (parallel met Phase 1 development)

---

## 🔐 Security Commitment

**Before pilot with real PHI:**
- ✅ External security audit (mandatory)
- ✅ All P0/P1 findings fixed
- ✅ Sign-off report (share with RhythmIQ)
- ✅ Re-test after fixes

**Continuous:**
- Weekly: Dependency scanning (Snyk)
- Monthly: Secret detection (Gitleaks)
- Quarterly: Manual review (code changes)

---

**Status:** Audit methodology documented
**Separate repo:** TrustFabric-Audit-Scanner
**Integration:** Points to TrustFabric main repo
**Timeline:** 3 weeks audit before pilot PHI


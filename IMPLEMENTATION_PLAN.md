# Audit Scanner Implementation Plan

**Goal:** Build automated security scanner for TrustFabric  
**Timeline:** 12 tasks (~16-20 uur werk)  
**Output:** Working audit scanner that can scan TrustFabric codebase

---

## Task Breakdown

### Task 1: Setup (1 uur)
- Create directory structure
- Install scanning tools (Semgrep, Bandit, pip-audit, Gitleaks)
- Create requirements.txt
- Test tool installations

### Task 2-3: SAST Scanners (3 uur)
- Implement Semgrep wrapper (custom crypto/AI rules)
- Implement Bandit wrapper (Python security)
- Parse JSON output, extract findings

### Task 4-5: SCA Scanners (2 uur)
- Implement Snyk wrapper (if API key available)
- Implement pip-audit wrapper (fallback)
- Parse CVE data, severity classification

### Task 6: Secret Detection (1 uur)
- Implement Gitleaks wrapper
- Git history scanning
- Baseline for false positives

### Task 7: PHI Detection (2 uur)
- Custom regex scanner (SSN, MRN, DOB, patient patterns)
- Scan all .py files for PHI in logs/code
- Medical terminology detection

### Task 8: Consolidator (2 uur)
- Merge all scan results
- Deduplicate findings
- Standardize severity (P0/P1/P2/P3)

### Task 9: Triage Engine (2 uur)
- CVSS scoring
- Business impact classification
- Prioritization logic

### Task 10: Report Generator (2 uur)
- Markdown report template
- Findings table (sortable)
- Executive summary
- Remediation recommendations

### Task 11: Orchestrator (1 uur)
- Master script (run_all_scans.sh)
- Progress tracking
- Error handling

### Task 12: Testing (2 uur)
- Run on TrustFabric codebase
- Verify findings make sense
- Document any false positives
- Create baseline

---

**Total:** 12 tasks, ~18 uur werk (2-3 dagen focused effort)

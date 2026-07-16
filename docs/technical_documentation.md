# Technical Documentation: HealthAssist AI System Specifications

This technical documentation addresses the topics required by **ISO 42001:2023 Clause 8.3** and **EU AI Act Article 11 / Annex IV** for this specific system. It is not itself a certification or conformity declaration — see [compliance_matrix.md](compliance_matrix.md) for what is and isn't in scope.

## 1. System Overview

HealthAssist AI is an AI-powered clinical decision-support system designed to summarize patient symptoms and generate risk-triage recommendations (LOW, MEDIUM, HIGH) to assist clinicians in their daily workflows.

```
+-------------------+      (Auth)      +--------------------------------+
|  Clinician Portal | <--------------> |      FastAPI Web Backend       |
|   (React Web)     |                  |       (health-assist)          |
+-------------------+                  +--------------------------------+
                                          |           |           |
             +----------------------------+           |           +---------------------------+
             |                                        v                                       |
             v                                +---------------+                               v
+------------------------+                    | SQLite Database|                     +-----------------+
| HIPAA/Act Pre-screen   |                    | (healthassist) |                     |  OpenAI API or  |
|  & PII Encryption      |                    +----------------+                     |Fallback Engine  |
+------------------------+                           |                               +-----------------+
                                                     v
                                             +---------------+
                                             |  Audit Trail  |
                                             | (Hash Chain)  |
                                             +---------------+
```

## 2. Technical Architecture & Security Controls

### 2.1. PII/PHI Cryptographic Protection (GDPR / HIPAA)
Sensitive patient fields (`patient_name`, `ssn`, `dob`, `symptoms`) are cryptographically secured before database storage — including `symptoms`, which is clinical health information and not just a direct identifier:
- **Algorithm:** AES-128 in CBC mode using PKCS7 padding (via `cryptography.fernet.Fernet`).
- **Key Storage:** If `DATABASE_ENCRYPTION_KEY` is set (expected to come from a KMS/Vault in
  production), it is used directly if it's already a valid Fernet key, or deterministically
  derived via SHA-256 if it's a passphrase — never truncated/padded, which would silently
  discard entropy. If unset, a random key is generated on first run and persisted to
  `database/encryption.key` (git-ignored) — acceptable for local testing only; a real
  deployment must set `DATABASE_ENCRYPTION_KEY` from a KMS/Vault instead of relying on that
  file. There is no hardcoded key anywhere in source.
- Plaintext fields are decrypted dynamically only when accessed by an authorized clinician.

### 2.1.1. Minimum-Necessary Access (HIPAA 45 CFR 164.502(b))
`GET /api/assessments` (the case queue) returns a masked summary — SSN reduced to
its last 4 digits, DOB reduced to birth year — rather than every patient's full
identifiers in one bulk response. Full unmasked identifiers are only returned by
`GET /api/assessments/{id}`, fetched one case at a time when a clinician
explicitly opens it. Name and symptoms remain unmasked in the queue view since
both are clinically necessary to triage a caseload at a glance; SSN and exact
DOB are pure identifiers with no such need.

### 2.2. Input Redaction & Governance (Article 10 / HIPAA)
Free-text symptom logs are screened in `backend/compliance.py` before model inference:
- **Demographics:** Sensitive profiling identifiers (religion, politics, ethnicity) are redacted.
- **PII Leakage:** Regex-based filters search and redact SSN, Email, and Phone formats to prevent leaking patient PII to external APIs.
- **Date of birth:** never sent to the model, the audit log, or any external API in raw form.
  `dob_to_age_years()` reduces it to an integer age before it reaches the prompt — the only
  place the raw DOB is stored is the encrypted `dob_encrypted` column, for clinician review.

### 2.3. Model Robustness & Fallback (Article 15)
If connection errors or timeout failures occur when calling the OpenAI API, the system gracefully degrades to `LOCAL_CLINICAL_HEURISTIC_V2`. This local engine applies deterministic clinical triage thresholds to calculate the recommendation.

### 2.4. Audit Chain Traceability (Article 12 / ISO 42001 Control A.6)
Every consultation insert creates a hash-chained audit log. The SHA-256 hash of each log incorporates the hash of the preceding log (`prev_hash`), ensuring that retroactive database modifications break the chain and are immediately detected.

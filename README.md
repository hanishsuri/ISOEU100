# HealthAssist AI: Clinical Decision-Support Demonstrator

HealthAssist AI is a clinical symptom summarizer and triage-support demonstrator built to show **technical controls aligned with** ISO 42001:2023 (AI Management System), the EU AI Act (Articles 9–15), and the NIST AI RMF 1.0.

> [!IMPORTANT]
> **Scope honesty.** This repository demonstrates *technical* controls. It is not a certified-compliant system, and no repository can be one: ISO 42001 certification requires an accredited audit of the organization's actual AI management system; EU AI Act high-risk compliance additionally requires a quality management system, conformity assessment, EU database registration, and post-market monitoring; and handling real patient data under HIPAA requires a documented Security Rule risk analysis, workforce training, and Business Associate Agreements with every subprocessor (including OpenAI) — none of which live in code. See [docs/compliance_matrix.md](docs/compliance_matrix.md) for the full control-by-control mapping and its explicit out-of-scope section.

## Technical Controls Implemented

* **Data protection (ISO 42001 Control A.7 / GDPR / HIPAA):** Field-level Fernet encryption for patient name, SSN, DOB, and symptoms at rest. The encryption key is never hardcoded — it's sourced from `DATABASE_ENCRYPTION_KEY` (expected to be KMS/Vault-backed in production) or, if unset, a random key generated once and persisted locally (git-ignored, local-testing only).
* **Data minimization:** Date of birth is reduced to a derived integer age before it ever reaches a model prompt or an audit log — the raw DOB never leaves the encrypted column. The case-queue list view masks SSN (last 4 digits) and DOB (year only); full unmasked identifiers require explicitly opening one case at a time.
* **Data governance (ISO 42001 Control A.7 / Article 10):** Regex-based redaction strips SSNs, emails, and phone numbers from free-text symptom input before it reaches the model, and flags protected-attribute mentions (race, religion, politics).
* **Human oversight (ISO 42001 Control A.9 / Article 14):** No triage recommendation is actionable until an authenticated clinician logs an explicit Approve / Override (with written rationale) / Reject decision. Clinician identity is resolved server-side from a bearer token, never from client input.
* **Traceability (ISO 42001 Control A.6 / Article 12):** Full prompts, raw model responses, parameters, and every human decision are recorded in a tamper-evident, hash-chained audit log — verifiable via `/api/compliance/audit-chain`.
* **Output-disparity monitoring (NIST MEASURE):** Tracks triage HIGH-risk rate by Insurance Provider (Public vs. Private) and auto-flags statistically significant disparities into the risk register.
* **Robustness (Article 15):** A deterministic local fallback triage engine (`LOCAL_CLINICAL_HEURISTIC_V2`) takes over if the OpenAI API is unreachable, measured by a runnable evaluation harness (`backend/evaluation.py`) rather than asserted.

## Known Limitations (deliberately documented, not hidden)

* Symptom-based keyword redaction misses paraphrases, misspellings, and non-English text.
* The evaluation dataset is synthetic and encodes the same clinical rules the fallback engine implements, so near-perfect scores are expected by construction — see the caveat in [instructions_for_use.md](docs/instructions_for_use.md). This is not clinical validation.
* The OpenAI-backed inference path is unevaluated; measured metrics cover only the fallback engine.
* SQLite storage, single-node; no backup/retention automation beyond the documented minimum.
* Demo clinician tokens in `database/demo_credentials.json` and the local fallback encryption key in `database/encryption.key` are local-testing conveniences — never ship either pattern to a real deployment.

## Setup Instructions

### 1. Run the FastAPI Backend
```bash
cd health-assist
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m uvicorn backend.main:app --reload
```
The backend server runs at `http://localhost:8000`. On first startup, it seeds two demo clinicians (`Dr. Alice Smith` and `Dr. Ben Jones`) and writes their bearer tokens to `database/demo_credentials.json`. Copy one of these tokens to sign in. It also generates a local encryption key at `database/encryption.key` if `DATABASE_ENCRYPTION_KEY` isn't set — see the Known Limitations note above.

### 2. Run the React Frontend
```bash
cd health-assist
npm install
npm run dev
```
The Vite server starts at `http://localhost:5173`.

### 3. Generate the Evaluation Report
```bash
.venv/bin/python -m backend.evaluation
```
Produces `docs/eval_results.json`, served at `/api/compliance/model-eval`.

### 4. Run the Compliance Test Suite
```bash
.venv/bin/pytest -c pytest.ini
```
Covers: auth enforcement, PII/PHI redaction (not rejection), DOB never reaching the model/audit log, field-level encryption (including that the key isn't a hardcoded constant), minimum-necessary masking on the list endpoint vs. full detail on single-record fetch, oversight rules + clinician attribution, bias-metrics consistency, evaluation-harness validity, and audit-chain tamper detection.

## Documentation
* **Compliance Matrix (with out-of-scope register):** [docs/compliance_matrix.md](docs/compliance_matrix.md)
* **Risk Management Framework:** [docs/risk_management_framework.md](docs/risk_management_framework.md)
* **Technical Documentation:** [docs/technical_documentation.md](docs/technical_documentation.md)
* **Instructions for Use:** [docs/instructions_for_use.md](docs/instructions_for_use.md)
* **Measured Evaluation Results:** [docs/eval_results.json](docs/eval_results.json)

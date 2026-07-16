# Compliance Matrix: HealthAssist AI (ISO 42001:2023 & EU AI Act)

Maps HealthAssist AI's technical controls to standard clauses and regulations. A control listed here is *demonstrated in code*, not *certified* — neither ISO 42001 nor the EU AI Act grants a "compliant" status to a codebase. See the bottom of this document for what's structurally out of scope.

> [!NOTE]
> **Clause/control number mapping caveat:** ISO 42001:2023's clause and Annex A text is copyrighted and not reproduced here; the mappings below are this project's best-effort interpretation based on the publicly available control *titles*, not a review against the licensed standard text. Verify these against your organization's copy of the standard before relying on them for an actual audit or certification submission.

## 1. ISO 42001:2023 AI Management System (AIMS) — technical controls demonstrated

| Standard Clause / Control | Focus Area | Code / File Reference | What is actually implemented |
| :--- | :--- | :--- | :--- |
| **Clause 8.2** | AI System Impact Assessment | [risk_management_framework.md](risk_management_framework.md) | Hazard identification and risk treatment matrix for this specific system. |
| **Clause 8.3** | AI System Requirements & Design | [technical_documentation.md](technical_documentation.md) | System requirements, inputs/outputs, and architecture description. |
| **Clause 8.4** | AI System Development & Integration | [backend/main.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/main.py), `requirements.txt` | OpenAI SDK integration with a deterministic fallback engine, pinned dependency versions. |
| **Clause 8.5** | AI System Evaluation | [backend/evaluation.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/evaluation.py), `data/eval_dataset.json` | Runnable evaluation harness measuring precision/recall/accuracy of the fallback engine specifically (see caveats in [instructions_for_use.md](instructions_for_use.md)). |
| **Control A.7 (Data for AI systems)** | Data Governance & PHI/PII Protection | [backend/compliance.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/compliance.py) (`encrypt_field`, `screen_and_redact`, `dob_to_age_years`) | Field-level Fernet encryption for direct identifiers and clinical PHI at rest; DOB reduced to a non-identifying derived age before it ever reaches a prompt or log; regex-based PII redaction (SSN/email/phone) from free-text before it reaches the model. |
| **Control A.9 (Use of AI systems)** | Human Oversight in Operation | [backend/main.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/main.py) (`PENDING_APPROVAL` gate, `get_current_clinician`) | No triage output is actionable without an authenticated clinician's explicit approve/override/reject decision; overrides require a written rationale. |
| **Control A.6 (AI system life cycle)** | Traceability & Audit Logging | [backend/compliance.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/compliance.py) (`append_audit_entry`, `verify_audit_chain`) | Hash-chained audit log covering the full life cycle of each consultation (creation, model response, human decision); tampering is detectable via chain re-verification. |

## 2. Regulation (EU) 2024/1689 (EU AI Act) — technical controls demonstrated

| Article | Focus Area | Code / File Reference | What is actually implemented |
| :--- | :--- | :--- | :--- |
| **Article 9** | Risk Management System | [backend/compliance.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/compliance.py) (`log_risk_event`, `get_bias_metrics`), `risk_logs` table | Live risk register: API failures, PII/PHI redactions, and output-disparity flags all logged automatically. |
| **Article 10** | Data & Data Governance | [backend/compliance.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/compliance.py) (`screen_and_redact`) | Protected-attribute terms redacted from free-text model input; DOB never sent to the model at all (see A.7 above). |
| **Article 11** | Technical Documentation | [technical_documentation.md](technical_documentation.md) | Architecture, data flow, and security control documentation — addresses the topics Annex IV requires, not a claim of Annex IV sign-off. |
| **Article 12** | Record-Keeping | [backend/compliance.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/compliance.py) (`verify_audit_chain`) | Full prompt/response/parameters logged per inference in a tamper-evident hash chain. |
| **Article 13** | Transparency | [instructions_for_use.md](instructions_for_use.md), `frontend/src/App.tsx` | UI disclosure banner; instructions document scope, limitations, and measured (not asserted) accuracy. |
| **Article 14** | Human Oversight | [backend/auth.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/auth.py) (`get_current_clinician`) | Every oversight action is attributed to a bearer-token-authenticated clinician resolved server-side, never a client-supplied identity. |
| **Article 15** | Robustness & Cybersecurity | [backend/risk_engine.py](file:///Users/hanishsuri/Documents/border-guard-ai/health-assist/backend/risk_engine.py) | Deterministic fallback engine on API failure; field-level encryption for all identifier and PHI columns backed by a non-hardcoded key (KMS/Vault-sourced in production, locally generated and git-ignored otherwise). |

## 3. Out of scope (required for real compliance, cannot live in this repo)

| Requirement | Why it's out of scope |
| :--- | :--- |
| ISO 42001 certification | Requires an accredited third-party audit of the organization's actual AIMS (Clauses 4–10: context, leadership, planning, support, operation, performance evaluation, improvement) — organizational process, not code. |
| EU AI Act Art 17/43/48/49/72 (QMS, conformity assessment, CE marking, registration, post-market monitoring) | Organizational and administrative obligations on the provider, not implementable in a repository. |
| HIPAA Security Rule compliance | Requires a documented risk analysis (45 CFR 164.308(a)(1)), workforce training, a Business Associate Agreement with OpenAI (or any subprocessor handling PHI), breach notification procedures, and physical/administrative safeguards — none of which are code. |
| Clinical validation | The measured accuracy figures cover a synthetic, self-consistent test set for the fallback engine only — not a substitute for clinical trial or real-world validation data. |

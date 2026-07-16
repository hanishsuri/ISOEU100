# Risk Management Framework: HealthAssist AI

Documents the risk-management lifecycle for this system, addressing the topics ISO 42001:2023 Clause 8.2 and EU AI Act Article 9 require — not itself a certification of an organization-wide AI management system.

## 1. System Risks & Treatment Matrix

| Risk ID | Hazard / Risk Description | Potential Impact | Treatment & Mitigation Control |
| :--- | :--- | :--- | :--- |
| **R-01** | AI model triage hallucination (false negative on critical symptom). | Delay in patient care or urgent referral. | Mandatory authenticated human oversight checkoff; clinicians can override AI risk scoring. |
| **R-02** | External AI provider leaks patient PII (e.g. SSN in symptoms, or DOB as a direct identifier). | Patient privacy breach, HIPAA violation. | Pre-screening regex-based redactor strips SSN, emails, and phones from symptom text before API requests. Date of birth never reaches the prompt at all — `dob_to_age_years()` reduces it to an integer age before the request is built (fixed 2026-07-16; the prior version sent raw DOB mislabeled as "Age"). |
| **R-03** | Algorithmic bias based on socio-economic class (Insurance Provider). | Systemic disparity in care recommendation. | NIST MEASURE output-disparity monitor flags high-risk triage rate differences between Public vs. Private insurance. |
| **R-04** | API timeout or external connection downtime. | Support system unavailability. | Fallback clinical rule engine triggers locally if the OpenAI API is unreachable. |
| **R-05** | Unauthorized database access to patient records. | Exfiltration of PII and health history. | Field-level Fernet encryption of patient Name, SSN, DOB, and Symptoms at rest, keyed by a KMS/Vault-sourced (or locally-generated, never hardcoded) encryption key (fixed 2026-07-16; the prior version used a fixed string literal baked into source control, and left `symptoms` unencrypted). |
| **R-06** | Bulk exposure of patient identifiers via the case-list API. | A single API call could return every patient's full SSN/DOB, violating the HIPAA minimum-necessary standard. | `GET /api/assessments` returns masked SSN/DOB; full identifiers require opening one case at a time via `GET /api/assessments/{id}` (fixed 2026-07-16). |

## 2. Risk Registry Logs (`risk_logs`)
The system logs active hazards dynamically to the SQLite database (e.g., API timeouts, output-disparity warnings, PII redactions) and surfaces them in the compliance control panel. Clinicians can review and resolve these issues to complete the risk lifecycle.

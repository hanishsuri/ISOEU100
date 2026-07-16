# Instructions for Use: HealthAssist AI Operational Guide

Written for clinicians, addressing the topics ISO 42001:2023 Control A.4 and EU AI Act Article 13 require operators to be given — not itself a certification.

## 1. System Scope & Limitations

HealthAssist AI is an AI-based clinical decision-support system. It is designed to assist, not replace, clinical judgment:
- **Intended Use:** Summarizing patient symptom statements and recommending primary triage levels (LOW, MEDIUM, HIGH) to streamline caseloads.
- **Out of Scope:** This system does **not** make diagnostic decisions. It does not prescribe medications, order laboratory tests, or directly direct patient treatment.
- **API Scope:** Measured metrics below cover only the local deterministic fallback engine (`LOCAL_CLINICAL_HEURISTIC_V2`). The OpenAI completions API is unevaluated.

## 2. Measured Accuracy Report

> [!WARNING]
> **Read before quoting these numbers.** They are computed by `backend/evaluation.py` against a **synthetic, hand-labeled dataset whose labels encode the same clinical rules the fallback engine implements** — near-perfect agreement is expected *by construction*, not evidence that the engine performs well on real patients. This is **not clinical validation**. Real validation would require a representative, independently labeled dataset and is out of scope for this demonstrator. The one thing this harness has already proven useful for: catching a real regression (the prior engine version scored lower here after missing a case category), so its ongoing value is regression protection, not a performance claim.

- **Accuracy:** 100% (on the synthetic self-consistent dataset described above)
- **Precision:** 1.0
- **Recall:** 1.0
- **False Positive Rate:** 0.0

## 3. Human Oversight Operational Guidelines

Clinicians must review each AI summary and suggested triage level.

To complete a case review:
1. Verify the patient's identity against the clinical record.
2. Confirm the declared symptom duration aligns with the notes.
3. Review any redacted PII/PHI flags — a flag means protected-attribute or PII text was stripped from what the model saw; the original text is still visible to you above it.
4. Select the appropriate action: **Approve AI Summary** (if correct), **Override AI Triage** (provide written rationale if changing risk level), or **Reject Case**.

## 4. Accessing Patient Records

The case queue shows a masked SSN (last 4 digits) and birth year only, not full identifiers — this is intentional (minimum-necessary access). Open a specific case to see the full record, including the complete SSN and date of birth, for that patient only.

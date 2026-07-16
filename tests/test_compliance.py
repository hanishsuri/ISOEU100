import json
import os
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.auth import create_clinician
from backend.compliance import (
    REDACTION_PLACEHOLDER,
    PII_REDACTION_PLACEHOLDER,
    dob_to_age_years,
    get_bias_metrics,
    screen_and_redact,
    verify_audit_chain,
    decrypt_field,
    ENCRYPTION_KEY,
)
from backend.database import get_db_connection
from backend.evaluation import run_evaluation
from backend.main import app

client = TestClient(app)


def _auth_headers() -> tuple[dict, str]:
    """Create a fresh clinician and return (headers, clinician_id)."""
    clinician_id = f"CLN-TEST-{uuid.uuid4().hex[:8]}"
    token = create_clinician(clinician_id, f"Test Clinician {clinician_id}")
    return {"Authorization": f"Bearer {token}"}, clinician_id


def _force_fallback():
    """Point the app at the deterministic engine (no real API key)."""
    os.environ["OPENAI_API_KEY"] = "replace-me"


VALID_PAYLOAD = {
    "patient_name": "John Doe",
    "ssn": "123-45-6789",
    "dob": "1980-05-15",
    "symptoms": "Mild cough and seasonal allergies, no fever.",
    "declared_duration": 4,
    "insurance_provider": "PUBLIC",
}


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_endpoints_require_authentication():
    # Enforce authentication on sensitive consultation and compliance endpoints
    assert client.post("/api/assessments", json=VALID_PAYLOAD).status_code in (401, 403)
    assert client.get("/api/assessments").status_code in (401, 403)
    assert client.get("/api/audit-logs").status_code in (401, 403)
    assert client.get("/api/compliance/metrics").status_code in (401, 403)

    bad = {"Authorization": "Bearer not-a-real-token"}
    assert client.get("/api/assessments", headers=bad).status_code == 401


def test_pii_and_protected_attributes_redacted_from_model_input():
    _force_fallback()
    headers, _ = _auth_headers()
    payload = dict(VALID_PAYLOAD)
    # Inject protected attributes ("religion") and HIPAA PII (email, phone)
    payload["symptoms"] = "Patient is of religious beliefs and reported symptoms via email patient@test.com and phone 123-456-7890."

    response = client.post("/api/assessments", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()

    # Original text preserved for clinical portal review
    assert "religious" in data["symptoms"]
    assert "patient@test.com" in data["symptoms"]
    
    # Governance flags recorded
    flags = json.loads(data["governance_flags"])
    assert len(flags) >= 3  # Matches: religion, email, phone

    # Check that model prompt had redaction applied
    conn = get_db_connection()
    audit = conn.execute(
        "SELECT full_prompt FROM audit_logs WHERE consultation_id = ? AND human_action = 'PENDING_APPROVAL'",
        (data["id"],),
    ).fetchone()
    conn.close()
    
    assert audit is not None
    prompt = audit["full_prompt"]
    assert REDACTION_PLACEHOLDER in prompt
    assert PII_REDACTION_PLACEHOLDER in prompt
    assert "religious" not in prompt
    assert "patient@test.com" not in prompt
    assert "123-456-7890" not in prompt


def test_screen_and_redact_unit():
    # Standard symptom log
    redacted, flags = screen_and_redact("Mild body pain and headache.")
    assert flags == []
    assert redacted == "Mild body pain and headache."

    # Sensitive logs with PII
    redacted, flags = screen_and_redact("Study of RELIGION. Email: bob@gmail.com, SSN: 999-99-9999")
    assert len(flags) == 3
    assert "RELIGION" not in redacted
    assert "bob@gmail.com" not in redacted
    assert "999-99-9999" not in redacted
    assert REDACTION_PLACEHOLDER in redacted
    assert PII_REDACTION_PLACEHOLDER in redacted


def test_pii_field_encryption():
    _force_fallback()
    headers, _ = _auth_headers()
    
    # Create patient case
    response = client.post("/api/assessments", json=VALID_PAYLOAD, headers=headers)
    assert response.status_code == 200
    data = response.json()
    case_id = data["id"]

    # Verify that values stored in SQLite are raw encrypted binary blobs — including
    # symptoms, which is clinical PHI and not just a direct identifier.
    conn = get_db_connection()
    row = conn.execute(
        "SELECT patient_name_encrypted, ssn_encrypted, dob_encrypted, symptoms_encrypted "
        "FROM consultations WHERE id = ?",
        (case_id,),
    ).fetchone()
    conn.close()

    assert row is not None
    assert isinstance(row["patient_name_encrypted"], bytes)
    assert isinstance(row["ssn_encrypted"], bytes)
    assert isinstance(row["dob_encrypted"], bytes)
    assert isinstance(row["symptoms_encrypted"], bytes)

    # Binary encrypted bytes should not match the plaintext inputs
    assert row["patient_name_encrypted"] != VALID_PAYLOAD["patient_name"].encode()
    assert row["ssn_encrypted"] != VALID_PAYLOAD["ssn"].encode()
    assert row["symptoms_encrypted"] != VALID_PAYLOAD["symptoms"].encode()

    # Decryption should successfully reconstruct the plaintext values
    assert decrypt_field(row["patient_name_encrypted"]) == VALID_PAYLOAD["patient_name"]
    assert decrypt_field(row["ssn_encrypted"]) == VALID_PAYLOAD["ssn"]
    assert decrypt_field(row["dob_encrypted"]) == VALID_PAYLOAD["dob"]
    assert decrypt_field(row["symptoms_encrypted"]) == VALID_PAYLOAD["symptoms"]


def test_list_endpoint_masks_identifiers_detail_endpoint_reveals_full():
    # HIPAA minimum-necessary standard (45 CFR 164.502(b)): the case queue must not
    # bulk-expose every patient's full SSN/DOB; only an explicit single-case fetch should.
    _force_fallback()
    headers, _ = _auth_headers()
    payload = dict(VALID_PAYLOAD)
    payload["ssn"] = "987-65-4321"
    payload["dob"] = "1975-08-02"

    created = client.post("/api/assessments", json=payload, headers=headers).json()
    case_id = created["id"]

    listing = client.get("/api/assessments", headers=headers)
    assert listing.status_code == 200
    summaries = listing.json()
    this_case = next(s for s in summaries if s["id"] == case_id)

    assert "ssn" not in this_case
    assert "dob" not in this_case
    assert this_case["ssn_masked"] == "***-**-4321"
    assert this_case["dob_year"] == "1975"
    # Full SSN/DOB must not leak into the list response in any form.
    assert "987-65-4321" not in json.dumps(summaries)
    assert "1975-08-02" not in json.dumps(summaries)
    # Name and symptoms ARE expected in full — both are needed to triage a queue.
    assert this_case["patient_name"] == payload["patient_name"]
    assert this_case["symptoms"] == payload["symptoms"]

    detail = client.get(f"/api/assessments/{case_id}", headers=headers)
    assert detail.status_code == 200
    full = detail.json()
    assert full["ssn"] == "987-65-4321"
    assert full["dob"] == "1975-08-02"

    assert client.get("/api/assessments/999999", headers=headers).status_code == 404


def test_dob_never_reaches_model_prompt_or_audit_log():
    # DOB is a direct HIPAA identifier (45 CFR 164.514(b)(2)) and must never leave the
    # encrypted consultations.dob_encrypted column — not to the model, not to the audit log.
    _force_fallback()
    headers, _ = _auth_headers()
    payload = dict(VALID_PAYLOAD)
    payload["dob"] = "1990-03-17"

    response = client.post("/api/assessments", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()

    conn = get_db_connection()
    audit = conn.execute(
        "SELECT full_prompt FROM audit_logs WHERE consultation_id = ? AND human_action = 'PENDING_APPROVAL'",
        (data["id"],),
    ).fetchone()
    conn.close()

    assert audit is not None
    assert "1990-03-17" not in audit["full_prompt"]
    # The derived integer age IS expected in the prompt (clinically relevant, not identifying).
    assert f"Age: {dob_to_age_years('1990-03-17')}" in audit["full_prompt"]


def test_dob_to_age_years_unit():
    from datetime import date

    today = date.today()
    # Someone born exactly N years ago today is N.
    dob = date(today.year - 30, today.month, today.day).isoformat()
    assert dob_to_age_years(dob) == 30
    # Someone whose birthday hasn't happened yet this year is one less.
    future_month_day = date(today.year - 30, 12, 31) if (today.month, today.day) != (12, 31) else date(today.year - 30, 1, 1)
    expected = 30 if (future_month_day.month, future_month_day.day) <= (today.month, today.day) else 29
    assert dob_to_age_years(future_month_day.isoformat()) == expected


def test_encryption_key_is_not_a_hardcoded_constant():
    # The old implementation used a fixed string literal baked into source control as the
    # fallback key — equivalent to no encryption for anyone who can read the repo. Guard
    # against that regression: the resolved key must not derive from that known constant,
    # and a local key file (not source control) must be what backs it when no
    # DATABASE_ENCRYPTION_KEY is configured.
    import base64
    old_hardcoded_source_string = "HealthAssistComplianceDemoKey32B="
    key_bytes = old_hardcoded_source_string.encode("utf-8")
    key_bytes = key_bytes + b"x" * (32 - len(key_bytes)) if len(key_bytes) < 32 else key_bytes[:32]
    old_derived_key = base64.urlsafe_b64encode(key_bytes)
    assert ENCRYPTION_KEY != old_derived_key

    from backend.compliance import _LOCAL_KEY_PATH
    if os.getenv("DATABASE_ENCRYPTION_KEY", "").strip() not in ("", "replace-me"):
        pytest.skip("DATABASE_ENCRYPTION_KEY is explicitly configured in this environment")
    assert _LOCAL_KEY_PATH.exists()
    assert _LOCAL_KEY_PATH.read_bytes().strip() == ENCRYPTION_KEY


def test_fallback_heuristic_robustness():
    _force_fallback()
    headers, _ = _auth_headers()
    payload = dict(VALID_PAYLOAD)
    # Duration > 14 should trigger HIGH chronic risk level
    payload["declared_duration"] = 25

    response = client.post("/api/assessments", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["ai_risk_level"] == "HIGH"
    assert "Fallback clinical triage" in data["ai_summary"]


def test_human_oversight_rules_and_identity():
    _force_fallback()
    headers, clinician_id = _auth_headers()

    res_create = client.post("/api/assessments", json=VALID_PAYLOAD, headers=headers)
    assert res_create.status_code == 200
    case_id = res_create.json()["id"]

    # Override action without rationale fails (validation check)
    res_bad = client.post(
      f"/api/assessments/{case_id}/oversight",
      json={"action": "OVERRIDDEN", "clinician_notes": "Clinician review", "override_reason": ""},
      headers=headers,
    )
    assert res_bad.status_code == 400
    assert "override reason" in res_bad.json()["detail"].lower()

    # Valid override succeeds and logs clinician_id
    res_ok = client.post(
      f"/api/assessments/{case_id}/oversight",
      json={
          "action": "OVERRIDDEN",
          "clinician_notes": "Symptoms resolved under monitoring.",
          "override_reason": "Follow-up notes show normal vitals.",
      },
      headers=headers,
    )
    assert res_ok.status_code == 200
    updated = res_ok.json()
    assert updated["status"] == "OVERRIDDEN"
    assert updated["clinician_id"] == clinician_id


def test_bias_metrics_structure_and_consistency():
    _force_fallback()
    headers, _ = _auth_headers()
    for i in range(3):
        payload = dict(VALID_PAYLOAD)
        payload["patient_name"] = f"Patient {i}"
        client.post("/api/assessments", json=payload, headers=headers)

    metrics = get_bias_metrics()
    assert metrics["total_scored_assessments"] >= 3
    assert 0.0 <= metrics["overall_high_risk_rate"] <= 1.0
    for group in metrics["by_nationality"]:
        assert group["high_risk_count"] <= group["assessments"]
        assert 0.0 <= group["high_risk_rate"] <= 1.0


def test_audit_chain_detects_tampering():
    _force_fallback()
    headers, _ = _auth_headers()
    res = client.post("/api/assessments", json=VALID_PAYLOAD, headers=headers)
    assert res.status_code == 200

    assert verify_audit_chain()["intact"] is True

    # Tamper with the newest entry and verify chain break
    conn = get_db_connection()
    conn.execute(
        "UPDATE audit_logs SET override_reason = 'forged entry' WHERE id = (SELECT MAX(id) FROM audit_logs)"
    )
    conn.commit()
    conn.close()

    verdict = verify_audit_chain()
    assert verdict["intact"] is False
    assert verdict["first_broken_entry_id"] is not None

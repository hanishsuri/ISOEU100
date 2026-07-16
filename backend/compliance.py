import base64
import hashlib
import json
import logging
import os
import re
from datetime import date
from pathlib import Path
from typing import List, Tuple
from cryptography.fernet import Fernet

from backend.database import get_db_connection

logger = logging.getLogger(__name__)

# Path for a locally-generated key when no KMS/Vault-sourced key is configured.
# This file is git-ignored and must never be committed or shipped with a real
# deployment — see _load_or_create_local_key() below.
_LOCAL_KEY_PATH = Path(__file__).resolve().parent.parent / "database" / "encryption.key"


def _load_or_create_local_key() -> bytes:
    """Fall back to a random key persisted locally, never a hardcoded constant.

    A key baked into source control is equivalent to no encryption at all —
    anyone with repo read access could decrypt every record. If no real
    KMS/Vault-sourced key is configured via DATABASE_ENCRYPTION_KEY, generate
    a random Fernet key on first run and persist it locally so restarts don't
    lose access to already-encrypted data. This is still NOT a production
    key-management solution (see warning logged below) — a real deployment
    must set DATABASE_ENCRYPTION_KEY from a KMS/Vault.
    """
    _LOCAL_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _LOCAL_KEY_PATH.exists():
        return _LOCAL_KEY_PATH.read_bytes().strip()
    key = Fernet.generate_key()
    _LOCAL_KEY_PATH.write_bytes(key)
    logger.warning(
        "DATABASE_ENCRYPTION_KEY not set: generated a random local encryption key at %s. "
        "This is acceptable for local testing only. A real deployment MUST set "
        "DATABASE_ENCRYPTION_KEY from a KMS/Vault, or this key file becomes the sole "
        "protection for all patient PII and must be managed with the same rigor.",
        _LOCAL_KEY_PATH,
    )
    return key


def _resolve_key(configured: str) -> bytes:
    """Turn an operator-supplied DATABASE_ENCRYPTION_KEY into a valid Fernet key.

    Accepts either a real Fernet key (the expected KMS/Vault output, e.g. from
    Fernet.generate_key()) as-is, or derives a full-entropy 32-byte key from an
    arbitrary passphrase via SHA-256 — never truncates/pads with filler bytes,
    which would silently throw away entropy the operator thought they had.
    """
    try:
        Fernet(configured.encode("utf-8"))
        return configured.encode("utf-8")
    except Exception:
        pass
    if len(configured) < 16:
        raise ValueError(
            "DATABASE_ENCRYPTION_KEY is too short to be a safe passphrase (< 16 chars). "
            "Refusing to start rather than silently weaken PII encryption."
        )
    return base64.urlsafe_b64encode(hashlib.sha256(configured.encode("utf-8")).digest())


_configured_key = os.getenv("DATABASE_ENCRYPTION_KEY", "").strip()
if _configured_key and _configured_key != "replace-me":
    # An operator explicitly configured a key (expected to come from a KMS/Vault
    # in production).
    ENCRYPTION_KEY = _resolve_key(_configured_key)
else:
    ENCRYPTION_KEY = _load_or_create_local_key()

fernet = Fernet(ENCRYPTION_KEY)


def encrypt_field(val: str) -> bytes:
    """Encrypt sensitive patient PII before writing to disk."""
    return fernet.encrypt(val.encode("utf-8"))


def decrypt_field(val: bytes) -> str:
    """Decrypt sensitive patient PII when retrieved by authenticated users."""
    return fernet.decrypt(val).decode("utf-8")


def mask_ssn(ssn: str) -> str:
    """Reduce an SSN to its last 4 digits for minimum-necessary case-queue views."""
    digits = ssn[-4:] if len(ssn) >= 4 else ssn
    return f"***-**-{digits}"


def dob_to_year(dob_iso: str) -> str:
    """Reduce a DOB to birth year only, for minimum-necessary case-queue views."""
    return date.fromisoformat(dob_iso).strftime("%Y")


def dob_to_age_years(dob_iso: str) -> int:
    """Reduce a date of birth to an integer age in years.

    Date of birth is a direct identifier under HIPAA Safe Harbor (45 CFR
    164.514(b)(2)) and must never reach the model or an unencrypted log —
    only the derived age (needed for clinically relevant triage) should. The
    raw DOB stays encrypted in the consultations table for clinician review;
    this function is the ONLY thing that should touch it before it is sent
    anywhere else (a prompt, an audit log, a third-party API).
    """
    born = date.fromisoformat(dob_iso)
    today = date.today()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    return age


# Protected attributes (religion, politics, sexual orientation, race/ethnicity, age)
# that should not bias medical clinical triage outputs.
PROTECTED_ATTRIBUTE_TERMS = [
    "religion", "religious", "political opinion", "political belief",
    "union membership", "philosophical beliefs", "sexual orientation",
    "racial origin", "ethnic origin", "biometric profiling"
]

REDACTION_PLACEHOLDER = "[REDACTED-PROTECTED-ATTRIBUTE]"
PII_REDACTION_PLACEHOLDER = "[REDACTED-PII]"

# Output-disparity monitoring thresholds (NIST MEASURE)
MIN_GROUP_SIZE = 5
DISPARITY_RATIO_THRESHOLD = 1.5


def screen_and_redact(text: str) -> Tuple[str, List[str]]:
    """Sanitize and redact both protected attributes and PII from model inputs.

    Returns (redacted_text, flags).
    - Checks for sensitive categories.
    - Uses regular expressions to redact phone numbers, emails, and SSNs.
    """
    flags = []
    redacted = text

    # 1. Screen and redact protected attributes
    for term in PROTECTED_ATTRIBUTE_TERMS:
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        if pattern.search(redacted):
            flags.append(
                f"Protected attribute '{term}' redacted from model input "
                f"(EU AI Act Article 10 / ISO 42001)."
            )
            redacted = pattern.sub(REDACTION_PLACEHOLDER, redacted)

    # 2. HIPAA PII redactions (SSNs, Emails, Phone Numbers)
    # SSN pattern: XXX-XX-XXXX
    ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    if ssn_pattern.search(redacted):
        flags.append("PII Redaction: SSN pattern detected and redacted from model input.")
        redacted = ssn_pattern.sub(PII_REDACTION_PLACEHOLDER, redacted)

    # Email pattern
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    if email_pattern.search(redacted):
        flags.append("PII Redaction: Email address detected and redacted from model input.")
        redacted = email_pattern.sub(PII_REDACTION_PLACEHOLDER, redacted)

    # Phone pattern (e.g. 123-456-7890 or 123-3456)
    phone_pattern = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
    if phone_pattern.search(redacted):
        flags.append("PII Redaction: Phone number detected and redacted from model input.")
        redacted = phone_pattern.sub(PII_REDACTION_PLACEHOLDER, redacted)

    return redacted, flags


def log_risk_event(hazard_type: str, severity: str, details: str) -> int:
    """Article 9 / ISO 42001 AIMS risk registry: log anomalies or system hazards."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO risk_logs (hazard_type, severity, details, resolved) VALUES (?, ?, ?, 0)",
        (hazard_type, severity, details),
    )
    conn.commit()
    inserted_id = cursor.lastrowid
    conn.close()
    return inserted_id


def resolve_risk_event(risk_id: int) -> None:
    conn = get_db_connection()
    conn.execute("UPDATE risk_logs SET resolved = 1 WHERE id = ?", (risk_id,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Tamper-evident audit chain (Article 12 / ISO 42001 Traceability)
# ---------------------------------------------------------------------------

def _entry_content_hash(consultation_id, model_name, prompt_hash, full_prompt,
                        model_response, model_params, api_latency_ms,
                        human_action, override_reason, clinician_id, prev_hash) -> str:
    payload = json.dumps(
        [consultation_id, model_name, prompt_hash, full_prompt, model_response,
         model_params, api_latency_ms, human_action, override_reason,
         clinician_id, prev_hash],
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_entry(
    conn,
    *,
    consultation_id: int,
    model_name: str,
    prompt_hash: str,
    full_prompt: str | None,
    model_response: str | None,
    model_params: str | None,
    api_latency_ms: int,
    human_action: str,
    override_reason: str | None,
    clinician_id: str,
) -> int:
    cursor = conn.cursor()
    prev = cursor.execute(
        "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = prev["entry_hash"] if prev and prev["entry_hash"] else "GENESIS"

    entry_hash = _entry_content_hash(
        consultation_id, model_name, prompt_hash, full_prompt, model_response,
        model_params, api_latency_ms, human_action, override_reason,
        clinician_id, prev_hash,
    )
    cursor.execute(
        """
        INSERT INTO audit_logs (
            consultation_id, model_name, prompt_hash, full_prompt, model_response,
            model_params, api_latency_ms, human_action, override_reason,
            clinician_id, prev_hash, entry_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (consultation_id, model_name, prompt_hash, full_prompt, model_response,
         model_params, api_latency_ms, human_action, override_reason,
         clinician_id, prev_hash, entry_hash),
    )
    conn.commit()
    return cursor.lastrowid


def verify_audit_chain() -> dict:
    """Recompute the hash chain over all audit entries; report any tampering."""
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
    conn.close()

    prev_hash = "GENESIS"
    for row in rows:
        if row["entry_hash"] is None:
            continue
        expected = _entry_content_hash(
            row["consultation_id"], row["model_name"], row["prompt_hash"],
            row["full_prompt"], row["model_response"], row["model_params"],
            row["api_latency_ms"], row["human_action"], row["override_reason"],
            row["clinician_id"], row["prev_hash"],
        )
        if row["prev_hash"] != prev_hash or row["entry_hash"] != expected:
            return {"intact": False, "first_broken_entry_id": row["id"], "entries_checked": len(rows)}
        prev_hash = row["entry_hash"]
    return {"intact": True, "first_broken_entry_id": None, "entries_checked": len(rows)}


# ---------------------------------------------------------------------------
# Metrics (NIST MEASURE / ISO 42001 Objectives)
# ---------------------------------------------------------------------------

def get_compliance_metrics() -> dict:
    """Collect clinical human-in-the-loop and risk objectives metrics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM consultations")
    total_consultations = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM consultations WHERE status != 'PENDING_APPROVAL'")
    total_completed = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM consultations WHERE status = 'APPROVED'")
    approved_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM consultations WHERE status = 'OVERRIDDEN'")
    overridden_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM consultations WHERE status = 'REJECTED'")
    rejected_count = cursor.fetchone()[0]

    override_rate = 0.0
    if total_completed > 0:
        override_rate = round((overridden_count / total_completed) * 100, 2)

    cursor.execute("SELECT COUNT(*) FROM risk_logs WHERE resolved = 0")
    active_risks_count = cursor.fetchone()[0]

    rows = cursor.execute(
        "SELECT id, timestamp, hazard_type, severity, details FROM risk_logs WHERE resolved = 0 ORDER BY id DESC"
    ).fetchall()
    active_risks_list = [dict(row) for row in rows]

    conn.close()

    return {
        "total_assessments": total_consultations,  # Keep key name for frontend compatibility
        "total_completed": total_completed,
        "approved": approved_count,
        "overridden": overridden_count,
        "rejected": rejected_count,
        "human_override_rate": override_rate,
        "active_risks_count": active_risks_count,
        "active_risks": active_risks_list,
    }


def get_bias_metrics() -> dict:
    """Measure output disparities in triage decisions based on Insurance Provider.

    This ensures fair assessment and triage recommendations for public and private insurance patients.
    """
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT insurance_provider, ai_risk_level FROM consultations WHERE ai_risk_level IS NOT NULL"
    ).fetchall()
    conn.close()

    total = len(rows)
    overall_high = sum(1 for r in rows if r["ai_risk_level"] == "HIGH")
    overall_rate = (overall_high / total) if total else 0.0

    groups: dict[str, dict] = {}
    for row in rows:
        g = groups.setdefault(row["insurance_provider"], {"n": 0, "high": 0})
        g["n"] += 1
        if row["ai_risk_level"] == "HIGH":
            g["high"] += 1

    flagged = []
    by_nationality = []  # Keep key name for frontend mapping convenience
    for provider, g in sorted(groups.items()):
        rate = g["high"] / g["n"]
        ratio = (rate / overall_rate) if overall_rate > 0 else None
        is_flagged = (
            g["n"] >= MIN_GROUP_SIZE
            and overall_rate > 0
            and rate > overall_rate * DISPARITY_RATIO_THRESHOLD
        )
        by_nationality.append(
            {
                "nationality": provider,  # Maps to nationality in frontend
                "assessments": g["n"],
                "high_risk_count": g["high"],
                "high_risk_rate": round(rate, 4),
                "ratio_to_overall": round(ratio, 2) if ratio is not None else None,
                "flagged": is_flagged,
                "sufficient_sample": g["n"] >= MIN_GROUP_SIZE,
            }
        )
        if is_flagged:
            flagged.append(provider)

    if flagged:
        log_risk_event(
            hazard_type="OUTPUT_DISPARITY",
            severity="HIGH",
            details=(
                f"HIGH-risk rate disparity detected for Insurance Provider: {', '.join(flagged)} "
                f"(> {DISPARITY_RATIO_THRESHOLD}x overall rate of {overall_rate:.2%}). "
                f"Verify there is no socio-economic bias in the AI model parameters."
            ),
        )

    return {
        "total_scored_assessments": total,
        "overall_high_risk_rate": round(overall_rate, 4),
        "min_group_size_for_flagging": MIN_GROUP_SIZE,
        "disparity_ratio_threshold": DISPARITY_RATIO_THRESHOLD,
        "by_nationality": by_nationality,
        "flagged_nationalities": flagged,
    }

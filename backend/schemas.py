from typing import Optional
from pydantic import BaseModel, Field


class PatientConsultationPayload(BaseModel):
    patient_name: str = Field(..., min_length=2, max_length=100)
    ssn: str = Field(..., pattern=r"^\d{3}-\d{2}-\d{4}$")  # Standard US SSN format for PII
    dob: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")   # YYYY-MM-DD
    symptoms: str = Field(..., min_length=5, max_length=1000)
    declared_duration: int = Field(..., gt=0, lt=366)
    insurance_provider: str = Field(..., pattern="^(PUBLIC|PRIVATE)$")


class ConsultationResponse(BaseModel):
    """Full record, including unmasked direct identifiers (SSN, DOB).

    Only returned from the create endpoint (the submitting clinician already has
    the values they just typed), the oversight endpoint (the clinician is actively
    reviewing that specific case), and the single-record detail endpoint. Never
    returned in bulk — see ConsultationSummary.
    """
    id: int
    patient_name: str
    ssn: str
    dob: str
    symptoms: str
    declared_duration: int
    insurance_provider: str
    ai_risk_level: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_summary: Optional[str] = None
    status: str
    clinician_notes: Optional[str] = None
    clinician_id: Optional[str] = None
    created_at: str
    governance_flags: str = "[]"


class ConsultationSummary(BaseModel):
    """Minimum-necessary record for the case queue (HIPAA minimum-necessary
    standard, 45 CFR 164.502(b)): SSN and exact DOB are pure identifiers with no
    triage value, so they're masked here. Name and symptoms ARE clinically
    necessary to scan a queue, so they stay in full. Full unmasked identifiers
    require explicitly opening a case via GET /api/assessments/{id}.
    """
    id: int
    patient_name: str
    ssn_masked: str
    dob_year: str
    symptoms: str
    declared_duration: int
    insurance_provider: str
    ai_risk_level: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_summary: Optional[str] = None
    status: str
    clinician_notes: Optional[str] = None
    clinician_id: Optional[str] = None
    created_at: str
    governance_flags: str = "[]"


class OversightPayload(BaseModel):
    # Clinician's oversight action: APPROVED, OVERRIDDEN, or REJECTED
    action: str = Field(..., pattern="^(APPROVED|OVERRIDDEN|REJECTED)$")
    clinician_notes: str = Field(..., min_length=5, max_length=1000)
    override_reason: Optional[str] = Field(None, max_length=500)


class RiskLogEntry(BaseModel):
    id: int
    timestamp: str
    hazard_type: str
    severity: str
    details: str
    resolved: int


class RiskEventPayload(BaseModel):
    hazard_type: str = Field(..., min_length=3, max_length=50)
    severity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH)$")
    details: str = Field(..., min_length=5, max_length=1000)


class AuditLogEntrySchema(BaseModel):
    id: int
    consultation_id: int
    timestamp: str
    model_name: str
    prompt_hash: str
    full_prompt: Optional[str] = None
    model_response: Optional[str] = None
    model_params: Optional[str] = None
    api_latency_ms: int
    human_action: str
    override_reason: Optional[str]
    clinician_id: str
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None

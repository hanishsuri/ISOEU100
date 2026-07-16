"""Deterministic fallback clinical triage engine (ISO 42001 & EU AI Act Article 15).

Exercises local rule-based safety controls if the OpenAI API is unreachable.
"""

FALLBACK_MODEL_NAME = "LOCAL_CLINICAL_HEURISTIC_V2"
FALLBACK_CONFIDENCE = 0.90

CHRONIC_THRESHOLD_DAYS = 14
ACUTE_THRESHOLD_DAYS = 5

CRITICAL_SYMPTOM_KEYWORDS = [
    "chest pain", "breathing difficulty", "shortness of breath",
    "stroke", "loss of consciousness", "severe bleeding",
    "paralysis", "seizure", "suspected poisoning", "suicidal"
]


def heuristic_risk(symptoms: str, declared_duration: int) -> tuple[str, str]:
    """Return (risk_level, summary) using rule-based clinical triage guidelines."""
    symptoms_lower = symptoms.lower()
    
    # 1. Check for critical/red-flag symptoms
    critical_matches = [kw for kw in CRITICAL_SYMPTOM_KEYWORDS if kw in symptoms_lower]
    if critical_matches:
        return (
            "HIGH",
            f"Fallback clinical triage: Red-flag symptoms detected ({', '.join(critical_matches)}). "
            f"Requires immediate urgent clinical evaluation.",
        )
        
    # 2. Check for long-standing/chronic symptoms
    if declared_duration > CHRONIC_THRESHOLD_DAYS:
        return (
            "HIGH",
            f"Fallback clinical triage: Symptom duration ({declared_duration} days) exceeds the "
            f"{CHRONIC_THRESHOLD_DAYS}-day chronic threshold. Requires specialist diagnostic review.",
        )
        
    # 3. Check for sub-acute symptoms
    if declared_duration > ACUTE_THRESHOLD_DAYS:
        return (
            "MEDIUM",
            f"Fallback clinical triage: Sub-acute symptoms (duration {declared_duration} days). "
            f"Schedule standard clinician consultation within 48 hours.",
        )
        
    # 4. Low risk / routine
    return (
        "LOW",
        f"Fallback clinical triage: Acute routine symptoms (duration {declared_duration} days) with "
        f"no red-flags. Provide standard self-care guidelines and follow-up if symptoms persist.",
    )

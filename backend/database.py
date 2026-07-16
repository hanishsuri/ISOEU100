import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "healthassist.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ISO 42001 & GDPR audit log retention: logs must be kept for audit trail.
AUDIT_RETENTION_MONTHS_MINIMUM = 6


def _column_exists(cursor: sqlite3.Cursor, table: str, column: str) -> bool:
    rows = cursor.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in rows)


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Consultations Table (all direct-identifier and clinical PHI fields encrypted at rest)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS consultations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name_encrypted BLOB NOT NULL,
            ssn_encrypted BLOB NOT NULL,
            dob_encrypted BLOB NOT NULL,
            symptoms_encrypted BLOB NOT NULL,
            declared_duration INTEGER NOT NULL,
            insurance_provider TEXT NOT NULL,
            ai_risk_level TEXT,
            ai_confidence REAL,
            ai_summary TEXT,
            status TEXT DEFAULT 'PENDING_APPROVAL', -- PENDING_APPROVAL, APPROVED, OVERRIDDEN, REJECTED
            clinician_notes TEXT,
            clinician_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            governance_flags TEXT DEFAULT '[]'
        )
        """
    )

    # Audit Logs Table (Tamper-evident record-keeping)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultation_id INTEGER NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            model_name TEXT NOT NULL,
            prompt_hash TEXT NOT NULL,
            full_prompt TEXT,
            model_response TEXT,
            model_params TEXT,
            api_latency_ms INTEGER NOT NULL,
            human_action TEXT NOT NULL, -- PENDING_APPROVAL, APPROVED, OVERRIDDEN, REJECTED
            override_reason TEXT,
            clinician_id TEXT NOT NULL,
            prev_hash TEXT,
            entry_hash TEXT,
            FOREIGN KEY (consultation_id) REFERENCES consultations (id)
        )
        """
    )

    # Risk Logs Table (Article 9 / ISO 42001 Risk Register)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            hazard_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT NOT NULL,
            resolved INTEGER DEFAULT 0
        )
        """
    )

    # Clinicians Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS clinicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            clinician_id TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

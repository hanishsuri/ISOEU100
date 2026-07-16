"""Clinician authentication (Article 14 accountability / ISO 42001 / NIST GOVERN).

Oversight decisions on a high-risk AI system must be attributable to an
authenticated natural person. This module implements bearer-token auth backed
by the `clinicians` table: tokens are random, stored only as SHA-256 hashes, and
the clinician identity is derived server-side from the token — never taken from
the request body.

Demo bootstrapping: on first init, two demo clinicians are created and their
plaintext tokens are written to database/demo_credentials.json (local demo
convenience only; that file must never ship to a real deployment).
"""

import hashlib
import json
import secrets
from pathlib import Path

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.database import get_db_connection

DEMO_CREDENTIALS_PATH = Path(__file__).resolve().parent.parent / "database" / "demo_credentials.json"

_bearer_scheme = HTTPBearer(auto_error=False)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_clinician(clinician_id: str, display_name: str) -> str:
    """Create a clinician account and return the plaintext bearer token (shown once)."""
    token = secrets.token_urlsafe(32)
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO clinicians (clinician_id, display_name, token_hash, active) VALUES (?, ?, ?, 1)",
        (clinician_id, display_name, _hash_token(token)),
    )
    conn.commit()
    conn.close()
    return token


def seed_demo_clinicians() -> None:
    """Seed two demo clinicians if the table is empty; write tokens to a local file."""
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM clinicians").fetchone()[0]
    conn.close()
    if count > 0:
        return

    credentials = {}
    for clinician_id, display_name in [
        ("CLN-1001", "Dr. Alice Smith"),
        ("CLN-1002", "Dr. Ben Jones"),
    ]:
        credentials[clinician_id] = create_clinician(clinician_id, display_name)

    DEMO_CREDENTIALS_PATH.write_text(json.dumps(credentials, indent=2))


class Clinician:
    def __init__(self, clinician_id: str, display_name: str):
        self.clinician_id = clinician_id
        self.display_name = display_name


def get_current_clinician(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> Clinician:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: provide a clinician bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    conn = get_db_connection()
    row = conn.execute(
        "SELECT clinician_id, display_name FROM clinicians WHERE token_hash = ? AND active = 1",
        (_hash_token(credentials.credentials),),
    ).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked clinician token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Clinician(clinician_id=row["clinician_id"], display_name=row["display_name"])

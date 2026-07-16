"""Isolated test database configuration for HealthAssist AI compliance tests."""
import pytest

import backend.auth as auth
import backend.database as database


@pytest.fixture(autouse=True, scope="session")
def isolated_test_db(tmp_path_factory):
    db_dir = tmp_path_factory.mktemp("healthassist-test-db")
    database.DB_PATH = db_dir / "test_healthassist.db"
    auth.DEMO_CREDENTIALS_PATH = db_dir / "demo_credentials.json"
    database.init_db()
    yield

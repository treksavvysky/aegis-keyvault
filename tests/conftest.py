import os
import sys
import tempfile
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.aegis import main as main_module
from services.aegis.models import Base


@pytest.fixture(autouse=True)
def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_SIGNING_KEY", "test-signing-key")
    monkeypatch.setenv("AEGIS_ADMIN_TOKEN", "test-admin-token")
    # Valid Fernet key for testing (generated via Fernet.generate_key())
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=")


@pytest.fixture()
def db_session(monkeypatch: pytest.MonkeyPatch) -> Generator:
    fd, path = tempfile.mkstemp()
    os.close(fd)
    db_url = f"sqlite:///{path}"
    monkeypatch.setenv("AEGIS_DATABASE_URL", db_url)

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        os.remove(path)


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    main_module.app.dependency_overrides[main_module.get_db] = override_get_db
    with TestClient(main_module.app) as test_client:
        yield test_client
    main_module.app.dependency_overrides.clear()

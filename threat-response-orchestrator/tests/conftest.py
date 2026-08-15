import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DATABASE_URL", "sqlite:///./data/test_orchestrator.db")


@pytest.fixture(scope="function")
def db_session():
    from app.database import Base, engine, SessionLocal
    from app.models import event, incident, playbook, ticket, threat_intel, audit_log  # noqa: F401

    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

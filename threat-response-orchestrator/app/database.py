"""
SQLAlchemy engine/session bootstrap.

Defaults to SQLite for zero-config local evaluation. For production,
set DATABASE_URL to a PostgreSQL DSN (recommended: managed Postgres with
daily snapshots, given this service stores security incident data).
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_settings

settings = get_settings()

if settings.DATABASE_URL.startswith("sqlite"):
    db_path = settings.DATABASE_URL.split("///")[-1]
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables. Called on startup; for production use Alembic migrations."""
    from app.models import event, incident, playbook, ticket, threat_intel, audit_log  # noqa: F401
    Base.metadata.create_all(bind=engine)

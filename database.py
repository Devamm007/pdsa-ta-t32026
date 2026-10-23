import os
import re
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from typing import Generator, Optional

from dotenv import load_dotenv
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, DateTime, Index
)
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session, Session

# Load environment variables (.env) if not already set in environment
load_dotenv()

logger = logging.getLogger("dsa_challenge")

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Neon DB / PostgreSQL / SQLite Engine Configuration
# ---------------------------------------------------------------------------

def _is_truthy(val: Optional[str]) -> bool:
    if not val:
        return False
    return val.strip().lower() in ("true", "1", "yes", "on")

# Production environment detection (Render, HuggingFace, Vercel, or PRODUCTION=true)
IS_PRODUCTION = (
    _is_truthy(os.getenv("PRODUCTION"))
    or bool(os.getenv("RENDER"))
    or bool(os.getenv("SPACE_ID"))
    or bool(os.getenv("VERCEL"))
    or os.getenv("ENVIRONMENT", "").strip().lower() == "production"
)

# Explicit manual override if developer wants to test PostgreSQL locally
FORCE_POSTGRES = _is_truthy(os.getenv("FORCE_POSTGRES"))

# True for production (Neon DB), False for local development (SQLite)
USE_POSTGRES = IS_PRODUCTION or FORCE_POSTGRES

def _mask_url(url: str) -> str:
    """Mask password credentials in database URL for safe logging."""
    return re.sub(r":([^@/:]+)@", ":***@", url)

if USE_POSTGRES:
    DATABASE_URL = (
        os.getenv("DATABASE_URL", "").strip()
        or os.getenv("POSTGRES_URL", "").strip()
        or os.getenv("NEON_DATABASE_URL", "").strip()
    )

    if not DATABASE_URL:
        raise ValueError(
            "Production/PostgreSQL mode is enabled, but neither DATABASE_URL, "
            "POSTGRES_URL, nor NEON_DATABASE_URL environment variable is set."
        )

    # Standardize scheme for SQLAlchemy (Neon/Heroku often provide 'postgres://')
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    # Detect installed PostgreSQL driver(s) and adapt URL dialect if needed
    try:
        import psycopg  # noqa: F401
        has_psycopg3 = True
    except ImportError:
        has_psycopg3 = False

    try:
        import psycopg2  # noqa: F401
        has_psycopg2 = True
    except ImportError:
        has_psycopg2 = False

    # Route dialect based on available driver
    if DATABASE_URL.startswith("postgresql+psycopg://") and not has_psycopg3 and has_psycopg2:
        DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql+psycopg2://") and not has_psycopg2 and has_psycopg3:
        DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)
    elif DATABASE_URL.startswith("postgresql://") and not has_psycopg2 and has_psycopg3:
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

    # Neon DB Serverless connection parameters:
    # pool_pre_ping=True protects against serverless cold suspend drops
    # pool_recycle=300 recycles connections every 5 minutes
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=10,
        max_overflow=20
    )
    DB_BACKEND = "postgresql"
    env_label = "Production" if IS_PRODUCTION else "Local (Forced Postgres)"
    logger.info(f"[{env_label}] SQLAlchemy Engine connected to Neon PostgreSQL: {_mask_url(DATABASE_URL)}")
else:
    # Local SQLite for local offline development
    sqlite_path = BASE_DIR / "app.db"
    DATABASE_URL = f"sqlite:///{sqlite_path}"
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
    DB_BACKEND = "sqlite"
    logger.info(f"[Local Development] SQLAlchemy Engine connected to SQLite: {sqlite_path}")

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()

# ---------------------------------------------------------------------------
# SQLAlchemy Declarative Models
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    google_id = Column(String(255), unique=True, index=True, nullable=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=True)
    picture = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Submission(Base):
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo_url = Column(String(512), unique=True, index=True, nullable=False)
    repo_name = Column(String(255), nullable=False)
    submitted_by_email = Column(String(255), index=True, nullable=True)
    submitted_by_name = Column(String(255), nullable=True)
    score = Column(Float, default=0.0)
    problems = Column(Integer, default=0)
    active_days = Column(Integer, default=0)
    easy_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    hard_count = Column(Integer, default=0)
    languages = Column(Text, default="")
    topics_covered = Column(Text, default="")
    breakdown_json = Column(Text, default="{}")
    is_deleted = Column(Integer, default=0, index=True)
    deleted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UserNote(Base):
    __tablename__ = "user_notes"

    user_email = Column(String(255), primary_key=True)
    steps_json = Column(Text, default="[]")
    notes_markdown = Column(Text, default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AnalyzedCommit(Base):
    __tablename__ = "analyzed_commits"

    commit_hash = Column(String(64), primary_key=True)
    repo_url = Column(String(512), index=True, nullable=False)
    commit_date = Column(String(32), nullable=True)
    commit_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AnalyzedProblem(Base):
    __tablename__ = "analyzed_problems"

    file_sha256 = Column(String(64), primary_key=True)
    problem_slug = Column(String(255), index=True, nullable=False)
    problem_name = Column(String(255), nullable=False)
    difficulty = Column(String(32), default="Medium")
    topic = Column(String(128), default="General DSA")
    time_complexity = Column(String(64), default="O(N)")
    space_complexity = Column(String(64), default="O(1)")
    analysis_source = Column(String(64), default="heuristic")
    created_at = Column(DateTime, default=datetime.utcnow)


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(64), primary_key=True)
    repo_url = Column(String(512), index=True, nullable=False)
    submitted_by_email = Column(String(255), index=True, nullable=True)
    submitted_by_name = Column(String(255), nullable=True)
    status = Column(String(32), default="queued", index=True)  # queued, analyzing, completed, failed
    progress_stage = Column(String(64), default="Queued")
    progress_percent = Column(Integer, default=5)
    error_message = Column(Text, nullable=True)
    stats_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def get_system_setting(session: Session, key: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieve system setting value by key."""
    try:
        row = session.query(SystemSetting).filter(SystemSetting.key == key).first()
        return row.value if row else default
    except Exception:
        return default


def set_system_setting(session: Session, key: str, value: str) -> None:
    """Set or update a system setting value."""
    try:
        row = session.query(SystemSetting).filter(SystemSetting.key == key).first()
        if row:
            row.value = value
            row.updated_at = datetime.utcnow()
        else:
            row = SystemSetting(key=key, value=value)
            session.add(row)
    except Exception as e:
        logger.warning(f"Failed to persist system setting {key}: {e}")


# ---------------------------------------------------------------------------
# Database Upsert Helpers (Zero Duplicate Key Violations)
# ---------------------------------------------------------------------------
def bulk_upsert_analyzed_problems(session: Session, records: list) -> int:
    """Safely bulk insert problems with atomic ON CONFLICT DO NOTHING."""
    if not records:
        return 0
    # Python-side deduplication guarantees no duplicate primary keys in parameter list
    deduped: dict = {}
    for r in records:
        sha = r.get("file_sha256")
        if sha:
            deduped[sha] = r

    if not deduped:
        return 0

    values = list(deduped.values())
    dialect_name = engine.dialect.name

    if dialect_name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        stmt = pg_insert(AnalyzedProblem).values(values).on_conflict_do_nothing(index_elements=["file_sha256"])
        session.execute(stmt)
    elif dialect_name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        stmt = sqlite_insert(AnalyzedProblem).values(values).on_conflict_do_nothing(index_elements=["file_sha256"])
        session.execute(stmt)
    else:
        for val in values:
            session.merge(AnalyzedProblem(**val))
    return len(values)


def bulk_upsert_analyzed_commits(session: Session, records: list) -> int:
    """Safely bulk insert commits with atomic ON CONFLICT DO NOTHING."""
    if not records:
        return 0
    deduped: dict = {}
    for r in records:
        h = r.get("commit_hash")
        if h:
            deduped[h] = r

    if not deduped:
        return 0

    values = list(deduped.values())
    dialect_name = engine.dialect.name

    if dialect_name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        stmt = pg_insert(AnalyzedCommit).values(values).on_conflict_do_nothing(index_elements=["commit_hash"])
        session.execute(stmt)
    elif dialect_name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        stmt = sqlite_insert(AnalyzedCommit).values(values).on_conflict_do_nothing(index_elements=["commit_hash"])
        session.execute(stmt)
    else:
        for val in values:
            session.merge(AnalyzedCommit(**val))
    return len(values)


# ---------------------------------------------------------------------------
# Session Helper & Context Manager
# ---------------------------------------------------------------------------
@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Provide a transactional SQLAlchemy session scope."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """Create all tables in Neon DB / SQLite and seed benchmark data if empty."""
    Base.metadata.create_all(bind=engine)
    logger.info("SQLAlchemy metadata verified / tables created.")

    # Seed benchmark initial submissions if database is empty
    with get_db() as session:
        count = session.query(Submission).count()
        if count == 0:
            logger.info("Database submissions table empty. Seeding verified benchmark repos...")
            initial_data = [
                Submission(
                    repo_url="https://github.com/25f2006944-glitch/neetcode-submissions",
                    repo_name="25f2006944-glitch/neetcode-submissions",
                    submitted_by_email="system",
                    submitted_by_name="Glitch",
                    score=11.17, problems=6, active_days=3,
                    easy_count=3, medium_count=3, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/aravinds-arv/DSA-Challenge-Python",
                    repo_name="aravinds-arv/DSA-Challenge-Python",
                    submitted_by_email="system",
                    submitted_by_name="Aravind",
                    score=8.39, problems=6, active_days=3,
                    easy_count=5, medium_count=1, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/25f2007872/neetcode-challenge",
                    repo_name="25f2007872/neetcode-challenge",
                    submitted_by_email="system",
                    submitted_by_name="25f2007872",
                    score=6.86, problems=6, active_days=1,
                    easy_count=5, medium_count=1, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/vickykumarcodes/neetcode-submissions",
                    repo_name="vickykumarcodes/neetcode-submissions",
                    submitted_by_email="system",
                    submitted_by_name="Vicky Kumar",
                    score=5.60, problems=5, active_days=1,
                    easy_count=5, medium_count=0, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/25f3000561/neetcode-submissions",
                    repo_name="25f3000561/neetcode-submissions",
                    submitted_by_email="system",
                    submitted_by_name="25f3000561",
                    score=3.41, problems=3, active_days=1,
                    easy_count=3, medium_count=0, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/ArpitaSingh246/DSA-Challenge-Python",
                    repo_name="ArpitaSingh246/DSA-Challenge-Python",
                    submitted_by_email="system",
                    submitted_by_name="Arpita Singh",
                    score=2.57, problems=2, active_days=2,
                    easy_count=2, medium_count=0, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/ajay-verma-iitm/neetcode-submissions",
                    repo_name="ajay-verma-iitm/neetcode-submissions",
                    submitted_by_email="system",
                    submitted_by_name="Ajay Verma",
                    score=1.07, problems=1, active_days=1,
                    easy_count=1, medium_count=0, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/25f1001395/neetcode-submissions",
                    repo_name="25f1001395/neetcode-submissions",
                    submitted_by_email="system",
                    submitted_by_name="25f1001395",
                    score=1.07, problems=1, active_days=1,
                    easy_count=1, medium_count=0, hard_count=0,
                    languages="Python", topics_covered="Arrays & Hashing",
                    is_deleted=0
                ),
                Submission(
                    repo_url="https://github.com/23f2001123/neetcode-submissions",
                    repo_name="23f2001123/neetcode-submissions",
                    submitted_by_email="system",
                    submitted_by_name="23f2001123",
                    score=0.00, problems=0, active_days=0,
                    easy_count=0, medium_count=0, hard_count=0,
                    languages="None", topics_covered="None",
                    is_deleted=0
                ),
            ]
            session.add_all(initial_data)
            logger.info(f"Seeded {len(initial_data)} benchmark repositories into submissions.")

"""
Shared database base and session configuration.
All models import Base from here.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Database connection URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cve_user:cve_me@localhost:5432/cve_intelligence_db"
)

# Create engine (connection pool)
engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True to see SQL queries
    pool_size=10,
    max_overflow=20
)

# Shared Base for all models
Base = declarative_base()

# Session factory
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_db():
    """
    Database session generator.
    Use with: db = next(get_db())
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

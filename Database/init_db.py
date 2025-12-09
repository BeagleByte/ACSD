"""
Database initialization script.
Creates all tables defined in models.
Run this ONCE before first use.
"""

import logging
from sqlalchemy import create_engine, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cve_user:password@localhost:5432/cve_intelligence_db"
)

# Create engine
engine = create_engine(DATABASE_URL, echo=True)

# Shared Base for all models
Base = declarative_base()


def check_tables_exist() -> dict:
    """
    Check which tables currently exist in database.

    Returns:
        dict: Table existence status
    """
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    required_tables = [
        'cves',
        'hacking_news',
        'agent_runs',
        'analysis_results'
    ]

    status = {}
    for table in required_tables:
        exists = table in existing_tables
        status[table] = exists
        logger.info(f"Table '{table}': {'✓ EXISTS' if exists else '✗ MISSING'}")

    return status


def create_all_tables():
    """
    Create all tables from models.
    Safe to run multiple times (won't recreate existing tables).
    """
    # Import all models (this registers them with Base)
    from Database.CVE import CVE
    from Database.HackingNews import HackingNews
    from Database.AgentRun import AgentRun
    from Database.AnalysisResult import AnalysisResult

    logger.info("Creating database tables...")

    # Create all tables
    Base.metadata.create_all(bind=engine)

    logger.info("✓ All tables created successfully!")

    # Verify tables were created
    logger.info("\nVerifying tables...")
    status = check_tables_exist()

    missing = [table for table, exists in status.items() if not exists]
    if missing:
        logger.error(f"✗ Tables still missing: {missing}")
        return False
    else:
        logger.info("✓ All required tables are present!")
        return True


def drop_all_tables():
    """
    WARNING: Drops ALL tables (use only for testing/reset).
    """
    logger.warning("⚠️  Dropping all tables...")
    Base.metadata.drop_all(bind=engine)
    logger.info("✓ All tables dropped")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--drop":
        # Danger zone: drop all tables
        confirm = input("⚠️  This will DELETE ALL DATA. Type 'yes' to confirm: ")
        if confirm.lower() == 'yes':
            drop_all_tables()
        else:
            logger.info("Cancelled")
    elif len(sys.argv) > 1 and sys.argv[1] == "--check":
        # Just check table status
        logger.info("Checking database tables...\n")
        check_tables_exist()
    else:
        # Default: create tables
        logger.info("Initializing database...\n")
        create_all_tables()

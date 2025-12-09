from sqlalchemy import create_engine, Column, String, DateTime, Integer, Text, JSON, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from datetime import datetime
import uuid

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cve_user:password@localhost:5432/cve_intelligence_db")

engine = create_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

class CVE(Base):
    """CVE vulnerability record"""
    __tablename__ = "cves"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id = Column(String(20), unique=True, index=True, nullable=False)  # e.g., CVE-2024-1234
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = Column(String(10), nullable=True)  # e.g., "9.8"
    cvss_vector = Column(String(200), nullable=True)
    affected_products = Column(JSON, default=list)  # List of product names
    references = Column(JSON, default=list)  # URLs
    published_date = Column(DateTime, index=True)
    modified_date = Column(DateTime, nullable=True)
    source = Column(String(50), index=True)  # "nvd", "mitre", "custom_feed", etc.
    metadata = Column(JSON, default=dict)  # Extra fields from RSS/JSON
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_cve_severity', 'severity'),
        Index('idx_cve_published', 'published_date'),
    )

class HackingNews(Base):
    """Hacking news from various sources"""
    __tablename__ = "hacking_news"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    content = Column(Text)
    source = Column(String(100), index=True)  # "hacker_news", "reddit", "twitter", etc.
    source_url = Column(String(500), unique=True, index=True)
    published_date = Column(DateTime, index=True)
    category = Column(String(50), index=True)  # "exploit", "breach", "threat", "tool", etc.
    relevance_score = Column(Integer, default=0)  # 0-100, set by agent
    is_darknet = Column(Boolean, default=False, index=True)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AgentRun(Base):
    """Track agent execution history"""
    __tablename__ = "agent_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_name = Column(String(100), index=True)  # "cve_agent", "news_agent", "darknet_agent"
    status = Column(String(20), index=True)  # "running", "success", "failed"
    items_collected = Column(Integer, default=0)
    items_processed = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    metadata = Column(JSON, default=dict)

def init_db():
    """Create all tables"""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Dependency for FastAPI"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
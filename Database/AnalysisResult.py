from sqlalchemy import Column, String, DateTime, Integer, Float, Text, JSON, Index
from sqlalchemy.dialects.postgresql import ARRAY
from Database.base import Base
import uuid
from datetime import datetime

class AnalysisResult(Base):
    """Store AI analysis results"""
    __tablename__ = "analysis_results"

    # Primary Key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Identification
    analysis_id = Column(String(100), index=True)
    analysis_type = Column(String(50), index=True)  # CVE_COLLECTION, NEWS_AGGREGATION, etc.
    agent_name = Column(String(100), index=True)
    
    # Status
    status = Column(String(20), index=True)  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    
    # Timing
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    
    # Results
    items_found = Column(Integer, default=0)
    items_processed = Column(Integer, default=0)
    items_failed = Column(Integer, default=0)
    
    # Data (stored as JSON)
    results = Column(JSON, default=dict)
    errors = Column(ARRAY(Text), default=list)
    warnings = Column(ARRAY(Text), default=list)
    
    # Confidence
    confidence_level = Column(String(20))  # VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH
    confidence_score = Column(Float, default=0.5)
    
    # Resource usage
    memory_used_mb = Column(Float, default=0.0)
    api_calls_made = Column(Integer, default=0)
    rate_limit_hits = Column(Integer, default=0)
    
    # Source tracking
    data_sources = Column(ARRAY(String), default=list)
    
    # Additional context
    analysis_result_metadata = Column('metadata', JSON, default=dict)
    tags = Column(ARRAY(String), default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_analysis_type_status', 'analysis_type', 'status'),
        Index('idx_analysis_agent', 'agent_name', 'started_at'),
    )

    def mark_started(self):
        """Mark analysis as started"""
        self.status = "IN_PROGRESS"
        self.started_at = datetime.utcnow()

    def mark_completed(self):
        """Mark analysis as completed"""
        self.status = "COMPLETED"
        self.completed_at = datetime.utcnow()
        if self.started_at:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def add_error(self, error: str):
        """Add error message"""
        if self.errors is None:
            self.errors = []
        self.errors.append(error)
        self.items_failed += 1

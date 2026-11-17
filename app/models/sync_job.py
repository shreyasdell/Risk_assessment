"""
Sync Job Model

Tracks progress of bulk CVE sync operations.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Index
from sqlalchemy.orm import relationship
from app.core.database import Base


class SyncJob(Base):
    """Model for tracking sync job progress."""
    
    __tablename__ = "sync_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, nullable=True, index=True)
    status = Column(String, nullable=False)  # 'running', 'completed', 'failed'
    total_components = Column(Integer, nullable=False)
    processed_components = Column(Integer, nullable=False, default=0)
    current_component = Column(String, nullable=True)
    total_verified_cves = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    def to_dict(self):
        """Convert to dictionary for API response."""
        percentage = 0
        if self.total_components > 0:
            percentage = (self.processed_components / self.total_components) * 100
        
        return {
            'id': self.id,
            'application_id': self.application_id,
            'status': self.status,
            'total_components': self.total_components,
            'processed_components': self.processed_components,
            'percentage_complete': round(percentage, 1),
            'current_component': self.current_component,
            'verified_cves': self.total_verified_cves,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }

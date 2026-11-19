"""
Background Task Model

Tracks progress of long-running operations like bulk CVE sync.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from app.core.database import Base


class BackgroundTask(Base):
    __tablename__ = "background_tasks"

    id = Column(Integer, primary_key=True, index=True)
    task_type = Column(String, nullable=False, index=True)
    status = Column(String, default="pending")
    total_items = Column(Integer, nullable=True)
    processed_items = Column(Integer, nullable=True)
    failed_items = Column(Integer, nullable=True)
    skipped_items = Column(Integer, nullable=True)
    current_item = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(String, nullable=True)
    
    # Scan history specific fields
    application_id = Column(Integer, nullable=True, index=True)
    nvd_calls = Column(Integer, default=0)
    cveorg_calls = Column(Integer, default=0)
    llm_calls = Column(Integer, default=0)
    cache_hits = Column(Integer, default=0)
    cache_misses = Column(Integer, default=0)
    new_cves = Column(Integer, default=0)
    removed_cves = Column(Integer, default=0)
    unchanged_cves = Column(Integer, default=0)
    error_list = Column(JSON, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "task_type": self.task_type,
            "status": self.status,
            "total_items": self.total_items,
            "processed_items": self.processed_items,
            "failed_items": self.failed_items,
            "skipped_items": self.skipped_items,
            "current_item": self.current_item,
            "error_message": self.error_message,
            "result": self.result,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
            "progress_percentage": (
                round((self.processed_items / self.total_items) * 100, 1)
                if self.total_items > 0 else 0
            ),
            "application_id": self.application_id,
            "nvd_calls": self.nvd_calls,
            "cveorg_calls": self.cveorg_calls,
            "llm_calls": self.llm_calls,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "new_cves": self.new_cves,
            "removed_cves": self.removed_cves,
            "unchanged_cves": self.unchanged_cves,
            "error_list": self.error_list
        }

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
    current_item = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(String, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "task_type": self.task_type,
            "status": self.status,
            "total_items": self.total_items,
            "processed_items": self.processed_items,
            "failed_items": self.failed_items,
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
            )
        }

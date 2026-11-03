"""
Codebase Upload Model

Stores uploaded codebase files (ZIP) or GitHub URLs for analysis.
"""

from sqlalchemy import Column, Integer, String, BigInteger, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import relationship
from datetime import datetime

from app.core.database import Base


class CodebaseUpload(Base):
    __tablename__ = "codebase_uploads"

    id = Column(Integer, primary_key=True, index=True)
    upload_id = Column(String, unique=True, nullable=False, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=True)
    source_type = Column(String, nullable=False)  # 'zip' or 'github'
    source_url = Column(String, nullable=True)  # GitHub URL
    file_path = Column(String, nullable=True)  # Path to stored ZIP file
    file_name = Column(String, nullable=True)  # Original filename
    file_size = Column(BigInteger, nullable=True)  # File size in bytes
    status = Column(String, default="uploaded", nullable=False)  # uploaded, analyzing, completed, failed
    analysis_result = Column(JSON, nullable=True)  # Analysis results
    error_message = Column(Text, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    analyzed_at = Column(DateTime, nullable=True)

    # Relationship
    application = relationship("Application", back_populates="codebase_uploads")

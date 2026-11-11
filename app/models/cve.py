from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey, Table, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    severity = Column(String, default="medium")
    cwe_id = Column(String, nullable=True)
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    exploit_available = Column(Boolean, default=False)
    patch_available = Column(Boolean, default=False)
    references = Column(Text, nullable=True)
    nvd_url = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # CVE.org cache fields
    cveorg_affected_products = Column(JSON, nullable=True)
    cveorg_fetched_at = Column(DateTime, nullable=True)
    cveorg_raw = Column(JSON, nullable=True)

    # Legacy agent fields (from old CVEFilterAgent - kept for backward compatibility)
    agent_confidence = Column(Integer, default=0)
    agent_verdict = Column(String, default="UNPROCESSED")
    agent_reasoning = Column(Text, nullable=True)
    match_method = Column(String, nullable=True)
    stage_details = Column(JSON, nullable=True)
    is_false_positive = Column(Boolean, default=False)
    agent_processing_time = Column(Float, nullable=True)
    agent_processed_at = Column(DateTime, nullable=True)

    components = relationship("Component", secondary="component_cve", back_populates="cves")
    remediations = relationship(
        "Remediation",
        back_populates="cve",
        cascade="all, delete-orphan"
    )


# Association table for many-to-many relationship between Component and CVE
component_cve = Table(
    'component_cve',
    Base.metadata,
    Column('component_id', Integer, ForeignKey('components.id'), primary_key=True),
    Column('cve_id', Integer, ForeignKey('cves.id'), primary_key=True),
    Column('confidence', Integer, nullable=True),  # Confidence score for this link
    Column('created_at', DateTime, server_default=func.now())
)

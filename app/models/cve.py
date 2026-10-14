from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey, Table, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class SeverityEnum(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    severity = Column(Enum(SeverityEnum), default=SeverityEnum.MEDIUM)
    cwe_id = Column(String, nullable=True)  # Common Weakness Enumeration
    published_date = Column(DateTime(timezone=True), nullable=True)
    modified_date = Column(DateTime(timezone=True), nullable=True)
    exploit_available = Column(Boolean, default=False)
    patch_available = Column(Boolean, default=False)
    references = Column(Text, nullable=True)  # JSON string of reference URLs
    nvd_url = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

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
    Column('created_at', DateTime(timezone=True), server_default=func.now())
)

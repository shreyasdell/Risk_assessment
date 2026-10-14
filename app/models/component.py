from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class ComponentTypeEnum(str, enum.Enum):
    LIBRARY = "library"
    FRAMEWORK = "framework"
    SDK = "sdk"
    TOOL = "tool"
    PLATFORM = "platform"
    OPERATING_SYSTEM = "operating_system"
    DATABASE = "database"
    OTHER = "other"


class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    version = Column(String, index=True, nullable=False)
    component_type = Column(Enum(ComponentTypeEnum), default=ComponentTypeEnum.LIBRARY)
    purl = Column(String, unique=True, index=True, nullable=True)  # Package URL
    supplier = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    license = Column(String, nullable=True)
    cpe = Column(String, nullable=True)  # Common Platform Enumeration
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=True)
    sbom_id = Column(String, index=True, nullable=True)  # Track which SBOM this came from
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    application = relationship("Application", backref="components")
    cves = relationship("CVE", secondary="component_cve", back_populates="components")
    remediations = relationship(
        "Remediation",
        back_populates="component"
    )

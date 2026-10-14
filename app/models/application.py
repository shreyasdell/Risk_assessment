from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class EnvironmentEnum(str, enum.Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class CriticalityEnum(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataClassificationEnum(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    description = Column(String)
    owner = Column(String)
    business_unit = Column(String)
    criticality = Column(Enum(CriticalityEnum), default=CriticalityEnum.MEDIUM)
    internet_facing = Column(Boolean, default=False)
    data_classification = Column(Enum(DataClassificationEnum), default=DataClassificationEnum.INTERNAL)
    environment = Column(Enum(EnvironmentEnum), default=EnvironmentEnum.PRODUCTION)
    vendor_id = Column(Integer, ForeignKey("vendors.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    vendor = relationship("Vendor", backref="applications")
    risk_scores = relationship(
        "RiskScore",
        back_populates="application",
        cascade="all, delete-orphan",
        order_by="RiskScore.calculated_at.desc()"
    )
    remediations = relationship(
        "Remediation",
        back_populates="application",
        cascade="all, delete-orphan"
    )

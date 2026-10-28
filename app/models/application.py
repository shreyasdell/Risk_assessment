from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    description = Column(String)
    owner = Column(String)
    business_unit = Column(String)
    criticality = Column(String, default="medium")  # Changed from Enum to String
    internet_facing = Column(Boolean, default=False)
    data_classification = Column(String, default="internal")  # Changed from Enum to String
    environment = Column(String, default="production")  # Changed from Enum to String
    vendor_id = Column(Integer, ForeignKey("vendors.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    vendor = relationship("Vendor", backref="applications")
    components = relationship(
        "Component",
        backref="application",
        cascade="all, delete-orphan"
    )
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

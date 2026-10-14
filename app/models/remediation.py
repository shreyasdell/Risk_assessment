from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class RemediationStatus(str, enum.Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    MITIGATED = "Mitigated"
    RESOLVED = "Resolved"
    ACCEPTED = "Risk Accepted"
    FALSE_POSITIVE = "False Positive"


class RemediationPriority(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Remediation(Base):
    """
    Tracks the fix process for a specific CVE
    found in a specific application.
    """
    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)

    # What needs fixing
    application_id = Column(
        Integer,
        ForeignKey("applications.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    cve_id = Column(
        Integer,
        ForeignKey("cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    component_id = Column(
        Integer,
        ForeignKey("components.id", ondelete="SET NULL"),
        nullable=True
    )

    # Tracking fields
    status = Column(
        SQLEnum(RemediationStatus),
        default=RemediationStatus.OPEN,
        nullable=False,
        index=True
    )
    priority = Column(
        SQLEnum(RemediationPriority),
        nullable=False
    )
    assigned_to = Column(String(200), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)

    # What was done
    resolution_notes = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    application = relationship("Application", back_populates="remediations")
    cve = relationship("CVE", back_populates="remediations")
    component = relationship("Component", back_populates="remediations")

    def __repr__(self):
        return (
            f"<Remediation app={self.application_id} "
            f"cve={self.cve_id} status={self.status}>"
        )

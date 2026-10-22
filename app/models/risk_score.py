from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class RiskScore(Base):
    """
    Each row represents one risk assessment calculation
    for a specific application at a specific point in time.
    """
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)

    # Which application this score belongs to
    application_id = Column(
        Integer,
        ForeignKey("applications.id"),
        nullable=False,
        index=True
    )

    # The final calculated score (0-10)
    overall_score = Column(Float, nullable=False)

    # Human readable rating derived from score
    rating = Column(String, nullable=False)

    # Individual factor scores (stored for transparency)
    cvss_weighted = Column(Float, nullable=True, default=0.0)
    criticality_weighted = Column(Float, nullable=True, default=0.0)
    exposure_weighted = Column(Float, nullable=True, default=0.0)
    exploit_weighted = Column(Float, nullable=True, default=0.0)
    patch_delay_weighted = Column(Float, nullable=True, default=0.0)
    vendor_risk_weighted = Column(Float, nullable=True, default=0.0)

    # How many CVEs existed at time of calculation
    total_cves_found = Column(Integer, default=0)
    critical_cves_count = Column(Integer, default=0)
    high_cves_count = Column(Integer, default=0)
    medium_cves_count = Column(Integer, default=0)
    low_cves_count = Column(Integer, default=0)

    # Metadata
    calculated_at = Column(
        DateTime,
        server_default=func.now(),
        nullable=False
    )
    calculated_by = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    application = relationship("Application", back_populates="risk_scores")

    def __repr__(self):
        return (
            f"<RiskScore app={self.application_id} "
            f"score={self.overall_score} rating={self.rating}>"
        )

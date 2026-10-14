from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from app.core.database import Base


class NistRecommendation(Base):
    """
    Maps CWE weakness types to NIST recommended actions.
    """
    __tablename__ = "nist_recommendations"

    id = Column(Integer, primary_key=True, index=True)

    # The CWE this recommendation addresses
    cwe_id = Column(String(20), nullable=False, index=True, unique=True)
    cwe_name = Column(String(200), nullable=True)

    # NIST framework references
    nist_category = Column(String(100), nullable=True)
    nist_function = Column(String(50), nullable=True)

    # The actual recommendation
    recommendation = Column(Text, nullable=False)
    detailed_guidance = Column(Text, nullable=True)
    references = Column(Text, nullable=True)

    # Metadata
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    def __repr__(self):
        return f"<NistRecommendation cwe={self.cwe_id}>"

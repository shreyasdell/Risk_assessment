from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.sql import func
from app.core.database import Base


class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    country = Column(String)
    business_owner = Column(String)
    contact = Column(String)
    service_type = Column(String)
    hosting_model = Column(String)
    tier = Column(String)  # Critical, High, Medium, Low
    risk_score = Column(Float)  # 0-10 scale
    compliance_status = Column(String)  # Compliant, Non-Compliant, Pending, Unknown
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

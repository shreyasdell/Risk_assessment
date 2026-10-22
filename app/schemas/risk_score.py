from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class RiskScoreBase(BaseModel):
    application_id: int
    notes: Optional[str] = None


class RiskScoreCreate(RiskScoreBase):
    pass


class RiskScoreResponse(BaseModel):
    id: int
    application_id: int
    overall_score: float = Field(ge=0, le=10)
    rating: str

    # Factor breakdown
    cvss_weighted: Optional[float] = 0.0
    criticality_weighted: Optional[float] = 0.0
    exposure_weighted: Optional[float] = 0.0
    exploit_weighted: Optional[float] = 0.0
    patch_delay_weighted: Optional[float] = 0.0
    vendor_risk_weighted: Optional[float] = 0.0

    # CVE counts
    total_cves_found: int = 0
    critical_cves_count: int = 0
    high_cves_count: int = 0
    medium_cves_count: int = 0
    low_cves_count: int = 0

    # Metadata
    calculated_at: datetime
    calculated_by: Optional[str] = None
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class RiskTrendPoint(BaseModel):
    date: datetime
    score: float
    rating: str

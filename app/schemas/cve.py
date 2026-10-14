from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.cve import SeverityEnum


class CVEBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: SeverityEnum = SeverityEnum.MEDIUM
    cwe_id: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    exploit_available: bool = False
    patch_available: bool = False
    references: Optional[str] = None
    nvd_url: Optional[str] = None


class CVECreate(CVEBase):
    pass


class CVEUpdate(BaseModel):
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Optional[SeverityEnum] = None
    cwe_id: Optional[str] = None
    exploit_available: Optional[bool] = None
    patch_available: Optional[bool] = None
    references: Optional[str] = None
    nvd_url: Optional[str] = None


class CVEResponse(CVEBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class CVESearch(BaseModel):
    cve_id: Optional[str] = None
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    severity: Optional[SeverityEnum] = None

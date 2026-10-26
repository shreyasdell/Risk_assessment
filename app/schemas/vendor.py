from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional
import re


class VendorBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Vendor name")
    country: Optional[str] = Field(None, max_length=100, description="Country name")
    business_owner: Optional[str] = Field(None, max_length=100, description="Business owner name")
    contact: Optional[EmailStr] = Field(None, description="Contact email")
    service_type: Optional[str] = Field(None, max_length=100, description="Service type")
    hosting_model: Optional[str] = Field(None, max_length=100, description="Hosting model")
    tier: Optional[str] = Field(None, max_length=50, description="Vendor tier (Critical, High, Medium, Low)")
    risk_score: Optional[float] = Field(None, ge=0, le=10, description="Vendor risk score (0-10)")
    compliance_status: Optional[str] = Field(None, max_length=50, description="Compliance status")

    @field_validator('name')
    @classmethod
    def name_must_be_valid(cls, v):
        # More lenient validation
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        v = re.sub(r'[<>\"\'\\]', '', v)
        return v.strip()[:255]


class VendorCreate(VendorBase):
    pass


class VendorUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    country: Optional[str] = Field(None, max_length=100)
    business_owner: Optional[str] = Field(None, max_length=100)
    contact: Optional[EmailStr] = Field(None)
    service_type: Optional[str] = Field(None, max_length=100)
    hosting_model: Optional[str] = Field(None, max_length=100)
    tier: Optional[str] = Field(None, max_length=50)
    risk_score: Optional[float] = Field(None, ge=0, le=10)
    compliance_status: Optional[str] = Field(None, max_length=50)

    @field_validator('name')
    @classmethod
    def name_must_be_valid(cls, v):
        if v is not None:
            if not v or not v.strip():
                raise ValueError('Name cannot be empty')
            v = re.sub(r'[<>\"\'\\]', '', v)
            return v.strip()[:255]
        return v


class VendorResponse(VendorBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class VendorStats(BaseModel):
    """Vendor statistics summary"""
    total_vendors: int
    by_tier: dict
    by_country: dict
    by_service_type: dict
    high_risk_vendors: int
    critical_vendors: int

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

    @field_validator('name')
    @classmethod
    def name_must_not_contain_special_chars(cls, v):
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Name must not contain special characters')
        return v.strip()


class VendorCreate(VendorBase):
    pass


class VendorUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    country: Optional[str] = Field(None, max_length=100)
    business_owner: Optional[str] = Field(None, max_length=100)
    contact: Optional[EmailStr] = Field(None)
    service_type: Optional[str] = Field(None, max_length=100)
    hosting_model: Optional[str] = Field(None, max_length=100)

    @field_validator('name')
    @classmethod
    def name_must_not_contain_special_chars(cls, v):
        if v is not None and not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Name must not contain special characters')
        return v.strip() if v else v


class VendorResponse(VendorBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class VendorBase(BaseModel):
    name: str
    country: Optional[str] = None
    business_owner: Optional[str] = None
    contact: Optional[str] = None
    service_type: Optional[str] = None
    hosting_model: Optional[str] = None


class VendorCreate(VendorBase):
    pass


class VendorUpdate(BaseModel):
    name: Optional[str] = None
    country: Optional[str] = None
    business_owner: Optional[str] = None
    contact: Optional[str] = None
    service_type: Optional[str] = None
    hosting_model: Optional[str] = None


class VendorResponse(VendorBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

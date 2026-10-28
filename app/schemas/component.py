from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional
import re


class ComponentBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Component name")
    version: str = Field(..., min_length=1, max_length=100, description="Component version")
    component_type: str = "library"  # Changed from Enum to String
    purl: Optional[str] = Field(None, max_length=500, description="Package URL")
    supplier: Optional[str] = Field(None, max_length=100, description="Supplier name")
    description: Optional[str] = Field(None, max_length=2000, description="Component description")
    license: Optional[str] = Field(None, max_length=100, description="License name")
    cpe: Optional[str] = Field(None, max_length=500, description="CPE string")
    application_id: Optional[int] = Field(None, ge=1, description="Application ID")
    sbom_id: Optional[str] = Field(None, max_length=100, description="SBOM ID")

    @field_validator('name', 'version')
    @classmethod
    def validate_component_fields(cls, v):
        # More lenient validation for SBOM compatibility
        if not v or not v.strip():
            raise ValueError('Cannot be empty')
        # Remove potentially dangerous characters but allow common SBOM chars
        v = re.sub(r'[<>\"\'\\]', '', v)
        return v.strip()


class ComponentCreate(ComponentBase):
    pass


class ComponentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    version: Optional[str] = Field(None, min_length=1, max_length=100)
    component_type: Optional[str] = None  # Changed from Enum to String
    purl: Optional[str] = Field(None, max_length=500)
    supplier: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=2000)
    license: Optional[str] = Field(None, max_length=100)
    cpe: Optional[str] = Field(None, max_length=500)
    application_id: Optional[int] = Field(None, ge=1)

    @field_validator('name', 'version')
    @classmethod
    def validate_component_fields(cls, v):
        if v is not None:
            if not v or not v.strip():
                raise ValueError('Cannot be empty')
            v = re.sub(r'[<>\"\'\\]', '', v)
            return v.strip()
        return v


class ComponentResponse(ComponentBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

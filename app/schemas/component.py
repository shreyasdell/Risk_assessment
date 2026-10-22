from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional
from app.models.component import ComponentTypeEnum
import re


class ComponentBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Component name")
    version: str = Field(..., min_length=1, max_length=100, description="Component version")
    component_type: ComponentTypeEnum = ComponentTypeEnum.LIBRARY
    purl: Optional[str] = Field(None, max_length=500, description="Package URL")
    supplier: Optional[str] = Field(None, max_length=100, description="Supplier name")
    description: Optional[str] = Field(None, max_length=2000, description="Component description")
    license: Optional[str] = Field(None, max_length=100, description="License name")
    cpe: Optional[str] = Field(None, max_length=500, description="CPE string")
    application_id: Optional[int] = Field(None, ge=1, description="Application ID")
    sbom_id: Optional[str] = Field(None, max_length=100, description="SBOM ID")

    @field_validator('name', 'version')
    @classmethod
    def validate_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Must not contain special characters')
        return v.strip()


class ComponentCreate(ComponentBase):
    pass


class ComponentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    version: Optional[str] = Field(None, min_length=1, max_length=100)
    component_type: Optional[ComponentTypeEnum] = None
    purl: Optional[str] = Field(None, max_length=500)
    supplier: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=2000)
    license: Optional[str] = Field(None, max_length=100)
    cpe: Optional[str] = Field(None, max_length=500)
    application_id: Optional[int] = Field(None, ge=1)

    @field_validator('name', 'version')
    @classmethod
    def validate_alphanumeric(cls, v):
        if v is not None and not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Must not contain special characters')
        return v.strip() if v else v


class ComponentResponse(ComponentBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

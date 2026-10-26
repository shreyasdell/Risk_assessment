from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional
from app.models.application import EnvironmentEnum, CriticalityEnum, DataClassificationEnum
import re


class ApplicationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Application name")
    description: Optional[str] = Field(None, max_length=2000, description="Application description")
    owner: Optional[str] = Field(None, max_length=100, description="Application owner")
    business_unit: Optional[str] = Field(None, max_length=100, description="Business unit")
    criticality: CriticalityEnum = CriticalityEnum.MEDIUM
    internet_facing: bool = False
    data_classification: DataClassificationEnum = DataClassificationEnum.INTERNAL
    environment: EnvironmentEnum = EnvironmentEnum.DEVELOPMENT
    vendor_id: Optional[int] = Field(None, description="Vendor ID")

    @field_validator('name')
    @classmethod
    def name_must_be_valid(cls, v):
        # More lenient validation - allow common characters
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        # Remove potentially dangerous characters but allow most common ones
        v = re.sub(r'[<>\"\'\\]', '', v)
        return v.strip()[:255]


class ApplicationCreate(ApplicationBase):
    pass


class ApplicationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    owner: Optional[str] = Field(None, max_length=100)
    business_unit: Optional[str] = Field(None, max_length=100)
    criticality: Optional[CriticalityEnum] = None
    internet_facing: Optional[bool] = None
    data_classification: Optional[DataClassificationEnum] = None
    environment: Optional[EnvironmentEnum] = None
    vendor_id: Optional[int] = Field(None)

    @field_validator('name')
    @classmethod
    def name_must_be_valid(cls, v):
        if v is not None:
            if not v or not v.strip():
                raise ValueError('Name cannot be empty')
            v = re.sub(r'[<>\"\'\\]', '', v)
            return v.strip()[:255]
        return v


class ApplicationResponse(ApplicationBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

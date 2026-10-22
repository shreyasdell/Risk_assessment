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
    environment: EnvironmentEnum = EnvironmentEnum.PRODUCTION
    vendor_id: Optional[int] = Field(None, ge=1, description="Vendor ID")

    @field_validator('name')
    @classmethod
    def name_must_not_contain_special_chars(cls, v):
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Name must not contain special characters')
        return v.strip()


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
    vendor_id: Optional[int] = Field(None, ge=1)

    @field_validator('name')
    @classmethod
    def name_must_not_contain_special_chars(cls, v):
        if v is not None and not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Name must not contain special characters')
        return v.strip() if v else v


class ApplicationResponse(ApplicationBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

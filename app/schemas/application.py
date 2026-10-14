from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.application import EnvironmentEnum, CriticalityEnum, DataClassificationEnum


class ApplicationBase(BaseModel):
    name: str
    description: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: CriticalityEnum = CriticalityEnum.MEDIUM
    internet_facing: bool = False
    data_classification: DataClassificationEnum = DataClassificationEnum.INTERNAL
    environment: EnvironmentEnum = EnvironmentEnum.PRODUCTION
    vendor_id: Optional[int] = None


class ApplicationCreate(ApplicationBase):
    pass


class ApplicationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: Optional[CriticalityEnum] = None
    internet_facing: Optional[bool] = None
    data_classification: Optional[DataClassificationEnum] = None
    environment: Optional[EnvironmentEnum] = None
    vendor_id: Optional[int] = None


class ApplicationResponse(ApplicationBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

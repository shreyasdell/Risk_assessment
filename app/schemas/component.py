from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.component import ComponentTypeEnum


class ComponentBase(BaseModel):
    name: str
    version: str
    component_type: ComponentTypeEnum = ComponentTypeEnum.LIBRARY
    purl: Optional[str] = None
    supplier: Optional[str] = None
    description: Optional[str] = None
    license: Optional[str] = None
    cpe: Optional[str] = None
    application_id: Optional[int] = None
    sbom_id: Optional[str] = None


class ComponentCreate(ComponentBase):
    pass


class ComponentUpdate(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    component_type: Optional[ComponentTypeEnum] = None
    purl: Optional[str] = None
    supplier: Optional[str] = None
    description: Optional[str] = None
    license: Optional[str] = None
    cpe: Optional[str] = None
    application_id: Optional[int] = None


class ComponentResponse(ComponentBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

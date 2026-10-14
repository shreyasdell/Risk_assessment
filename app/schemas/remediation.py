from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.models.remediation import RemediationStatus, RemediationPriority


class RemediationCreate(BaseModel):
    application_id: int
    cve_id: int
    component_id: Optional[int] = None
    priority: RemediationPriority
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    recommended_action: Optional[str] = None


class RemediationUpdate(BaseModel):
    status: Optional[RemediationStatus] = None
    priority: Optional[RemediationPriority] = None
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class RemediationResponse(BaseModel):
    id: int
    application_id: int
    cve_id: int
    component_id: Optional[int] = None
    status: RemediationStatus
    priority: RemediationPriority
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    recommended_action: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True

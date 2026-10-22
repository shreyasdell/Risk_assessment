"""
Audit Log API Router
View-only endpoints for audit trail.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.auth.dependencies import get_current_active_user
from app.models.user import User
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get("/", summary="List audit logs")
def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    username: Optional[str] = Query(None, description="Filter by username"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Query audit logs. Only admin users should access this in production."""
    query = db.query(AuditLog)
    
    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if username:
        query = query.filter(AuditLog.username == username)
    
    return query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()


@router.get("/recent", summary="Recent activity")
def recent_activity(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get most recent audit entries for activity feed."""
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

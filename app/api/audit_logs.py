"""
Audit Log API Router
View-only endpoints for audit trail.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from app.core.database import get_db
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_admin
from app.models.user import User
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get("/", summary="List audit logs")
def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    username: Optional[str] = Query(None, description="Filter by username"),
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Query audit logs with filters and pagination. Admin only."""
    query = db.query(AuditLog)
    
    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if username:
        query = query.filter(AuditLog.username == username)
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date)
            query = query.filter(AuditLog.timestamp >= start_dt)
        except ValueError:
            pass  # Invalid date format, ignore filter
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date)
            query = query.filter(AuditLog.timestamp <= end_dt)
        except ValueError:
            pass  # Invalid date format, ignore filter
    
    total = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "data": logs,
        "total": total,
        "skip": skip,
        "limit": limit
    }


@router.get("/recent", summary="Recent activity")
def recent_activity(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get most recent audit entries for activity feed."""
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

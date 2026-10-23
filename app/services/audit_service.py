"""
Audit Logging Service
Records all significant user actions.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


class AuditService:

    def log(
        self,
        db: Session,
        action: str,
        resource_type: str,
        resource_id: int = None,
        description: str = None,
        details: dict = None,
        user_id: int = None,
        username: str = None,
        user_role: str = None,
        ip_address: str = None,
        user_agent: str = None
    ):
        """
        Record an action in the audit log.

        Actions: CREATE, READ, UPDATE, DELETE,
                 LOGIN, LOGOUT, UPLOAD, SCAN,
                 CALCULATE, EXPORT, LINK

        Resource Types: user, vendor, application,
                       component, cve, sbom,
                       risk_score, remediation, report
        """
        log_entry = AuditLog(
            user_id=user_id,
            username=username,
            user_role=user_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow()
        )

        db.add(log_entry)
        db.commit()

        return log_entry

    def get_logs(
        self,
        db: Session,
        action: str = None,
        resource_type: str = None,
        username: str = None,
        limit: int = 100,
        skip: int = 0
    ):
        """Query audit logs with filters."""
        query = db.query(AuditLog)

        if action:
            query = query.filter(AuditLog.action == action)
        if resource_type:
            query = query.filter(
                AuditLog.resource_type == resource_type
            )
        if username:
            query = query.filter(AuditLog.username == username)

        return (
            query
            .order_by(AuditLog.timestamp.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_recent(
        self,
        db: Session,
        limit: int = 20
    ):
        """Get most recent audit log entries."""
        return (
            db.query(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
            .all()
        )


audit_service = AuditService()
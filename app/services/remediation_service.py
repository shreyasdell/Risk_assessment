"""
Remediation Service
Business logic for tracking vulnerability fixes.
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_
from fastapi import HTTPException

from app.models.remediation import (
    Remediation, RemediationStatus, RemediationPriority
)
from app.models.application import Application
from app.models.cve import CVE
from app.models.component import Component


class RemediationService:

    def create_remediation(
        self,
        db: Session,
        application_id: int,
        cve_id: int,
        component_id: int = None,
        priority: str = "High",
        assigned_to: str = None,
        due_date: datetime = None,
        recommended_action: str = None
    ) -> Remediation:
        """
        Create a new remediation task.

        Typically called when:
        1. A CVE sync discovers new vulnerabilities
        2. A security analyst manually flags an issue
        3. A risk score crosses a threshold
        """
        # Validate application exists
        app = (
            db.query(Application)
            .filter(Application.id == application_id)
            .first()
        )
        if not app:
            raise HTTPException(
                status_code=404,
                detail=f"Application {application_id} not found"
            )

        # Validate CVE exists
        cve = db.query(CVE).filter(CVE.id == cve_id).first()
        if not cve:
            raise HTTPException(
                status_code=404,
                detail=f"CVE {cve_id} not found"
            )

        # Check for duplicate
        existing = (
            db.query(Remediation)
            .filter(
                and_(
                    Remediation.application_id == application_id,
                    Remediation.cve_id == cve_id
                )
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Remediation already exists for "
                    f"this application-CVE pair (ID: {existing.id})"
                )
            )

        remediation = Remediation(
            application_id=application_id,
            cve_id=cve_id,
            component_id=component_id,
            status=RemediationStatus.OPEN,
            priority=priority,
            assigned_to=assigned_to,
            due_date=due_date,
            recommended_action=recommended_action,
        )

        db.add(remediation)
        db.commit()
        db.refresh(remediation)

        return remediation

    def get_remediation(
        self,
        db: Session,
        remediation_id: int
    ) -> Remediation:
        """Get a single remediation by ID."""
        rem = (
            db.query(Remediation)
            .filter(Remediation.id == remediation_id)
            .first()
        )
        if not rem:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation {remediation_id} not found"
            )
        return rem

    def list_remediations(
        self,
        db: Session,
        application_id: int = None,
        status: str = None,
        priority: str = None,
        assigned_to: str = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Remediation]:
        """
        List remediations with optional filters.
        """
        query = db.query(Remediation)

        if application_id:
            query = query.filter(
                Remediation.application_id == application_id
            )
        if status:
            query = query.filter(Remediation.status == status)
        if priority:
            query = query.filter(Remediation.priority == priority)
        if assigned_to:
            query = query.filter(
                Remediation.assigned_to == assigned_to
            )

        return (
            query
            .order_by(Remediation.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def update_status(
        self,
        db: Session,
        remediation_id: int,
        new_status: str,
        resolution_notes: str = None
    ) -> Remediation:
        """
        Update remediation status.

        Valid transitions:
        Open -> In Progress -> Resolved
        Open -> In Progress -> Mitigated
        Open -> Risk Accepted
        Any  -> False Positive
        """
        rem = self.get_remediation(db, remediation_id)

        rem.status = new_status

        if resolution_notes:
            rem.resolution_notes = resolution_notes

        # Set resolved_at timestamp when resolved/mitigated
        if new_status in [
            RemediationStatus.RESOLVED,
            RemediationStatus.MITIGATED
        ]:
            rem.resolved_at = datetime.utcnow()

        db.commit()
        db.refresh(rem)
        return rem

    def update_remediation(
        self,
        db: Session,
        remediation_id: int,
        **kwargs
    ) -> Remediation:
        """Update any field on a remediation."""
        rem = self.get_remediation(db, remediation_id)

        allowed_fields = [
            "priority", "assigned_to", "due_date",
            "resolution_notes", "recommended_action",
            "status"
        ]

        for key, value in kwargs.items():
            if key in allowed_fields and value is not None:
                setattr(rem, key, value)

        # Auto-set resolved_at
        if kwargs.get("status") in ["Resolved", "Mitigated"]:
            rem.resolved_at = datetime.utcnow()

        db.commit()
        db.refresh(rem)
        return rem

    def delete_remediation(
        self,
        db: Session,
        remediation_id: int
    ):
        """Delete a remediation record."""
        rem = self.get_remediation(db, remediation_id)
        db.delete(rem)
        db.commit()

    def get_overdue(self, db: Session) -> List[Remediation]:
        """Get all overdue remediations."""
        now = datetime.utcnow()
        return (
            db.query(Remediation)
            .filter(
                Remediation.status.in_([
                    RemediationStatus.OPEN,
                    RemediationStatus.IN_PROGRESS
                ]),
                Remediation.due_date < now
            )
            .order_by(Remediation.due_date.asc())
            .all()
        )

    def get_stats(
        self,
        db: Session,
        application_id: int = None
    ) -> dict:
        """Get remediation statistics."""
        query = db.query(Remediation)
        if application_id:
            query = query.filter(
                Remediation.application_id == application_id
            )

        all_rems = query.all()
        now = datetime.utcnow()

        if not all_rems:
            return {
                "total": 0,
                "open": 0,
                "in_progress": 0,
                "resolved": 0,
                "mitigated": 0,
                "risk_accepted": 0,
                "false_positive": 0,
                "overdue": 0,
                "average_resolution_days": 0
            }

        resolved = [
            r for r in all_rems
            if r.status == RemediationStatus.RESOLVED
            and r.resolved_at
        ]

        avg_days = 0
        if resolved:
            total_days = sum(
                (r.resolved_at - r.created_at).days
                for r in resolved
            )
            avg_days = round(total_days / len(resolved), 1)

        return {
            "total": len(all_rems),
            "open": sum(
                1 for r in all_rems
                if r.status == RemediationStatus.OPEN
            ),
            "in_progress": sum(
                1 for r in all_rems
                if r.status == RemediationStatus.IN_PROGRESS
            ),
            "resolved": sum(
                1 for r in all_rems
                if r.status == RemediationStatus.RESOLVED
            ),
            "mitigated": sum(
                1 for r in all_rems
                if r.status == RemediationStatus.MITIGATED
            ),
            "risk_accepted": sum(
                1 for r in all_rems
                if r.status == RemediationStatus.ACCEPTED
            ),
            "false_positive": sum(
                1 for r in all_rems
                if r.status == RemediationStatus.FALSE_POSITIVE
            ),
            "overdue": sum(
                1 for r in all_rems
                if r.status in [
                    RemediationStatus.OPEN,
                    RemediationStatus.IN_PROGRESS
                ]
                and r.due_date
                and r.due_date < now
            ),
            "average_resolution_days": avg_days
        }


remediation_service = RemediationService()
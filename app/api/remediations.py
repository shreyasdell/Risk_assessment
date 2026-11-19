"""
Remediation API Router
Endpoints for tracking vulnerability remediation.
"""

from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime

from app.core.database import get_db
from app.auth.dependencies import get_current_user
from app.auth.rbac import require_write_access, require_delete_access
from app.services.remediation_service import remediation_service
from app.services.audit_service import audit_service
from app.models.user import User

router = APIRouter(prefix="/remediations", tags=["Remediations"])


@router.post("/", summary="Create remediation task")
def create_remediation(
    application_id: int,
    cve_id: int,
    component_id: Optional[int] = None,
    priority: str = "High",
    assigned_to: Optional[str] = None,
    due_date: Optional[str] = None,
    recommended_action: Optional[str] = None,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    """
    Create a new remediation task to track fixing a CVE.

    Priority: Critical, High, Medium, Low
    """
    parsed_due = None
    if due_date:
        try:
            parsed_due = datetime.fromisoformat(due_date)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use ISO format."
            )

    result = remediation_service.create_remediation(
        db=db,
        application_id=application_id,
        cve_id=cve_id,
        component_id=component_id,
        priority=priority,
        assigned_to=assigned_to,
        due_date=parsed_due,
        recommended_action=recommended_action
    )
    
    audit_service.log(
        db=db,
        action="CREATE",
        resource_type="remediation",
        resource_id=result.id,
        description=f"Remediation created for CVE {cve_id}",
        details={
            "application_id": application_id,
            "cve_id": cve_id,
            "component_id": component_id,
            "priority": priority,
            "assigned_to": assigned_to
        },
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


@router.get("/", summary="List all remediations")
def list_remediations(
    application_id: Optional[int] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """List remediations with optional filters."""
    return remediation_service.list_remediations(
        db=db,
        application_id=application_id,
        status=status,
        priority=priority,
        assigned_to=assigned_to,
        skip=skip,
        limit=limit
    )


@router.get(
    "/{remediation_id}",
    summary="Get remediation details"
)
def get_remediation(
    remediation_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get a single remediation by ID."""
    return remediation_service.get_remediation(db, remediation_id)


@router.put(
    "/{remediation_id}",
    summary="Update remediation"
)
def update_remediation(
    remediation_id: int,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    due_date: Optional[str] = None,
    resolution_notes: Optional[str] = None,
    recommended_action: Optional[str] = None,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Update any field on a remediation."""
    kwargs = {}
    if status:
        kwargs["status"] = status
    if priority:
        kwargs["priority"] = priority
    if assigned_to:
        kwargs["assigned_to"] = assigned_to
    if resolution_notes:
        kwargs["resolution_notes"] = resolution_notes
    if recommended_action:
        kwargs["recommended_action"] = recommended_action
    if due_date:
        try:
            kwargs["due_date"] = datetime.fromisoformat(due_date)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format"
            )

    result = remediation_service.update_remediation(
        db=db,
        remediation_id=remediation_id,
        **kwargs
    )
    
    audit_service.log(
        db=db,
        action="UPDATE",
        resource_type="remediation",
        resource_id=remediation_id,
        description=f"Remediation updated: {remediation_id}",
        details={"updated_fields": list(kwargs.keys()), "changed_by": current_user.username},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


@router.patch(
    "/{remediation_id}/status",
    summary="Update remediation status"
)
def update_status(
    remediation_id: int,
    new_status: str,
    resolution_notes: Optional[str] = None,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Quick status update.

    Valid statuses:
    - Open
    - In Progress
    - Mitigated
    - Resolved
    - Risk Accepted
    - False Positive
    """
    result = remediation_service.update_status(
        db=db,
        remediation_id=remediation_id,
        new_status=new_status,
        resolution_notes=resolution_notes
    )
    
    audit_service.log(
        db=db,
        action="UPDATE",
        resource_type="remediation",
        resource_id=remediation_id,
        description=f"Remediation status changed to {new_status}",
        details={"new_status": new_status, "resolution_notes": resolution_notes, "changed_by": current_user.username},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


@router.delete(
    "/{remediation_id}",
    summary="Delete remediation"
)
def delete_remediation(
    remediation_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Delete a remediation record."""
    remediation_service.delete_remediation(db, remediation_id)
    
    audit_service.log(
        db=db,
        action="DELETE",
        resource_type="remediation",
        resource_id=remediation_id,
        description=f"Remediation deleted: {remediation_id}",
        details={"deleted_by": current_user.username},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return {"message": "Remediation deleted"}


@router.get(
    "/overdue/list",
    summary="Get overdue remediations"
)
def get_overdue(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get all remediations past their due date."""
    return remediation_service.get_overdue(db)


@router.get(
    "/stats/summary",
    summary="Get remediation statistics"
)
def get_stats(
    application_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get aggregated remediation stats."""
    return remediation_service.get_stats(db, application_id)
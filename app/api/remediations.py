"""
Remediation API Router
Track remediation status for CVEs.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.auth.dependencies import get_current_active_user
from app.models.user import User
from app.models.remediation import Remediation
from app.schemas.remediation import RemediationCreate, RemediationUpdate, RemediationResponse

router = APIRouter(prefix="/remediations", tags=["Remediations"])


@router.post("/", response_model=RemediationResponse, status_code=status.HTTP_201_CREATED)
def create_remediation(
    remediation: RemediationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new remediation record."""
    db_remediation = Remediation(**remediation.model_dump())
    db.add(db_remediation)
    db.commit()
    db.refresh(db_remediation)
    return db_remediation


@router.get("/", response_model=list[RemediationResponse])
def list_remediations(
    application_id: Optional[int] = None,
    cve_id: Optional[int] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List remediations with optional filters."""
    query = db.query(Remediation)
    
    if application_id:
        query = query.filter(Remediation.application_id == application_id)
    if cve_id:
        query = query.filter(Remediation.cve_id == cve_id)
    if status:
        query = query.filter(Remediation.status == status)
    
    return query.order_by(Remediation.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/{remediation_id}", response_model=RemediationResponse)
def get_remediation(
    remediation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific remediation."""
    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return remediation


@router.put("/{remediation_id}", response_model=RemediationResponse)
def update_remediation(
    remediation_id: int,
    remediation: RemediationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update a remediation."""
    db_remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not db_remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")
    
    for key, value in remediation.model_dump(exclude_unset=True).items():
        setattr(db_remediation, key, value)
    
    db.commit()
    db.refresh(db_remediation)
    return db_remediation


@router.delete("/{remediation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_remediation(
    remediation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete a remediation."""
    db_remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not db_remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")
    
    db.delete(db_remediation)
    db.commit()
    return None

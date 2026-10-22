"""
NIST Recommendations API Router
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.auth.dependencies import get_current_active_user
from app.models.user import User
from app.models.nist_recommendation import NistRecommendation
from app.services.nist_service import nist_service


class NistRecommendationCreate(BaseModel):
    cwe_id: str
    cwe_name: str
    nist_category: str
    nist_function: str
    recommendation: str
    detailed_guidance: str
    references: str = None


router = APIRouter(prefix="/nist", tags=["NIST Recommendations"])


@router.post("/", status_code=status.HTTP_201_CREATED, summary="Create recommendation")
def create_recommendation(
    rec: NistRecommendationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new NIST recommendation."""
    # Check if already exists
    existing = db.query(NistRecommendation).filter(NistRecommendation.cwe_id == rec.cwe_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Recommendation for this CWE already exists")
    
    db_rec = NistRecommendation(**rec.model_dump())
    db.add(db_rec)
    db.commit()
    db.refresh(db_rec)
    return db_rec


@router.get("/", summary="List all recommendations")
def get_all(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all NIST recommendations."""
    return nist_service.get_all(db)


@router.get("/cwe/{cwe_id}", summary="Get recommendation by CWE")
def get_by_cwe(
    cwe_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get NIST recommendation for a specific CWE."""
    rec = nist_service.get_by_cwe(db, cwe_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return rec


@router.get("/cve/{cve_id}", summary="Get recommendation for CVE")
def get_for_cve(
    cve_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get NIST recommendation for a specific CVE by looking up its CWE."""
    rec = nist_service.get_for_cve(db, cve_id)
    if not rec:
        raise HTTPException(status_code=404, detail="No recommendation found")
    return rec

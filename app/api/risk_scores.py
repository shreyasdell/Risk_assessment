from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.schemas.risk_score import RiskScoreResponse
from app.services.risk_service import (
    calculate_and_save_risk_score,
    calculate_risk_scores_for_all_applications
)
from app.auth.dependencies import get_current_active_user
from app.models.user import User
from app.models.risk_score import RiskScore

router = APIRouter(prefix="/risk-scores", tags=["Risk Scores"])


@router.post("/calculate/{application_id}", response_model=RiskScoreResponse)
def calculate_risk_score_endpoint(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Calculate risk score for a specific application
    """
    try:
        risk_score = calculate_and_save_risk_score(
            db=db,
            application_id=application_id,
            calculated_by=current_user.username
        )
        return risk_score
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate risk score: {str(e)}"
        )


@router.post("/calculate-all", response_model=List[RiskScoreResponse])
def calculate_all_risk_scores(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Calculate risk scores for all applications
    """
    try:
        risk_scores = calculate_risk_scores_for_all_applications(
            db=db,
            calculated_by=current_user.username
        )
        return risk_scores
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate risk scores: {str(e)}"
        )


@router.get("/application/{application_id}", response_model=RiskScoreResponse)
def get_risk_score_for_application(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the latest risk score for an application
    """
    risk_score = db.query(RiskScore).filter(
        RiskScore.application_id == application_id
    ).order_by(RiskScore.calculated_at.desc()).first()
    
    if not risk_score:
        raise HTTPException(
            status_code=404,
            detail="No risk score found for this application. Calculate one first."
        )
    
    return risk_score


@router.get("/application/{application_id}/history", response_model=List[RiskScoreResponse])
def get_risk_score_history(
    application_id: int,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get risk score history for an application
    """
    risk_scores = db.query(RiskScore).filter(
        RiskScore.application_id == application_id
    ).order_by(RiskScore.calculated_at.desc()).limit(limit).all()
    
    return risk_scores


@router.get("/", response_model=List[RiskScoreResponse])
def get_all_risk_scores(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all risk scores
    """
    risk_scores = db.query(RiskScore).order_by(
        RiskScore.calculated_at.desc()
    ).offset(skip).limit(limit).all()
    
    return risk_scores

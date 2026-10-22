from sqlalchemy.orm import Session
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from app.models.application import Application
from app.models.component import Component
from app.models.cve import CVE
from app.models.risk_score import RiskScore
from app.schemas.risk_score import RiskScoreCreate
import logging

logger = logging.getLogger(__name__)


class RiskScoringWeights:
    """Weights for different risk factors"""
    CVSS_WEIGHT = 0.35
    CRITICALITY_WEIGHT = 0.20
    EXPOSURE_WEIGHT = 0.15
    EXPLOIT_WEIGHT = 0.15
    PATCH_DELAY_WEIGHT = 0.10
    VENDOR_RISK_WEIGHT = 0.05


class CriticalityScores:
    """Risk scores based on application criticality"""
    LOW = 1.0
    MEDIUM = 2.0
    HIGH = 3.0
    CRITICAL = 4.0


class SeverityScores:
    """Risk scores based on CVE severity"""
    NONE = 0.0
    LOW = 1.0
    MEDIUM = 2.0
    HIGH = 3.0
    CRITICAL = 4.0


def calculate_criticality_score(criticality: str) -> float:
    """Convert criticality string to numeric score"""
    criticality_map = {
        "low": CriticalityScores.LOW,
        "medium": CriticalityScores.MEDIUM,
        "high": CriticalityScores.HIGH,
        "critical": CriticalityScores.CRITICAL
    }
    return criticality_map.get(criticality.lower(), CriticalityScores.MEDIUM)


def calculate_severity_score(severity: str) -> float:
    """Convert severity string to numeric score"""
    severity_map = {
        "none": SeverityScores.NONE,
        "low": SeverityScores.LOW,
        "medium": SeverityScores.MEDIUM,
        "high": SeverityScores.HIGH,
        "critical": SeverityScores.CRITICAL
    }
    return severity_map.get(severity.lower(), SeverityScores.MEDIUM)


def calculate_exposure_score(application: Application) -> float:
    """
    Calculate exposure score based on:
    - Internet facing (yes = higher risk)
    - Environment (production = higher risk)
    - Data classification (restricted = higher risk)
    """
    score = 1.0
    
    # Internet facing
    if application.internet_facing:
        score += 2.0
    
    # Environment
    if application.environment:
        env = application.environment.lower()
        if env == "production":
            score += 2.0
        elif env == "staging":
            score += 1.0
    
    # Data classification
    if application.data_classification:
        classification = application.data_classification.lower()
        if classification == "restricted":
            score += 2.0
        elif classification == "confidential":
            score += 1.5
        elif classification == "internal":
            score += 1.0
    
    return min(score, 5.0)  # Cap at 5.0


def calculate_exploit_score(cves: List[CVE]) -> float:
    """
    Calculate exploit score based on:
    - Number of CVEs with exploits available
    - Total number of CVEs
    """
    if not cves:
        return 0.0
    
    exploit_count = sum(1 for cve in cves if cve.exploit_available)
    total_count = len(cves)
    
    if total_count == 0:
        return 0.0
    
    # Base score on percentage of CVEs with exploits
    exploit_ratio = exploit_count / total_count
    score = exploit_ratio * 5.0
    
    # Bonus if there are any exploits at all
    if exploit_count > 0:
        score += 1.0
    
    return min(score, 5.0)


def calculate_patch_delay_score(cves: List[CVE]) -> float:
    """
    Calculate patch delay score based on:
    - Number of CVEs without patches
    - Age of CVEs without patches
    """
    if not cves:
        return 0.0
    
    unpatched_count = sum(1 for cve in cves if not cve.patch_available)
    total_count = len(cves)
    
    if total_count == 0:
        return 0.0
    
    # Base score on percentage of unpatched CVEs
    unpatched_ratio = unpatched_count / total_count
    score = unpatched_ratio * 5.0
    
    # Check age of unpatched CVEs
    now = datetime.utcnow()
    for cve in cves:
        if not cve.patch_available and cve.published_date:
            age_days = (now - cve.published_date.replace(tzinfo=None)).days
            if age_days > 90:  # Older than 3 months
                score += 0.5
            elif age_days > 30:  # Older than 1 month
                score += 0.25
    
    return min(score, 5.0)


def calculate_vendor_risk_score(application: Application, db: Session) -> float:
    """
    Calculate vendor risk score based on:
    - Number of applications from this vendor
    - Total CVEs across all vendor applications
    """
    if not application.vendor_id:
        return 1.0  # Default score if no vendor
    
    from app.models.vendor import Vendor
    vendor = db.query(Vendor).filter(Vendor.id == application.vendor_id).first()
    if not vendor:
        return 1.0
    
    # Get all applications from this vendor
    vendor_apps = db.query(Application).filter(Application.vendor_id == vendor.id).all()
    
    if not vendor_apps:
        return 1.0
    
    # Count total CVEs across all vendor applications
    total_cves = 0
    for app in vendor_apps:
        if hasattr(app, 'components'):
            for component in app.components:
                if hasattr(component, 'cves'):
                    total_cves += len(component.cves)
    
    # Calculate score based on CVE density
    avg_cves_per_app = total_cves / len(vendor_apps) if vendor_apps else 0
    
    if avg_cves_per_app > 10:
        return 5.0
    elif avg_cves_per_app > 5:
        return 4.0
    elif avg_cves_per_app > 2:
        return 3.0
    elif avg_cves_per_app > 0:
        return 2.0
    else:
        return 1.0


def calculate_cvss_weighted_score(cves: List[CVE]) -> float:
    """
    Calculate weighted CVSS score
    """
    if not cves:
        return 0.0
    
    # Average CVSS score
    cvss_scores = [cve.cvss_score for cve in cves if cve.cvss_score is not None]
    if not cvss_scores:
        return 0.0
    
    avg_cvss = sum(cvss_scores) / len(cvss_scores)
    
    # Normalize to 0-5 scale (CVSS is 0-10)
    return avg_cvss / 2.0


def calculate_overall_risk_score(
    application: Application,
    cves: List[CVE],
    db: Session
) -> Dict[str, float]:
    """
    Calculate overall risk score for an application
    
    Returns dictionary with all component scores and overall score
    """
    # Calculate individual components
    cvss_score = calculate_cvss_weighted_score(cves)
    
    criticality_score = calculate_criticality_score(application.criticality) if application.criticality else 2.0
    
    exposure_score = calculate_exposure_score(application)
    
    exploit_score = calculate_exploit_score(cves)
    
    patch_delay_score = calculate_patch_delay_score(cves)
    
    vendor_risk_score = calculate_vendor_risk_score(application, db)
    
    # Calculate weighted overall score
    overall_score = (
        cvss_score * RiskScoringWeights.CVSS_WEIGHT +
        criticality_score * RiskScoringWeights.CRITICALITY_WEIGHT +
        exposure_score * RiskScoringWeights.EXPOSURE_WEIGHT +
        exploit_score * RiskScoringWeights.EXPLOIT_WEIGHT +
        patch_delay_score * RiskScoringWeights.PATCH_DELAY_WEIGHT +
        vendor_risk_score * RiskScoringWeights.VENDOR_RISK_WEIGHT
    )
    
    # Normalize to 0-10 scale
    overall_score = min(overall_score * 2, 10.0)
    
    # Determine rating
    if overall_score >= 8.0:
        rating = "Critical"
    elif overall_score >= 6.0:
        rating = "Very High"
    elif overall_score >= 4.0:
        rating = "High"
    elif overall_score >= 2.0:
        rating = "Moderate"
    else:
        rating = "Low"
    
    # Count CVEs by severity
    critical_cves = sum(1 for cve in cves if cve.severity and cve.severity.lower() == "critical")
    high_cves = sum(1 for cve in cves if cve.severity and cve.severity.lower() == "high")
    medium_cves = sum(1 for cve in cves if cve.severity and cve.severity.lower() == "medium")
    low_cves = sum(1 for cve in cves if cve.severity and cve.severity.lower() == "low")
    
    return {
        "overall_score": round(overall_score, 2),
        "rating": rating,
        "cvss_weighted": round(cvss_score, 2),
        "criticality_weighted": round(criticality_score, 2),
        "exposure_weighted": round(exposure_score, 2),
        "exploit_weighted": round(exploit_score, 2),
        "patch_delay_weighted": round(patch_delay_score, 2),
        "vendor_risk_weighted": round(vendor_risk_score, 2),
        "total_cves_found": len(cves),
        "critical_cves_count": critical_cves,
        "high_cves_count": high_cves,
        "medium_cves_count": medium_cves,
        "low_cves_count": low_cves
    }


def get_application_cves(db: Session, application_id: int) -> List[CVE]:
    """Get all CVEs for an application (through its components)"""
    application = db.query(Application).filter(Application.id == application_id).first()
    if not application:
        return []
    
    all_cves = []
    if hasattr(application, 'components'):
        for component in application.components:
            if hasattr(component, 'cves'):
                all_cves.extend(component.cves)
    
    return all_cves


def calculate_and_save_risk_score(
    db: Session,
    application_id: int,
    calculated_by: Optional[str] = None
) -> RiskScore:
    """
    Calculate risk score for an application and save to database
    """
    application = db.query(Application).filter(Application.id == application_id).first()
    if not application:
        raise ValueError("Application not found")
    
    # Get all CVEs for the application
    cves = get_application_cves(db, application_id)
    
    # Calculate risk score
    risk_data = calculate_overall_risk_score(application, cves, db)
    
    # Create or update risk score
    existing_score = db.query(RiskScore).filter(
        RiskScore.application_id == application_id
    ).first()
    
    if existing_score:
        # Update existing
        for key, value in risk_data.items():
            setattr(existing_score, key, value)
        existing_score.calculated_at = datetime.utcnow()
        existing_score.calculated_by = calculated_by
        db.commit()
        db.refresh(existing_score)
        return existing_score
    else:
        # Create new
        risk_score_data = {
            "application_id": application_id,
            **risk_data,
            "calculated_by": calculated_by
        }
        risk_score = RiskScore(**risk_score_data)
        db.add(risk_score)
        db.commit()
        db.refresh(risk_score)
        return risk_score


def calculate_risk_scores_for_all_applications(
    db: Session,
    calculated_by: Optional[str] = None
) -> List[RiskScore]:
    """
    Calculate risk scores for all applications
    """
    applications = db.query(Application).all()
    risk_scores = []
    
    for application in applications:
        try:
            risk_score = calculate_and_save_risk_score(db, application.id, calculated_by)
            risk_scores.append(risk_score)
        except Exception as e:
            logger.error(f"Error calculating risk score for application {application.id}: {e}")
            continue
    
    return risk_scores

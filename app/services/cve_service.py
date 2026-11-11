from sqlalchemy.orm import Session
from typing import List, Optional, Tuple
from app.models.cve import CVE
from app.models.component import Component
from app.schemas.cve import CVECreate, CVEUpdate


def get_cve(db: Session, cve_id: int) -> Optional[CVE]:
    return db.query(CVE).filter(CVE.id == cve_id).first()


def get_cve_by_cve_id(db: Session, cve_id: str) -> Optional[CVE]:
    return db.query(CVE).filter(CVE.cve_id == cve_id).first()


def get_cves(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    min_cvss: Optional[float] = None,
    application_id: Optional[int] = None,
    distinct: bool = True
) -> Tuple[List[CVE], int]:
    """Get CVEs with total count for pagination."""
    if application_id:
        # Filter by application - join with components and application
        # Use subquery to avoid DISTINCT on JSON columns
        from sqlalchemy import func
        
        # Get distinct CVE IDs
        cve_ids_subquery = db.query(CVE.id).join(CVE.components).join(Component.application)
        if severity:
            cve_ids_subquery = cve_ids_subquery.filter(CVE.severity == severity)
        if min_cvss is not None:
            cve_ids_subquery = cve_ids_subquery.filter(CVE.cvss_score >= min_cvss)
        if application_id:
            cve_ids_subquery = cve_ids_subquery.filter(Component.application_id == application_id)
        
        if distinct:
            cve_ids_subquery = cve_ids_subquery.distinct()
        
        # Get total count
        total = cve_ids_subquery.count()
        
        # Get CVE IDs for pagination
        cve_ids = cve_ids_subquery.order_by(CVE.cvss_score.desc()).offset(skip).limit(limit).all()
        cve_ids = [id for (id,) in cve_ids]
        
        # Get full CVE objects
        cves = db.query(CVE).filter(CVE.id.in_(cve_ids)).order_by(CVE.cvss_score.desc()).all()
    else:
        # Get all CVEs - no join needed
        query = db.query(CVE)
        
        if severity:
            query = query.filter(CVE.severity == severity)
        if min_cvss is not None:
            query = query.filter(CVE.cvss_score >= min_cvss)
        
        # Get total count
        total = query.count()
        
        # Get paginated results
        cves = query.order_by(CVE.cvss_score.desc()).offset(skip).limit(limit).all()
    
    return cves, total


def create_cve(db: Session, cve: CVECreate) -> CVE:
    db_cve = CVE(**cve.model_dump())
    db.add(db_cve)
    db.commit()
    db.refresh(db_cve)
    return db_cve


def create_cves_bulk(db: Session, cves: List[CVECreate]) -> List[CVE]:
    db_cves = []
    for cve_data in cves:
        # Check if CVE already exists
        existing = db.query(CVE).filter(CVE.cve_id == cve_data.cve_id).first()
        if existing:
            # Update existing
            for key, value in cve_data.model_dump(exclude_unset=True).items():
                if key != "cve_id":
                    setattr(existing, key, value)
            db_cves.append(existing)
        else:
            # Create new
            db_cve = CVE(**cve_data.model_dump())
            db.add(db_cve)
            db_cves.append(db_cve)
    
    db.commit()
    for cve in db_cves:
        db.refresh(cve)
    return db_cves


def update_cve(db: Session, cve_id: int, cve: CVEUpdate) -> Optional[CVE]:
    db_cve = get_cve(db, cve_id)
    if not db_cve:
        return None
    for key, value in cve.model_dump(exclude_unset=True).items():
        setattr(db_cve, key, value)
    db.commit()
    db.refresh(db_cve)
    return db_cve


def delete_cve(db: Session, cve_id: int) -> bool:
    db_cve = get_cve(db, cve_id)
    if not db_cve:
        return False
    db.delete(db_cve)
    db.commit()
    return True


def get_cves_for_component(db: Session, component_id: int) -> List[CVE]:
    """Get all CVEs associated with a component"""
    from app.models.component import Component
    component = db.query(Component).filter(Component.id == component_id).first()
    if not component:
        return []
    return component.cves

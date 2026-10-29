from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.cve import CVE
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
    min_cvss: Optional[float] = None
) -> List[CVE]:
    query = db.query(CVE)
    
    if severity:
        query = query.filter(CVE.severity == severity)
    if min_cvss is not None:
        query = query.filter(CVE.cvss_score >= min_cvss)
    
    return query.order_by(CVE.cvss_score.desc()).offset(skip).limit(limit).all()


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

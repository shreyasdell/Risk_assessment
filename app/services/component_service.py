from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.component import Component
from app.schemas.component import ComponentCreate, ComponentUpdate


def get_component(db: Session, component_id: int) -> Optional[Component]:
    return db.query(Component).filter(Component.id == component_id).first()


def get_components(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    application_id: Optional[int] = None,
    sbom_id: Optional[str] = None
) -> List[Component]:
    query = db.query(Component)
    if application_id:
        query = query.filter(Component.application_id == application_id)
    if sbom_id:
        query = query.filter(Component.sbom_id == sbom_id)
    return query.offset(skip).limit(limit).all()


def get_component_by_purl(db: Session, purl: str) -> Optional[Component]:
    return db.query(Component).filter(Component.purl == purl).first()


def create_component(db: Session, component: ComponentCreate) -> Component:
    db_component = Component(**component.model_dump())
    db.add(db_component)
    db.commit()
    db.refresh(db_component)
    return db_component


def create_components_bulk(db: Session, components: List[ComponentCreate]) -> List[Component]:
    created_components = []
    for comp in components:
        # Check if component with same purl AND same application_id already exists
        if comp.purl:
            existing = db.query(Component).filter(
                Component.purl == comp.purl,
                Component.application_id == comp.application_id
            ).first()
            if existing:
                # Skip duplicate components for the same application
                continue
        
        db_component = Component(**comp.model_dump())
        db.add(db_component)
        created_components.append(db_component)
    
    if created_components:
        db.commit()
        for comp in created_components:
            db.refresh(comp)
    
    return created_components


def update_component(db: Session, component_id: int, component: ComponentUpdate) -> Optional[Component]:
    db_component = get_component(db, component_id)
    if not db_component:
        return None
    for key, value in component.model_dump(exclude_unset=True).items():
        setattr(db_component, key, value)
    db.commit()
    db.refresh(db_component)
    return db_component


def delete_component(db: Session, component_id: int) -> bool:
    db_component = get_component(db, component_id)
    if not db_component:
        return False
    db.delete(db_component)
    db.commit()
    return True


def delete_components_by_sbom_id(db: Session, sbom_id: str) -> int:
    count = db.query(Component).filter(Component.sbom_id == sbom_id).count()
    db.query(Component).filter(Component.sbom_id == sbom_id).delete()
    db.commit()
    return count

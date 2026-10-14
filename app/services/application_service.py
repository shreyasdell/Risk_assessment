from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.application import Application
from app.schemas.application import ApplicationCreate, ApplicationUpdate


def get_application(db: Session, application_id: int) -> Optional[Application]:
    return db.query(Application).filter(Application.id == application_id).first()


def get_applications(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    vendor_id: Optional[int] = None
) -> List[Application]:
    query = db.query(Application)
    if vendor_id:
        query = query.filter(Application.vendor_id == vendor_id)
    return query.offset(skip).limit(limit).all()


def create_application(db: Session, application: ApplicationCreate) -> Application:
    db_application = Application(**application.model_dump())
    db.add(db_application)
    db.commit()
    db.refresh(db_application)
    return db_application


def update_application(db: Session, application_id: int, application: ApplicationUpdate) -> Optional[Application]:
    db_application = get_application(db, application_id)
    if not db_application:
        return None
    for key, value in application.model_dump(exclude_unset=True).items():
        setattr(db_application, key, value)
    db.commit()
    db.refresh(db_application)
    return db_application


def delete_application(db: Session, application_id: int) -> bool:
    db_application = get_application(db, application_id)
    if not db_application:
        return False
    db.delete(db_application)
    db.commit()
    return True

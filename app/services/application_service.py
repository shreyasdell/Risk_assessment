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
    
    # Delete component_cve links for this application's components
    from app.models.component import Component
    from app.models.cve import CVE
    
    # Cancel any running background tasks for this application
    from app.models.background_task import BackgroundTask
    from app.services.background_sync_service import background_sync_service
    
    running_tasks = db.query(BackgroundTask).filter(
        BackgroundTask.task_type == "bulk_cve_sync",
        BackgroundTask.status.in_(["running", "paused"])
    ).all()
    
    for task in running_tasks:
        # Check if this task is for this application (by checking result details)
        if task.result and task.result.get("details"):
            # Check if any component in the task belongs to this application
            task_component_ids = [d.get("component_id") for d in task.result.get("details", [])]
            if task_component_ids:
                task_components = db.query(Component).filter(
                    Component.id.in_(task_component_ids),
                    Component.application_id == application_id
                ).first()
                if task_components:
                    # Cancel this task
                    background_sync_service.cancel_task(db, task.id)
    
    # Get all components for this application
    components = db.query(Component).filter(Component.application_id == application_id).all()
    
    for component in components:
        # Clear CVE links (this deletes from component_cve table)
        component.cves.clear()
    
    # Delete all components for this application
    db.query(Component).filter(Component.application_id == application_id).delete()
    
    # Delete the application
    db.delete(db_application)
    db.commit()
    return True

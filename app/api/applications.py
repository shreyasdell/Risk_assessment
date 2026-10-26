from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.schemas.application import ApplicationCreate, ApplicationUpdate, ApplicationResponse
from app.services.application_service import (
    get_application,
    get_applications,
    create_application,
    update_application,
    delete_application
)
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_write_access, require_delete_access
from app.models.user import User

router = APIRouter(prefix="/applications", tags=["Applications"])


@router.post("/", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED)
def create_application_endpoint(
    application: ApplicationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    return create_application(db=db, application=application)


@router.get("/", response_model=List[ApplicationResponse])
def read_applications(
    skip: int = 0,
    limit: int = 100,
    vendor_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    applications = get_applications(db, skip=skip, limit=limit, vendor_id=vendor_id)
    return applications


@router.get("/{application_id}", response_model=ApplicationResponse)
def read_application(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    application = get_application(db, application_id=application_id)
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return application


@router.put("/{application_id}", response_model=ApplicationResponse)
def update_application_endpoint(
    application_id: int,
    application: ApplicationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    db_application = update_application(db, application_id=application_id, application=application)
    if db_application is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return db_application


@router.delete("/{application_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_application_endpoint(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_delete_access)
):
    success = delete_application(db, application_id=application_id)
    if not success:
        raise HTTPException(status_code=404, detail="Application not found")
    return None

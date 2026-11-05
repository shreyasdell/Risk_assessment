from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, Form, File
from sqlalchemy.orm import Session
from typing import List, Optional
from pathlib import Path
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
from app.models.codebase_upload import CodebaseUpload

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


@router.post("/upload-codebase", status_code=status.HTTP_201_CREATED)
def upload_codebase(
    file: UploadFile = File(...),
    application_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    """Upload codebase via ZIP file"""
    import uuid

    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported")

    # Validate file size (max 500MB for codebase ZIP files)
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
    content = file.file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds 500MB limit"
        )

    uploads_dir = Path("uploads")
    uploads_dir.mkdir(exist_ok=True)

    upload_id = str(uuid.uuid4())
    file_path = uploads_dir / f"{upload_id}_{file.filename}"

    with open(file_path, "wb") as buffer:
        buffer.write(content)

    codebase_upload = CodebaseUpload(
        upload_id=upload_id,
        application_id=application_id,
        source_type="zip",
        file_path=str(file_path),
        file_name=file.filename,
        file_size=len(content),
        status="uploaded"
    )

    db.add(codebase_upload)
    db.commit()

    return {"message": "Codebase uploaded successfully", "upload_id": upload_id}

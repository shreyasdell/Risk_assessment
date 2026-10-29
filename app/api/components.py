from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.schemas.component import ComponentCreate, ComponentUpdate, ComponentResponse
from app.services.component_service import (
    get_component,
    get_components,
    create_component,
    update_component,
    delete_component
)
from app.services.sbom_service import process_sbom_upload
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_write_access, require_delete_access
from app.models.user import User

router = APIRouter(prefix="/components", tags=["Components"])


@router.post("/", response_model=ComponentResponse, status_code=status.HTTP_201_CREATED)
def create_component_endpoint(
    component: ComponentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    return create_component(db=db, component=component)


@router.get("/")
def read_components(
    skip: int = 0,
    limit: int = 100,
    application_id: Optional[int] = Query(None),
    sbom_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    components, total = get_components(db, skip=skip, limit=limit, application_id=application_id, sbom_id=sbom_id)
    return {"data": components, "total": total}


@router.get("/{component_id}", response_model=ComponentResponse)
def read_component(
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    component = get_component(db, component_id=component_id)
    if component is None:
        raise HTTPException(status_code=404, detail="Component not found")
    return component


@router.put("/{component_id}", response_model=ComponentResponse)
def update_component_endpoint(
    component_id: int,
    component: ComponentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    db_component = update_component(db, component_id=component_id, component=component)
    if db_component is None:
        raise HTTPException(status_code=404, detail="Component not found")
    return db_component


@router.delete("/{component_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_component_endpoint(
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_delete_access)
):
    success = delete_component(db, component_id=component_id)
    if not success:
        raise HTTPException(status_code=404, detail="Component not found")
    return None


@router.post("/upload-sbom", status_code=status.HTTP_201_CREATED)
def upload_sbom(
    file: UploadFile = File(...),
    application_id: Optional[int] = Form(None),
    replace_existing: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    """
    Upload and parse SBOM file (CycloneDX or SPDX format)
    
    Supported formats:
    - CycloneDX JSON (.json)
    - CycloneDX XML (.xml)
    - SPDX JSON (.json)
    - SPDX RDF/XML (.xml)
    """
    print(f"DEBUG: SBOM upload - application_id received: {application_id}")
    
    # Validate file size (max 10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    content = file.file.read()
    
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds 10MB limit"
        )
    
    # Validate file extension
    allowed_extensions = ['.json', '.xml']
    if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only .json and .xml files are supported"
        )
    
    try:
        content_str = content.decode('utf-8')
        result = process_sbom_upload(
            db=db,
            content=content_str,
            filename=file.filename,
            application_id=application_id,
            replace_existing=replace_existing
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process SBOM: {str(e)}"
        )

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
    """Upload codebase via ZIP file and extract components"""
    import uuid
    from app.services.codebase_service import codebase_analyzer
    from app.services.component_service import create_components_bulk

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

    # Analyze the codebase to extract components
    try:
        components_data = codebase_analyzer.analyze_zip(str(file_path))
        print(f"[codebase_upload] Extracted {len(components_data)} components from codebase")
        
        # Convert to ComponentCreate objects
        from app.schemas.component import ComponentCreate
        from app.agent.canonical_identity.resolver import CanonicalIdentityResolver
        
        resolver = CanonicalIdentityResolver()
        component_creates = []
        
        for comp_data in components_data:
            # Resolve canonical identity from PURL
            canonical_identity = None
            purl = comp_data.get('purl')
            if purl:
                canonical_identity = resolver.resolve_from_purl(purl)
            
            # Parse PURL for additional fields
            purl_type, purl_namespace, purl_name = None, None, None
            if purl and purl.startswith("pkg:"):
                from app.sbom.parser import SBOMParser
                purl_type, purl_namespace, purl_name = SBOMParser._parse_purl(purl)
            
            component_creates.append(ComponentCreate(
                name=comp_data['name'],
                version=comp_data['version'],
                component_type=comp_data.get('component_type', 'library'),
                purl=purl,
                application_id=application_id,
                sbom_id=upload_id,  # Use upload_id as sbom_id for tracking
                purl_type=purl_type,
                purl_namespace=purl_namespace,
                purl_name=purl_name,
                canonical_ecosystem=canonical_identity["canonical_ecosystem"] if canonical_identity else None,
                canonical_vendor_identity=canonical_identity["canonical_vendor_identity"] if canonical_identity else None,
                canonical_product_identity=canonical_identity["canonical_product_identity"] if canonical_identity else None,
                canonical_key=canonical_identity["canonical_key"] if canonical_identity else None,
            ))
        
        # Bulk create components
        if component_creates:
            created_components = create_components_bulk(db, component_creates)
            print(f"[codebase_upload] Created {len(created_components)} components in database")
        
        # Trigger enrichment for the application in background
        from app.agent.langgraph_agent import ComponentEnrichmentAgent
        from app.models.component import Component
        from app.core.database import SessionLocal
        import asyncio
        
        # Get component IDs for this application (not objects, to avoid detached instance error)
        component_ids = [c.id for c in db.query(Component.id).filter(Component.application_id == application_id).all()]
        
        if component_ids:
            print(f"[codebase_upload] Triggering enrichment for {len(component_ids)} components")
            
            # Run enrichment in background task to avoid blocking
            def run_enrichment():
                # Create new database session for background task
                bg_db = SessionLocal()
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        agent = ComponentEnrichmentAgent(bg_db)
                        for component_id in component_ids:
                            try:
                                loop.run_until_complete(agent.enrich_component(component_id))
                            except Exception as e:
                                print(f"[codebase_upload] Error enriching component {component_id}: {e}")
                    finally:
                        loop.close()
                finally:
                    bg_db.close()
            
            import threading
            enrichment_thread = threading.Thread(target=run_enrichment, daemon=True)
            enrichment_thread.start()
        
    except Exception as e:
        print(f"[codebase_upload] Error analyzing codebase: {e}")
        # Still save the upload record even if analysis fails
        pass

    codebase_upload = CodebaseUpload(
        upload_id=upload_id,
        application_id=application_id,
        source_type="zip",
        file_path=str(file_path),
        file_name=file.filename,
        file_size=len(content),
        status="processed"
    )

    db.add(codebase_upload)
    db.commit()

    return {"message": "Codebase uploaded and processed successfully", "upload_id": upload_id, "components_extracted": len(components_data) if 'components_data' in locals() else 0}

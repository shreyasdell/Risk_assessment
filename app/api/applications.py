from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, Form, File, Request
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
from app.models.component import Component
from app.models.application import Application
from app.services.audit_service import audit_service

router = APIRouter(prefix="/applications", tags=["Applications"])


@router.post("/", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED)
def create_application_endpoint(
    request: Request,
    application: ApplicationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    result = create_application(db=db, application=application)
    
    audit_service.log(
        db=db,
        action="CREATE",
        resource_type="application",
        resource_id=result.id,
        description=f"Application created: {application.name}",
        details={"name": application.name, "vendor_id": application.vendor_id, "criticality": application.criticality},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


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
    request: Request,
    application_id: int,
    application: ApplicationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    db_application = db.query(Application).filter(Application.id == application_id).first()
    if not db_application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    old_values = {
        "name": db_application.name,
        "criticality": db_application.criticality.value if db_application.criticality else None,
        "environment": db_application.environment.value if db_application.environment else None
    }
    
    result = update_application(db, application_id=application_id, application=application)
    
    audit_service.log(
        db=db,
        action="UPDATE",
        resource_type="application",
        resource_id=application_id,
        description=f"Application updated: {old_values['name']}",
        details={
            "old_values": old_values,
            "new_values": {
                "name": result.name,
                "criticality": result.criticality.value if result.criticality else None,
                "environment": result.environment.value if result.environment else None
            },
            "changed_by": current_user.username
        },
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


@router.delete("/{application_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_application_endpoint(
    request: Request,
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_delete_access)
):
    db_application = db.query(Application).filter(Application.id == application_id).first()
    if not db_application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    app_info = {
        "name": db_application.name,
        "vendor_id": db_application.vendor_id,
        "criticality": db_application.criticality if db_application.criticality else None
    }
    
    success = delete_application(db, application_id=application_id)
    if not success:
        raise HTTPException(status_code=404, detail="Application not found")
    
    audit_service.log(
        db=db,
        action="DELETE",
        resource_type="application",
        resource_id=application_id,
        description=f"Application deleted: {app_info['name']}",
        details={"deleted_application": app_info, "deleted_by": current_user.username},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )


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
    components_extracted = 0
    components_created = 0
    components_skipped = 0
    component_ids = []  # Initialize before try block
    
    try:
        components_data = codebase_analyzer.analyze_zip(str(file_path))
        components_extracted = len(components_data)
        print(f"[codebase_upload] Extracted {components_extracted} components from codebase")
        
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
                dependency_type=comp_data.get('dependency_type'),
                declared_version=comp_data.get('declared_version'),
                version_unresolved=comp_data.get('version_unresolved', False),
            ))
        
        # Bulk create components (skip duplicates by canonical_key)
        new_component_creates = []
        if component_creates:
            try:
                # Get existing canonical_keys globally (not just for this application)
                existing_canonical_keys = set()
                existing_components = db.query(Component.canonical_key).filter(
                    Component.canonical_key.isnot(None)
                ).all()
                existing_canonical_keys = {ck[0] for ck in existing_components}
                print(f"[codebase_upload] Found {len(existing_canonical_keys)} existing canonical_keys in database")
                
                # Also check for duplicates within the current batch
                batch_canonical_keys = set()
                deduplicated_creates = []
                for cc in component_creates:
                    if cc.canonical_key:
                        if cc.canonical_key in batch_canonical_keys:
                            # Duplicate within batch, skip this one
                            print(f"[codebase_upload] Skipping duplicate within batch: {cc.canonical_key}")
                            continue
                        batch_canonical_keys.add(cc.canonical_key)
                    deduplicated_creates.append(cc)
                
                # Filter out components that already exist
                new_component_creates = []
                for cc in deduplicated_creates:
                    if cc.canonical_key and cc.canonical_key in existing_canonical_keys:
                        print(f"[codebase_upload] Skipping existing component: {cc.canonical_key}")
                    else:
                        new_component_creates.append(cc)
                
                duplicate_count = len(component_creates) - len(new_component_creates)
                components_skipped = duplicate_count
                print(f"[codebase_upload] Found {duplicate_count} duplicate components (skipped)")
                
                if new_component_creates:
                    created_components = create_components_bulk(db, new_component_creates)
                    components_created = len(created_components)
                    print(f"[codebase_upload] Created {components_created} new components in database")
                    
                    # Get component IDs from the created components
                    component_ids = [c.id for c in created_components]
                else:
                    print(f"[codebase_upload] All components already exist, skipping creation")
            except Exception as e:
                print(f"[codebase_upload] Error creating components: {e}")
                db.rollback()
        
        # Trigger enrichment for newly created components in background
        if component_ids:
            print(f"[codebase_upload] Triggering enrichment for {len(component_ids)} components")
            
            # Run enrichment in background task to avoid blocking
            def run_enrichment():
                # Create new database session for background task
                from app.core.database import SessionLocal
                bg_db = SessionLocal()
                try:
                    from app.agent.langgraph_agent import ComponentEnrichmentAgent
                    import asyncio
                    
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        agent = ComponentEnrichmentAgent(bg_db)
                        
                        # Use semaphore to limit concurrent enrichments (respect rate limits)
                        # Max 5 concurrent enrichments to avoid overwhelming NVD API
                        semaphore = asyncio.Semaphore(5)
                        
                        async def enrich_with_semaphore(component_id):
                            async with semaphore:
                                try:
                                    await agent.enrich_component(component_id)
                                except Exception as e:
                                    print(f"[codebase_upload] Error enriching component {component_id}: {e}")
                        
                        # Run all enrichments in parallel
                        tasks = [enrich_with_semaphore(cid) for cid in component_ids]
                        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                        
                        print(f"[codebase_upload] Completed enrichment for {len(component_ids)} components")
                    finally:
                        loop.close()
                finally:
                    bg_db.close()
            
            import threading
            enrichment_thread = threading.Thread(target=run_enrichment, daemon=True)
            enrichment_thread.start()
        
    except Exception as e:
        print(f"[codebase_upload] Error analyzing codebase: {e}")
        db.rollback()
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

    return {
        "message": "Codebase uploaded and processed successfully",
        "upload_id": upload_id,
        "components_extracted": components_extracted,
        "components_created": components_created,
        "components_skipped": components_skipped
    }

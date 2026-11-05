from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.schemas.cve import CVECreate, CVEUpdate, CVEResponse, CVESearch
from app.services.cve_service import (
    get_cve,
    get_cve_by_cve_id,
    get_cves,
    create_cve,
    create_cves_bulk,
    update_cve,
    delete_cve,
    get_cves_for_component
)
from app.services.nvd_service import nvd_service
from app.services.background_sync_service import background_sync_service
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_write_access, require_delete_access
from app.models.user import User

router = APIRouter(prefix="/cves", tags=["CVEs"])


@router.post("/", response_model=CVEResponse, status_code=status.HTTP_201_CREATED)
def create_cve_endpoint(
    cve: CVECreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    # Check if CVE already exists
    existing = get_cve_by_cve_id(db, cve.cve_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CVE with this ID already exists"
        )
    return create_cve(db=db, cve=cve)


@router.post("/bulk", response_model=List[CVEResponse], status_code=status.HTTP_201_CREATED)
def create_cves_bulk_endpoint(
    cves: List[CVECreate],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    return create_cves_bulk(db=db, cves=cves)


@router.get("/")
def read_cves(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = Query(None),
    min_cvss: Optional[float] = Query(None),
    application_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    cves, total = get_cves(db, skip=skip, limit=limit, severity=severity, min_cvss=min_cvss, application_id=application_id)
    return {
        "data": cves,
        "total": total,
        "skip": skip,
        "limit": limit
    }


@router.get("/{cve_id}", response_model=CVEResponse)
def read_cve(
    cve_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    cve = get_cve(db, cve_id=cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@router.get("/by-cve-id/{cve_id_str}", response_model=CVEResponse)
def read_cve_by_cve_id(
    cve_id_str: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    cve = get_cve_by_cve_id(db, cve_id=cve_id_str)
    if cve is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@router.get("/component/{component_id}", response_model=List[CVEResponse])
def read_cves_for_component(
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    return get_cves_for_component(db, component_id=component_id)


@router.put("/{cve_id}", response_model=CVEResponse)
def update_cve_endpoint(
    cve_id: int,
    cve: CVEUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    db_cve = update_cve(db, cve_id=cve_id, cve=cve)
    if db_cve is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return db_cve


@router.delete("/{cve_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_cve_endpoint(
    cve_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_delete_access)
):
    success = delete_cve(db, cve_id=cve_id)
    if not success:
        raise HTTPException(status_code=404, detail="CVE not found")
    return None


@router.post("/sync/{component_id}", response_model=List[CVEResponse])
def sync_cves_for_component(
    component_id: int,
    force_refresh: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Sync CVEs for a component from NVD API
    """
    from app.models.component import Component
    from app.services.component_service import get_component
    
    component = get_component(db, component_id=component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    
    try:
        cves = nvd_service.sync_component_cves(db, component)
        return cves
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync CVEs: {str(e)}"
        )


@router.post("/sync-all", response_model=dict)
def sync_all_cves(
    application_id: Optional[int] = Query(None),
    force_refresh: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Sync CVEs for all components (optionally filtered by application)
    """
    from app.models.component import Component
    from app.services.component_service import get_components
    
    # Get components to sync
    query = db.query(Component)
    if application_id:
        query = query.filter(Component.application_id == application_id)
    
    components = query.all()
    
    if not components:
        return {"message": "No components found to sync", "total": 0, "processed": 0}
    
    results = {
        "total": len(components),
        "processed": 0,
        "failed": 0,
        "details": []
    }
    
    for component in components:
        try:
            print(f"[BULK SYNC] Processing component {component.id}: {component.name} {component.version}")
            cves = nvd_service.sync_component_cves(db, component)
            results["processed"] += 1
            results["details"].append({
                "component_id": component.id,
                "name": component.name,
                "version": component.version,
                "cves_found": len(cves),
                "status": "success"
            })
            print(f"[BULK SYNC] Completed component {component.id}: {len(cves)} CVEs")
        except Exception as e:
            results["failed"] += 1
            results["details"].append({
                "component_id": component.id,
                "name": component.name,
                "version": component.version,
                "status": "failed",
                "error": str(e)
            })
            print(f"[BULK SYNC] Failed component {component.id}: {str(e)}")
    
    return results


@router.post("/link", summary="Link a CVE to a component")
def link_cve_to_component(
    cve_id: int,
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Manually link an existing CVE to a component.

    This is needed when:
    1. CVEs are created manually (not from NVD sync)
    2. NVD sync missed a link
    3. You know a component is affected but NVD does not have the exact CPE match
    """
    from app.models.component import Component
    from app.models.cve import CVE
    
    # Find the CVE
    cve = db.query(CVE).filter(CVE.id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE with id {cve_id} not found")

    # Find the component
    component = db.query(Component).filter(Component.id == component_id).first()
    if not component:
        raise HTTPException(status_code=404, detail=f"Component with id {component_id} not found")

    # Check if already linked
    if cve in component.cves:
        return {
            "message": "CVE already linked to this component",
            "cve_id": cve.cve_id,
            "component": component.name
        }

    # Link them
    component.cves.append(cve)
    db.commit()

    return {
        "message": "CVE linked to component successfully",
        "cve_id": cve.cve_id,
        "cve_db_id": cve.id,
        "component": component.name,
        "component_id": component.id,
        "application_id": component.application_id
    }


@router.delete("/unlink", summary="Unlink a CVE from a component")
def unlink_cve_from_component(
    cve_id: int,
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Remove link between a CVE and a component."""
    from app.models.component import Component
    from app.models.cve import CVE
    
    cve = db.query(CVE).filter(CVE.id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE with id {cve_id} not found")

    component = db.query(Component).filter(Component.id == component_id).first()
    if not component:
        raise HTTPException(status_code=404, detail=f"Component with id {component_id} not found")

    if cve in component.cves:
        component.cves.remove(cve)
        db.commit()
        return {"message": "CVE unlinked from component"}
    else:
        return {"message": "CVE was not linked to this component"}


@router.get("/component/{component_id}/linked", summary="Get all CVEs linked to a component")
def get_linked_cves(
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all CVEs currently linked to a specific component."""
    from app.models.component import Component
    
    component = db.query(Component).filter(Component.id == component_id).first()
    if not component:
        raise HTTPException(status_code=404, detail=f"Component with id {component_id} not found")

    cves = component.cves

    return {
        "component_id": component.id,
        "component_name": component.name,
        "component_version": component.version,
        "total_cves": len(cves),
        "cves": [
            {
                "id": cve.id,
                "cve_id": cve.cve_id,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "description": cve.description[:200] if cve.description else None,
                "exploit_available": cve.exploit_available,
                "patch_available": cve.patch_available,
            }
            for cve in cves
        ]
    }


@router.post("/bulk-link", summary="Link multiple CVEs to a component")
def bulk_link_cves(
    component_id: int,
    cve_ids: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Link multiple CVEs to a component in one request.

    Useful when importing vulnerability data from external sources.
    """
    from app.models.component import Component
    from app.models.cve import CVE

    component = db.query(Component).filter(Component.id == component_id).first()
    if not component:
        raise HTTPException(status_code=404, detail=f"Component {component_id} not found")

    linked = []
    skipped = []
    not_found = []

    for cve_id in cve_ids:
        cve = db.query(CVE).filter(CVE.id == cve_id).first()
        if not cve:
            not_found.append(cve_id)
            continue

        if cve in component.cves:
            skipped.append(cve.cve_id)
        else:
            component.cves.append(cve)
            linked.append(cve.cve_id)

    db.commit()

    return {
        "component": component.name,
        "linked": linked,
        "skipped": skipped,
        "not_found": not_found,
        "total_linked": len(linked)
    }


@router.post("/sync-all-background", summary="Start bulk CVE sync in background")
def sync_all_cves_background(
    application_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Start a bulk CVE sync operation in the background.

    Returns immediately with a task ID. Use the /tasks/{task_id} endpoint
    to poll for progress.

    This is non-blocking and suitable for large SBOMs with 100+ components.
    """
    try:
        task = background_sync_service.start_bulk_cve_sync(
            db=db,
            application_id=application_id,
            username=current_user.username
        )
        return {
            "message": "Bulk CVE sync started in background",
            "task_id": task.id,
            "total_components": task.total_items,
            "status": task.status
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/tasks/{task_id}", summary="Get background task progress")
def get_task_progress(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the current progress of a background sync task.

    Poll this endpoint to show a progress bar in the UI.
    """
    task_status = background_sync_service.get_task_status(db, task_id)
    if not task_status:
        raise HTTPException(status_code=404, detail="Task not found")
    return task_status


@router.get("/tasks", summary="Get recent background tasks")
def get_recent_tasks(
    task_type: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get recent background tasks for monitoring."""
    return background_sync_service.get_recent_tasks(db, task_type=task_type, limit=limit)


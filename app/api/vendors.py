from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
from app.core.database import get_db
from app.schemas.vendor import VendorCreate, VendorUpdate, VendorResponse, VendorStats
from app.services.vendor_service import (
    get_vendor,
    get_vendor_by_name,
    get_vendors,
    create_vendor,
    update_vendor,
    delete_vendor
)
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_write_access, require_delete_access
from app.models.user import User
from app.models.vendor import Vendor
from app.models.application import Application
from app.services.audit_service import audit_service

router = APIRouter(prefix="/vendors", tags=["Vendors"])


@router.post("/", response_model=VendorResponse, status_code=status.HTTP_201_CREATED)
def create_vendor_endpoint(
    vendor: VendorCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    db_vendor = get_vendor_by_name(db, name=vendor.name)
    if db_vendor:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vendor with this name already exists"
        )
    result = create_vendor(db=db, vendor=vendor)
    
    # Log vendor creation
    audit_service.log(
        db=db,
        action="CREATE",
        resource_type="vendor",
        resource_id=result.id,
        description=f"Vendor created: {vendor.name}",
        details={"name": vendor.name, "country": vendor.country, "service_type": vendor.service_type},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


@router.get("/", response_model=List[VendorResponse])
def read_vendors(
    skip: int = 0,
    limit: int = 100,
    tier: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    vendors = get_vendors(db, skip=skip, limit=limit, tier=tier)
    return vendors


@router.get("/stats", response_model=VendorStats)
def get_vendor_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vendor statistics and risk summary"""
    total_vendors = db.query(func.count(Vendor.id)).scalar() or 0
    
    # By tier
    by_tier = {}
    tier_results = db.query(Vendor.tier, func.count(Vendor.id)).group_by(Vendor.tier).all()
    for tier, count in tier_results:
        by_tier[tier or 'Unclassified'] = count
    
    # By country
    by_country = {}
    country_results = db.query(Vendor.country, func.count(Vendor.id)).group_by(Vendor.country).all()
    for country, count in country_results:
        by_country[country or 'Unknown'] = count
    
    # By service type
    by_service_type = {}
    service_results = db.query(Vendor.service_type, func.count(Vendor.id)).group_by(Vendor.service_type).all()
    for service, count in service_results:
        by_service_type[service or 'Unknown'] = count
    
    # High and critical risk vendors
    high_risk_vendors = db.query(func.count(Vendor.id)).filter(
        Vendor.risk_score >= 6.0
    ).scalar() or 0
    
    critical_vendors = db.query(func.count(Vendor.id)).filter(
        Vendor.tier == 'Critical'
    ).scalar() or 0
    
    return VendorStats(
        total_vendors=total_vendors,
        by_tier=by_tier,
        by_country=by_country,
        by_service_type=by_service_type,
        high_risk_vendors=high_risk_vendors,
        critical_vendors=critical_vendors
    )


@router.get("/{vendor_id}", response_model=VendorResponse)
def read_vendor(
    vendor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    vendor = get_vendor(db, vendor_id=vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return vendor


@router.get("/{vendor_id}/applications", response_model=List)
def get_vendor_applications(
    vendor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all applications for a specific vendor"""
    vendor = get_vendor(db, vendor_id=vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    
    applications = db.query(Application).filter(
        Application.vendor_id == vendor_id
    ).all()
    
    return [
        {
            "id": app.id,
            "name": app.name,
            "criticality": app.criticality.value if app.criticality else None,
            "environment": app.environment.value if app.environment else None,
            "internet_facing": app.internet_facing
        }
        for app in applications
    ]


@router.post("/{vendor_id}/calculate-risk", response_model=VendorResponse)
def calculate_vendor_risk(
    vendor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Calculate vendor risk score based on their applications"""
    vendor = get_vendor(db, vendor_id=vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    
    # Get all applications for this vendor
    applications = db.query(Application).filter(
        Application.vendor_id == vendor_id
    ).all()
    
    if not applications:
        vendor.risk_score = 0.0
        db.commit()
        db.refresh(vendor)
        return vendor
    
    # Calculate risk based on application count and criticality
    total_apps = len(applications)
    critical_apps = sum(1 for app in applications if app.criticality and app.criticality.value == 'critical')
    high_apps = sum(1 for app in applications if app.criticality and app.criticality.value == 'high')
    internet_facing_apps = sum(1 for app in applications if app.internet_facing)
    
    # Simple risk calculation
    risk_score = 0.0
    risk_score += (critical_apps * 2.0)
    risk_score += (high_apps * 1.0)
    risk_score += (internet_facing_apps * 0.5)
    risk_score += (total_apps * 0.1)
    
    # Cap at 10
    risk_score = min(risk_score, 10.0)
    
    vendor.risk_score = risk_score
    
    # Auto-assign tier based on risk score
    if risk_score >= 8.0:
        vendor.tier = 'Critical'
    elif risk_score >= 6.0:
        vendor.tier = 'High'
    elif risk_score >= 4.0:
        vendor.tier = 'Medium'
    else:
        vendor.tier = 'Low'
    
    db.commit()
    db.refresh(vendor)
    return vendor


@router.put("/{vendor_id}", response_model=VendorResponse)
def update_vendor_endpoint(
    vendor_id: int,
    vendor: VendorUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    db_vendor = db.query(Vendor).filter(Vendor.id == vendor_id).first()
    if not db_vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    
    # Store old values
    old_values = {
        "name": db_vendor.name,
        "country": db_vendor.country,
        "service_type": db_vendor.service_type,
        "tier": db_vendor.tier
    }
    
    result = update_vendor(db, vendor_id=vendor_id, vendor=vendor)
    
    # Log vendor update
    audit_service.log(
        db=db,
        action="UPDATE",
        resource_type="vendor",
        resource_id=vendor_id,
        description=f"Vendor updated: {old_values['name']}",
        details={
            "old_values": old_values,
            "new_values": {
                "name": result.name,
                "country": result.country,
                "service_type": result.service_type,
                "tier": result.tier
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


@router.delete("/{vendor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vendor_endpoint(
    vendor_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_delete_access)
):
    db_vendor = db.query(Vendor).filter(Vendor.id == vendor_id).first()
    if not db_vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    
    # Store vendor info before deletion
    vendor_info = {
        "name": db_vendor.name,
        "country": db_vendor.country,
        "service_type": db_vendor.service_type,
        "tier": db_vendor.tier
    }
    
    success = delete_vendor(db, vendor_id=vendor_id)
    if not success:
        raise HTTPException(status_code=404, detail="Vendor not found")
    
    # Log vendor deletion
    audit_service.log(
        db=db,
        action="DELETE",
        resource_type="vendor",
        resource_id=vendor_id,
        description=f"Vendor deleted: {vendor_info['name']}",
        details={"deleted_vendor": vendor_info, "deleted_by": current_user.username},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return None

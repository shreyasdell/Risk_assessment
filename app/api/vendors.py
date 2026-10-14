from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.schemas.vendor import VendorCreate, VendorUpdate, VendorResponse
from app.services.vendor_service import (
    get_vendor,
    get_vendor_by_name,
    get_vendors,
    create_vendor,
    update_vendor,
    delete_vendor
)
from app.auth.dependencies import get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/vendors", tags=["Vendors"])


@router.post("/", response_model=VendorResponse, status_code=status.HTTP_201_CREATED)
def create_vendor_endpoint(
    vendor: VendorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    db_vendor = get_vendor_by_name(db, name=vendor.name)
    if db_vendor:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vendor with this name already exists"
        )
    return create_vendor(db=db, vendor=vendor)


@router.get("/", response_model=List[VendorResponse])
def read_vendors(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    vendors = get_vendors(db, skip=skip, limit=limit)
    return vendors


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


@router.put("/{vendor_id}", response_model=VendorResponse)
def update_vendor_endpoint(
    vendor_id: int,
    vendor: VendorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    db_vendor = update_vendor(db, vendor_id=vendor_id, vendor=vendor)
    if db_vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return db_vendor


@router.delete("/{vendor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vendor_endpoint(
    vendor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    success = delete_vendor(db, vendor_id=vendor_id)
    if not success:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return None

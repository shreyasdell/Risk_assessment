from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.vendor import Vendor
from app.schemas.vendor import VendorCreate, VendorUpdate


def get_vendor(db: Session, vendor_id: int) -> Optional[Vendor]:
    return db.query(Vendor).filter(Vendor.id == vendor_id).first()


def get_vendor_by_name(db: Session, name: str) -> Optional[Vendor]:
    return db.query(Vendor).filter(Vendor.name == name).first()


def get_vendors(db: Session, skip: int = 0, limit: int = 100) -> List[Vendor]:
    return db.query(Vendor).offset(skip).limit(limit).all()


def create_vendor(db: Session, vendor: VendorCreate) -> Vendor:
    db_vendor = Vendor(**vendor.model_dump())
    db.add(db_vendor)
    db.commit()
    db.refresh(db_vendor)
    return db_vendor


def update_vendor(db: Session, vendor_id: int, vendor: VendorUpdate) -> Optional[Vendor]:
    db_vendor = get_vendor(db, vendor_id)
    if not db_vendor:
        return None
    for key, value in vendor.model_dump(exclude_unset=True).items():
        setattr(db_vendor, key, value)
    db.commit()
    db.refresh(db_vendor)
    return db_vendor


def delete_vendor(db: Session, vendor_id: int) -> bool:
    db_vendor = get_vendor(db, vendor_id)
    if not db_vendor:
        return False
    db.delete(db_vendor)
    db.commit()
    return True

"""
Component Normalization API Endpoints

Provides endpoints for normalizing component names and identifying vendors.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict

from app.core.database import get_db
from app.models.component import Component
from app.models.user import User
from app.auth.dependencies import get_current_active_user
from app.agent.normalizer.normalizer import component_normalizer

router = APIRouter(prefix="/normalize", tags=["Normalization"])


@router.get("/{component_id}", summary="Get normalization result for a component")
def get_normalization(
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the normalization result for a single component.
    
    If the component is not yet normalized, it will be normalized now.
    """
    component = db.query(Component).filter(Component.id == component_id).first()
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    
    # Normalize if not already done
    if not component.normalized_name or not component.identified_vendor:
        normalized_name, vendor, method = component_normalizer.normalize_component(component, db)
    else:
        normalized_name = component.normalized_name
        vendor = component.identified_vendor
        method = component.normalization_method
    
    return {
        "component_id": component.id,
        "raw_name": component.name,
        "normalized_name": normalized_name,
        "identified_vendor": vendor,
        "method": method,
        "purl": component.purl,
        "cpe": component.cpe,
        "supplier": component.supplier
    }


@router.post("/bulk", summary="Normalize all unnormalized components")
def normalize_bulk(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Normalize all components that don't have normalization data yet.
    
    Returns statistics about the normalization process.
    """
    # Find all unnormalized components
    unnormalized = db.query(Component).filter(
        (Component.normalized_name.is_(None)) | (Component.identified_vendor.is_(None))
    ).all()
    
    if not unnormalized:
        return {
            "message": "All components are already normalized",
            "total": 0,
            "processed": 0,
            "stats": {}
        }
    
    stats = {
        "total": len(unnormalized),
        "processed": 0,
        "methods": {
            "tier1_purl": 0,
            "tier2_lookup": 0,
            "tier3_llm": 0,
            "fallback": 0,
            "cached": 0
        }
    }
    
    for component in unnormalized:
        try:
            normalized_name, vendor, method = component_normalizer.normalize_component(component, db)
            stats["processed"] += 1
            stats["methods"][method] = stats["methods"].get(method, 0) + 1
        except Exception as e:
            print(f"[Normalization] Error normalizing component {component.id}: {e}")
    
    return {
        "message": f"Normalized {stats['processed']} components",
        "total": stats["total"],
        "processed": stats["processed"],
        "stats": stats["methods"]
    }


@router.post("/reprocess/{component_id}", summary="Re-normalize a component")
def reprocess_component(
    component_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Force re-normalization of a component by clearing cached data and re-running.
    """
    component = db.query(Component).filter(Component.id == component_id).first()
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    
    # Clear cached normalization
    component.normalized_name = None
    component.identified_vendor = None
    component.normalization_method = None
    db.commit()
    
    # Re-normalize
    normalized_name, vendor, method = component_normalizer.normalize_component(component, db)
    
    return {
        "message": "Component re-normalized",
        "component_id": component.id,
        "normalized_name": normalized_name,
        "identified_vendor": vendor,
        "method": method
    }


@router.get("/stats", summary="Get normalization statistics")
def get_normalization_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get statistics about component normalization coverage.
    """
    total = db.query(Component).count()
    normalized = db.query(Component).filter(
        Component.normalized_name.isnot(None)
    ).count()
    
    # Get method breakdown
    from sqlalchemy import func
    method_stats = db.query(
        Component.normalization_method,
        func.count(Component.id)
    ).filter(
        Component.normalization_method.isnot(None)
    ).group_by(Component.normalization_method).all()
    
    methods = {method: count for method, count in method_stats}
    
    return {
        "total_components": total,
        "normalized_count": normalized,
        "unnormalized_count": total - normalized,
        "coverage_percentage": round((normalized / total * 100) if total > 0 else 0, 1),
        "methods": methods
    }

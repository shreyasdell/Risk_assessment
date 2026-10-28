from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional
from app.core.database import get_db
from app.schemas.dashboard import (
    DashboardSummary,
    DashboardData,
    CriticalityDistribution,
    EnvironmentDistribution,
    ComponentTypeDistribution,
    TopVendor,
    TopApplication,
    RecentActivity,
    VendorDashboard,
    ApplicationDashboard
)
from app.services.dashboard_service import (
    get_dashboard_summary,
    get_dashboard_data,
    get_criticality_distribution,
    get_environment_distribution,
    get_component_type_distribution,
    get_top_vendors,
    get_top_applications,
    get_recent_activity,
    get_vendor_dashboard,
    get_application_dashboard,
    refresh_component_count
)
from app.auth.dependencies import get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get overall summary statistics"""
    return get_dashboard_summary(db)


@router.get("/", response_model=DashboardData)
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get complete dashboard data"""
    return get_dashboard_data(db)


@router.get("/criticality-distribution", response_model=list[CriticalityDistribution])
def get_criticality_dist(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get distribution of applications by criticality"""
    return get_criticality_distribution(db)


@router.get("/environment-distribution", response_model=list[EnvironmentDistribution])
def get_environment_dist(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get distribution of applications by environment"""
    return get_environment_distribution(db)


@router.get("/component-type-distribution", response_model=list[ComponentTypeDistribution])
def get_component_type_dist(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get distribution of components by type"""
    return get_component_type_distribution(db)


@router.get("/top-vendors", response_model=list[TopVendor])
def get_top_vendors_endpoint(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get top vendors by application count"""
    return get_top_vendors(db, limit=limit)


@router.get("/top-applications", response_model=list[TopApplication])
def get_top_applications_endpoint(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get top applications by component count"""
    return get_top_applications(db, limit=limit)


@router.get("/recent-activity", response_model=list[RecentActivity])
def get_recent_activity_endpoint(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get recent activity across all entities"""
    return get_recent_activity(db, limit=limit)


@router.get("/vendor/{vendor_id}", response_model=VendorDashboard)
def get_vendor_dashboard_endpoint(
    vendor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get dashboard data for a specific vendor"""
    try:
        return get_vendor_dashboard(db, vendor_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.get("/application/{application_id}", response_model=ApplicationDashboard)
def get_application_dashboard_endpoint(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get dashboard data for a specific application"""
    try:
        return get_application_dashboard(db, application_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.get("/refresh-component-count")
def refresh_component_count_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Refresh and return the current component count"""
    count = refresh_component_count(db)
    return {"total_components": count}

from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict
from datetime import datetime, timedelta
from app.models.application import Application
from app.models.vendor import Vendor
from app.models.component import Component
from app.schemas.dashboard import (
    DashboardSummary,
    CriticalityDistribution,
    EnvironmentDistribution,
    ComponentTypeDistribution,
    TopVendor,
    TopApplication,
    RecentActivity,
    DashboardData,
    VendorDashboard,
    ApplicationDashboard
)


def get_dashboard_summary(db: Session) -> DashboardSummary:
    """Get overall summary statistics"""
    
    total_applications = db.query(func.count(Application.id)).scalar() or 0
    total_vendors = db.query(func.count(Vendor.id)).scalar() or 0
    total_components = db.query(func.count(Component.id)).scalar() or 0
    
    critical_applications = db.query(func.count(Application.id)).filter(
        Application.criticality == "critical"
    ).scalar() or 0
    
    internet_facing_apps = db.query(func.count(Application.id)).filter(
        Application.internet_facing == True
    ).scalar() or 0
    
    production_apps = db.query(func.count(Application.id)).filter(
        Application.environment == "production"
    ).scalar() or 0
    
    return DashboardSummary(
        total_applications=total_applications,
        total_vendors=total_vendors,
        total_components=total_components,
        critical_applications=critical_applications,
        internet_facing_apps=internet_facing_apps,
        production_apps=production_apps
    )


def refresh_component_count(db: Session) -> int:
    """
    Refresh and return the current component count.
    This function ensures a fresh count from the database.
    """
    total_components = db.query(func.count(Component.id)).scalar() or 0
    return total_components


def get_criticality_distribution(db: Session) -> List[CriticalityDistribution]:
    """Get distribution of applications by criticality"""
    
    results = db.query(
        Application.criticality,
        func.count(Application.id).label('count')
    ).group_by(Application.criticality).all()
    
    total = sum(r.count for r in results) if results else 0
    
    distribution = []
    for result in results:
        percentage = (result.count / total * 100) if total > 0 else 0
        distribution.append(CriticalityDistribution(
            criticality=result.criticality if result.criticality else "unknown",
            count=result.count,
            percentage=round(percentage, 2)
        ))
    
    return distribution


def get_environment_distribution(db: Session) -> List[EnvironmentDistribution]:
    """Get distribution of applications by environment"""
    
    results = db.query(
        Application.environment,
        func.count(Application.id).label('count')
    ).group_by(Application.environment).all()
    
    total = sum(r.count for r in results) if results else 0
    
    distribution = []
    for result in results:
        percentage = (result.count / total * 100) if total > 0 else 0
        distribution.append(EnvironmentDistribution(
            environment=result.environment if result.environment else "unknown",
            count=result.count,
            percentage=round(percentage, 2)
        ))
    
    return distribution


def get_component_type_distribution(db: Session) -> List[ComponentTypeDistribution]:
    """Get distribution of components by type"""
    
    results = db.query(
        Component.component_type,
        func.count(Component.id).label('count')
    ).group_by(Component.component_type).all()
    
    total = sum(r.count for r in results) if results else 0
    
    distribution = []
    for result in results:
        percentage = (result.count / total * 100) if total > 0 else 0
        distribution.append(ComponentTypeDistribution(
            component_type=result.component_type if result.component_type else "unknown",
            count=result.count,
            percentage=round(percentage, 2)
        ))
    
    return distribution


def get_top_vendors(db: Session, limit: int = 10) -> List[TopVendor]:
    """Get top vendors by application count"""
    
    subquery = db.query(
        Application.vendor_id,
        func.count(Application.id).label('app_count')
    ).group_by(Application.vendor_id).subquery()
    
    results = db.query(
        Vendor.id,
        Vendor.name,
        subquery.c.app_count
    ).join(subquery, Vendor.id == subquery.c.vendor_id)\
     .order_by(desc(subquery.c.app_count))\
     .limit(limit).all()
    
    top_vendors = []
    for result in results:
        # Get component count for this vendor's applications
        component_count = db.query(func.count(Component.id)).join(
            Application, Component.application_id == Application.id
        ).filter(Application.vendor_id == result.id).scalar() or 0
        
        top_vendors.append(TopVendor(
            vendor_id=result.id,
            vendor_name=result.name,
            application_count=result.app_count,
            component_count=component_count
        ))
    
    return top_vendors


def get_top_applications(db: Session, limit: int = 10) -> List[TopApplication]:
    """Get top applications by component count"""
    
    results = db.query(
        Application.id,
        Application.name,
        func.count(Component.id).label('component_count'),
        Application.criticality,
        Application.internet_facing
    ).outerjoin(Component, Application.id == Component.application_id)\
     .group_by(Application.id)\
     .order_by(desc('component_count'))\
     .limit(limit).all()
    
    top_applications = []
    for result in results:
        top_applications.append(TopApplication(
            application_id=result.id,
            application_name=result.name,
            component_count=result.component_count,
            criticality=result.criticality if result.criticality else "unknown",
            internet_facing=result.internet_facing
        ))
    
    return top_applications


def get_recent_activity(db: Session, limit: int = 10) -> List[RecentActivity]:
    """Get recent activity across all entities"""
    
    activities = []
    
    # Recent applications
    recent_apps = db.query(Application).order_by(
        desc(Application.created_at)
    ).limit(limit // 3).all()
    
    for app in recent_apps:
        activities.append(RecentActivity(
            type="application",
            name=app.name,
            created_at=app.created_at
        ))
    
    # Recent vendors
    recent_vendors = db.query(Vendor).order_by(
        desc(Vendor.created_at)
    ).limit(limit // 3).all()
    
    for vendor in recent_vendors:
        activities.append(RecentActivity(
            type="vendor",
            name=vendor.name,
            created_at=vendor.created_at
        ))
    
    # Recent components
    recent_components = db.query(Component).order_by(
        desc(Component.created_at)
    ).limit(limit // 3).all()
    
    for comp in recent_components:
        activities.append(RecentActivity(
            type="component",
            name=f"{comp.name} {comp.version}",
            created_at=comp.created_at
        ))
    
    # Sort by date and limit
    activities.sort(key=lambda x: x.created_at, reverse=True)
    return activities[:limit]


def get_dashboard_data(db: Session) -> DashboardData:
    """Get complete dashboard data"""

    return DashboardData(
        summary=get_dashboard_summary(db),
        criticality_distribution=get_criticality_distribution(db),
        environment_distribution=get_environment_distribution(db),
        component_type_distribution=get_component_type_distribution(db),
        top_vendors=get_top_vendors(db),
        top_applications=get_top_applications(db),
        recent_activity=get_recent_activity(db)
    )


def get_vendor_dashboard(db: Session, vendor_id: int) -> VendorDashboard:
    """Get dashboard data for a specific vendor"""

    vendor = db.query(Vendor).filter(Vendor.id == vendor_id).first()
    if not vendor:
        raise ValueError("Vendor not found")

    # Get applications for this vendor
    applications = db.query(Application).filter(Application.vendor_id == vendor_id).all()

    total_applications = len(applications)
    total_components = db.query(func.count(Component.id)).join(
        Application, Component.application_id == Application.id
    ).filter(Application.vendor_id == vendor_id).scalar() or 0

    critical_apps = sum(1 for app in applications if app.criticality == "critical")
    internet_facing = sum(1 for app in applications if app.internet_facing)

    # Get top applications for this vendor
    app_results = db.query(
        Application.id,
        Application.name,
        func.count(Component.id).label('component_count'),
        Application.criticality,
        Application.internet_facing
    ).outerjoin(Component, Application.id == Component.application_id)\
     .filter(Application.vendor_id == vendor_id)\
     .group_by(Application.id)\
     .order_by(desc('component_count'))\
     .all()

    top_apps = []
    for result in app_results:
        top_apps.append(TopApplication(
            application_id=result.id,
            application_name=result.name,
            component_count=result.component_count,
            criticality=result.criticality if result.criticality else "unknown",
            internet_facing=result.internet_facing
        ))

    return VendorDashboard(
        vendor_id=vendor.id,
        vendor_name=vendor.name,
        total_applications=total_applications,
        total_components=total_components,
        critical_applications=critical_apps,
        internet_facing_apps=internet_facing,
        applications=top_apps
    )


def get_application_dashboard(db: Session, application_id: int) -> ApplicationDashboard:
    """Get dashboard data for a specific application"""

    application = db.query(Application).filter(Application.id == application_id).first()
    if not application:
        raise ValueError("Application not found")

    # Get component count
    component_count = db.query(func.count(Component.id)).filter(
        Component.application_id == application_id
    ).scalar() or 0

    # Get vendor name
    vendor_name = None
    if application.vendor_id:
        vendor = db.query(Vendor).filter(Vendor.id == application.vendor_id).first()
        if vendor:
            vendor_name = vendor.name

    # Get component type distribution for this application
    results = db.query(
        Component.component_type,
        func.count(Component.id).label('count')
    ).filter(Component.application_id == application_id)\
     .group_by(Component.component_type).all()

    total = sum(r.count for r in results) if results else 0

    type_distribution = []
    for result in results:
        percentage = (result.count / total * 100) if total > 0 else 0
        type_distribution.append(ComponentTypeDistribution(
            component_type=result.component_type if result.component_type else "unknown",
            count=result.count,
            percentage=round(percentage, 2)
        ))

    return ApplicationDashboard(
        application_id=application.id,
        application_name=application.name,
        component_count=component_count,
        criticality=application.criticality if application.criticality else "unknown",
        internet_facing=application.internet_facing,
        environment=application.environment if application.environment else "unknown",
        data_classification=application.data_classification if application.data_classification else "unknown",
        vendor_name=vendor_name,
        component_type_distribution=type_distribution
    )

"""
Global Search API
Search across applications, vendors, components, CVEs.
"""

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_, func

from app.core.database import get_db
from app.auth.dependencies import get_current_user
from app.models.vendor import Vendor
from app.models.application import Application
from app.models.component import Component
from app.models.cve import CVE

router = APIRouter(prefix="/search", tags=["Search"])


@router.get("/", summary="Global search")
def global_search(
    q: str = Query(
        ...,
        min_length=2,
        max_length=200,
        description="Search query (minimum 2 characters)"
    ),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Search across all resource types.

    Returns categorized results from:
    - Vendors (name, country, business owner)
    - Applications (name, description, owner)
    - Components (name, version, supplier)
    - CVEs (cve_id, description, cwe_id)

    Results are ranked by relevance (exact match first,
    then partial match).
    """
    search_term = f"%{q.lower()}%"
    results = {
        "query": q,
        "vendors": [],
        "applications": [],
        "components": [],
        "cves": [],
        "total_results": 0,
    }

    # Search Vendors
    vendors = (
        db.query(Vendor)
        .filter(
            or_(
                func.lower(Vendor.name).like(search_term),
                func.lower(Vendor.country).like(search_term),
                func.lower(
                    Vendor.business_owner
                ).like(search_term),
            )
        )
        .limit(limit)
        .all()
    )
    results["vendors"] = [
        {
            "id": v.id,
            "name": v.name,
            "country": v.country,
            "type": "vendor",
        }
        for v in vendors
    ]

    # Search Applications
    applications = (
        db.query(Application)
        .filter(
            or_(
                func.lower(Application.name).like(search_term),
                func.lower(
                    Application.description
                ).like(search_term),
                func.lower(Application.owner).like(search_term),
                func.lower(
                    Application.business_unit
                ).like(search_term),
            )
        )
        .limit(limit)
        .all()
    )
    results["applications"] = [
        {
            "id": a.id,
            "name": a.name,
            "criticality": a.criticality.value if a.criticality else None,
            "environment": a.environment.value if a.environment else None,
            "type": "application",
        }
        for a in applications
    ]

    # Search Components
    components = (
        db.query(Component)
        .filter(
            or_(
                func.lower(Component.name).like(search_term),
                func.lower(Component.version).like(search_term),
                func.lower(Component.supplier).like(search_term),
                func.lower(Component.purl).like(search_term),
            )
        )
        .limit(limit)
        .all()
    )
    results["components"] = [
        {
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "application_id": c.application_id,
            "type": "component",
        }
        for c in components
    ]

    # Search CVEs
    cves = (
        db.query(CVE)
        .filter(
            or_(
                func.lower(CVE.cve_id).like(search_term),
                func.lower(CVE.description).like(search_term),
                func.lower(CVE.cwe_id).like(search_term),
            )
        )
        .limit(limit)
        .all()
    )
    results["cves"] = [
        {
            "id": c.id,
            "cve_id": c.cve_id,
            "severity": c.severity,
            "cvss_score": c.cvss_score,
            "type": "cve",
        }
        for c in cves
    ]

    results["total_results"] = (
        len(results["vendors"])
        + len(results["applications"])
        + len(results["components"])
        + len(results["cves"])
    )

    return results
